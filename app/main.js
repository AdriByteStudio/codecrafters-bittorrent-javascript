const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");
const net = require("net");
const process = require("process");
const util = require("util");

// Examples:
// - decodeBencode("5:hello") -> "hello"
// - decodeBencode("10:hello12345") -> "hello12345"
// - decodeBencode("i52e") -> 52
// - decodeBencode("l5:helloi52ee") -> ["hello", 52]
function decodeBencodeValue(bencodedValue, startIndex) {
  const currentByte = bencodedValue[startIndex];

  if (currentByte === 0x69) {
    const endIndex = bencodedValue.indexOf(0x65, startIndex + 1);
    if (endIndex === -1) {
      throw new Error("Invalid encoded value");
    }

    const integerString = bencodedValue.slice(startIndex + 1, endIndex).toString("ascii");
    if (!/^-?\d+$/.test(integerString)) {
      throw new Error("Invalid encoded value");
    }

    return {
      value: Number(integerString),
      nextIndex: endIndex + 1,
      rawBytes: bencodedValue.slice(startIndex, endIndex + 1),
    };
  }

  if (currentByte === 0x6c) {
    const values = [];
    let index = startIndex + 1;

    while (index < bencodedValue.length && bencodedValue[index] !== 0x65) {
      const decodedValue = decodeBencodeValue(bencodedValue, index);
      values.push(decodedValue.value);
      index = decodedValue.nextIndex;
    }

    if (index >= bencodedValue.length || bencodedValue[index] !== 0x65) {
      throw new Error("Invalid encoded value");
    }

    return {
      value: values,
      nextIndex: index + 1,
      rawBytes: bencodedValue.slice(startIndex, index + 1),
    };
  }

  if (currentByte === 0x64) {
    const object = {};
    let index = startIndex + 1;
    let infoRawBytes = null;

    while (index < bencodedValue.length && bencodedValue[index] !== 0x65) {
      const keyDecoded = decodeBencodeValue(bencodedValue, index);
      if (typeof keyDecoded.value !== "string") {
        throw new Error("Dictionary keys must be strings");
      }

      index = keyDecoded.nextIndex;

      const valueDecoded = decodeBencodeValue(bencodedValue, index);
      object[keyDecoded.value] = valueDecoded.value;

      if (keyDecoded.value === "info") {
        infoRawBytes = valueDecoded.rawBytes;
      }

      index = valueDecoded.nextIndex;
    }

    if (index >= bencodedValue.length || bencodedValue[index] !== 0x65) {
      throw new Error("Invalid encoded value");
    }

    return {
      value: object,
      nextIndex: index + 1,
      rawBytes: bencodedValue.slice(startIndex, index + 1),
      infoRawBytes,
    };
  }

  if (currentByte >= 0x30 && currentByte <= 0x39) {
    const firstColonIndex = bencodedValue.indexOf(0x3a, startIndex);
    if (firstColonIndex === -1) {
      throw new Error("Invalid encoded value");
    }

    const lengthString = bencodedValue.slice(startIndex, firstColonIndex).toString("ascii");
    if (!/^\d+$/.test(lengthString)) {
      throw new Error("Invalid encoded value");
    }

    const length = Number(lengthString);
    const value = bencodedValue.slice(firstColonIndex + 1, firstColonIndex + 1 + length).toString("latin1");

    if (value.length !== length) {
      throw new Error("Invalid encoded value");
    }

    return {
      value,
      nextIndex: firstColonIndex + 1 + length,
      rawBytes: bencodedValue.slice(startIndex, firstColonIndex + 1 + length),
    };
  }

  throw new Error("Unsupported bencoded value");
}

function decodeBencode(bencodedValue) {
  const input = Buffer.isBuffer(bencodedValue) ? bencodedValue : Buffer.from(bencodedValue, "latin1");
  const decodedValue = decodeBencodeValue(input, 0);

  if (decodedValue.nextIndex !== input.length) {
    throw new Error("Invalid encoded value");
  }

  return decodedValue.value;
}

function decodeBencodeWithMetadata(bencodedValue) {
  const input = Buffer.isBuffer(bencodedValue) ? bencodedValue : Buffer.from(bencodedValue, "latin1");
  const decodedValue = decodeBencodeValue(input, 0);

  if (decodedValue.nextIndex !== input.length) {
    throw new Error("Invalid encoded value");
  }

  return {
    value: decodedValue.value,
    infoRawBytes: decodedValue.infoRawBytes,
  };
}

function makeTrackerRequestUrl(trackerUrl, infoHashBuffer, left) {
  const encodedInfoHash = Array.from(infoHashBuffer)
    .map((byte) => `%${byte.toString(16).padStart(2, "0")}`)
    .join("");

  const params = [
    `info_hash=${encodedInfoHash}`,
    `peer_id=-CC0001-123456789012`,
    "port=6881",
    "uploaded=0",
    "downloaded=0",
    `left=${left}`,
    "compact=1",
  ];

  const separator = trackerUrl.includes("?") ? "&" : "?";
  return `${trackerUrl}${separator}${params.join("&")}`;
}

function requestTracker(trackerUrl, infoHashBuffer, left) {
  const requestUrl = makeTrackerRequestUrl(trackerUrl, infoHashBuffer, left);

  return new Promise((resolve, reject) => {
    const transport = requestUrl.startsWith("https://") ? https : http;
    const request = transport.get(requestUrl, (response) => {
      if (response.statusCode && response.statusCode >= 400) {
        reject(new Error(`Tracker request failed with status ${response.statusCode}`));
        response.resume();
        return;
      }

      const chunks = [];
      response.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      response.on("end", () => resolve(Buffer.concat(chunks)));
    });

    request.on("error", reject);
  });
}

function parseCompactPeers(peersString) {
  const peersBuffer = Buffer.from(peersString, "latin1");
  const peers = [];

  for (let index = 0; index + 6 <= peersBuffer.length; index += 6) {
    const peerBuffer = peersBuffer.subarray(index, index + 6);
    const ipAddress = Array.from(peerBuffer.subarray(0, 4))
      .map((byte) => String(byte))
      .join(".");
    const port = peerBuffer.readUInt16BE(4);
    peers.push(`${ipAddress}:${port}`);
  }

  return peers;
}

function createHandshake(infoHashBuffer) {
  const protocolName = "BitTorrent protocol";
  const protocolBuffer = Buffer.from(protocolName, "utf8");
  const peerId = crypto.randomBytes(20);
  const handshake = Buffer.alloc(1 + protocolBuffer.length + 8 + infoHashBuffer.length + peerId.length);

  handshake[0] = protocolBuffer.length;
  protocolBuffer.copy(handshake, 1);
  // Reserved bytes are already zero-filled by Buffer.alloc.
  infoHashBuffer.copy(handshake, 1 + protocolBuffer.length + 8);
  peerId.copy(handshake, 1 + protocolBuffer.length + 8 + infoHashBuffer.length);

  return { handshake, peerId };
}

function performHandshake(peerAddress, infoHashBuffer) {
  return new Promise((resolve, reject) => {
    const [host, portString] = peerAddress.split(":");
    const port = Number(portString);

    if (!host || Number.isNaN(port)) {
      reject(new Error("Invalid peer address"));
      return;
    }

    const socket = net.createConnection({ host, port });
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error("Handshake timed out"));
    }, 5000);

    socket.on("connect", () => {
      const { handshake, peerId } = createHandshake(infoHashBuffer);
      socket.write(handshake);
    });

    socket.on("data", (data) => {
      clearTimeout(timeout);
      if (data.length < 68) {
        socket.destroy();
        reject(new Error("Handshake response was too short"));
        return;
      }

      const peerId = data.subarray(48, 68).toString("hex");
      socket.end();
      resolve(peerId);
    });

    socket.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}

async function main() {
  const command = process.argv[2];

  // You can use print statements as follows for debugging, they'll be visible here.
  console.error("Logs from your program will appear here!");

  if (command === "decode") {
    const bencodedValue = process.argv[3];

    // In JavaScript, there's no need to manually convert bytes to string for printing
    // because JS doesn't distinguish between bytes and strings in the same way Python does.
    console.log(JSON.stringify(decodeBencode(bencodedValue)));
  } else if (command === "info") {
    const torrentPath = process.argv[3];
    const torrentData = fs.readFileSync(torrentPath);
    const decodedTorrent = decodeBencodeWithMetadata(torrentData);

    if (!decodedTorrent.value || typeof decodedTorrent.value !== "object" || Array.isArray(decodedTorrent.value)) {
      throw new Error("Invalid torrent file");
    }

    const trackerUrl = decodedTorrent.value.announce;
    const fileInfo = decodedTorrent.value.info;

    if (typeof trackerUrl !== "string" || !fileInfo || typeof fileInfo !== "object" || Array.isArray(fileInfo)) {
      throw new Error("Invalid torrent file");
    }

    const infoHash = crypto.createHash("sha1").update(decodedTorrent.infoRawBytes || Buffer.from([])).digest("hex");
    const pieceLength = fileInfo["piece length"];
    const pieceHashes = fileInfo.pieces;

    console.log(`Tracker URL: ${trackerUrl}`);
    console.log(`Length: ${fileInfo.length}`);
    console.log(`Info Hash: ${infoHash}`);
    console.log(`Piece Length: ${pieceLength}`);
    console.log("Piece Hashes:");

    if (typeof pieceHashes === "string") {
      for (let index = 0; index < pieceHashes.length; index += 20) {
        const chunk = pieceHashes.slice(index, index + 20);
        const hex = Buffer.from(chunk, "latin1").toString("hex");
        console.log(hex);
      }
    }
  } else if (command === "peers") {
    const torrentPath = process.argv[3];
    const torrentData = fs.readFileSync(torrentPath);
    const decodedTorrent = decodeBencodeWithMetadata(torrentData);

    if (!decodedTorrent.value || typeof decodedTorrent.value !== "object" || Array.isArray(decodedTorrent.value)) {
      throw new Error("Invalid torrent file");
    }

    const trackerUrl = decodedTorrent.value.announce;
    const fileInfo = decodedTorrent.value.info;

    if (typeof trackerUrl !== "string" || !fileInfo || typeof fileInfo !== "object" || Array.isArray(fileInfo)) {
      throw new Error("Invalid torrent file");
    }

    const infoHash = crypto.createHash("sha1").update(decodedTorrent.infoRawBytes || Buffer.from([])).digest("hex");
    const trackerResponse = await requestTracker(trackerUrl, Buffer.from(infoHash, "hex"), fileInfo.length);
    const decodedResponse = decodeBencode(trackerResponse);

    if (!decodedResponse || typeof decodedResponse !== "object" || Array.isArray(decodedResponse)) {
      throw new Error("Invalid tracker response");
    }

    const peers = parseCompactPeers(decodedResponse.peers);
    for (const peer of peers) {
      console.log(peer);
    }
  } else if (command === "handshake") {
    const torrentPath = process.argv[3];
    const peerAddress = process.argv[4];
    const torrentData = fs.readFileSync(torrentPath);
    const decodedTorrent = decodeBencodeWithMetadata(torrentData);

    if (!decodedTorrent.value || typeof decodedTorrent.value !== "object" || Array.isArray(decodedTorrent.value)) {
      throw new Error("Invalid torrent file");
    }

    const fileInfo = decodedTorrent.value.info;
    if (!fileInfo || typeof fileInfo !== "object" || Array.isArray(fileInfo)) {
      throw new Error("Invalid torrent file");
    }

    const infoHashBuffer = crypto.createHash("sha1").update(decodedTorrent.infoRawBytes || Buffer.from([])).digest();
    const peerId = await performHandshake(peerAddress, infoHashBuffer);
    console.log(`Peer ID: ${peerId}`);
  } else {
    throw new Error(`Unknown command ${command}`);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
