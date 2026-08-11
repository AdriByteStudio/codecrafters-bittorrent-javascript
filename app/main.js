const crypto = require("crypto");
const fs = require("fs");
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

function main() {
  const command = process.argv[2];

  // You can use print statements as follows for debugging, they'll be visible when running tests.
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

    console.log(`Tracker URL: ${trackerUrl}`);
    console.log(`Length: ${fileInfo.length}`);
    console.log(`Info Hash: ${infoHash}`);
  } else {
    throw new Error(`Unknown command ${command}`);
  }
}

main();
