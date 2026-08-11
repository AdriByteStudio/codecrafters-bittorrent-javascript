const process = require("process");
const util = require("util");

// Examples:
// - decodeBencode("5:hello") -> "hello"
// - decodeBencode("10:hello12345") -> "hello12345"
// - decodeBencode("i52e") -> 52
// - decodeBencode("l5:helloi52ee") -> ["hello", 52]
function decodeBencodeValue(bencodedValue, startIndex) {
  const currentChar = bencodedValue[startIndex];

  if (currentChar === "i") {
    const endIndex = bencodedValue.indexOf("e", startIndex + 1);
    if (endIndex === -1) {
      throw new Error("Invalid encoded value");
    }

    const integerString = bencodedValue.slice(startIndex + 1, endIndex);
    if (!/^-?\d+$/.test(integerString)) {
      throw new Error("Invalid encoded value");
    }

    return { value: Number(integerString), nextIndex: endIndex + 1 };
  }

  if (currentChar === "l") {
    const values = [];
    let index = startIndex + 1;

    while (index < bencodedValue.length && bencodedValue[index] !== "e") {
      const decodedValue = decodeBencodeValue(bencodedValue, index);
      values.push(decodedValue.value);
      index = decodedValue.nextIndex;
    }

    if (index >= bencodedValue.length || bencodedValue[index] !== "e") {
      throw new Error("Invalid encoded value");
    }

    return { value: values, nextIndex: index + 1 };
  }

  if (currentChar === "d") {
    const object = {};
    let index = startIndex + 1;

    while (index < bencodedValue.length && bencodedValue[index] !== "e") {
      const keyDecoded = decodeBencodeValue(bencodedValue, index);
      if (typeof keyDecoded.value !== "string") {
        throw new Error("Dictionary keys must be strings");
      }

      index = keyDecoded.nextIndex;

      const valueDecoded = decodeBencodeValue(bencodedValue, index);
      object[keyDecoded.value] = valueDecoded.value;
      index = valueDecoded.nextIndex;
    }

    if (index >= bencodedValue.length || bencodedValue[index] !== "e") {
      throw new Error("Invalid encoded value");
    }

    return { value: object, nextIndex: index + 1 };
  }

  if (!isNaN(currentChar)) {
    const firstColonIndex = bencodedValue.indexOf(":", startIndex);
    if (firstColonIndex === -1) {
      throw new Error("Invalid encoded value");
    }

    const lengthString = bencodedValue.slice(startIndex, firstColonIndex);
    if (!/^\d+$/.test(lengthString)) {
      throw new Error("Invalid encoded value");
    }

    const length = Number(lengthString);
    const value = bencodedValue.slice(firstColonIndex + 1, firstColonIndex + 1 + length);

    if (value.length !== length) {
      throw new Error("Invalid encoded value");
    }

    return { value, nextIndex: firstColonIndex + 1 + length };
  }

  throw new Error("Unsupported bencoded value");
}

function decodeBencode(bencodedValue) {
  const decodedValue = decodeBencodeValue(bencodedValue, 0);

  if (decodedValue.nextIndex !== bencodedValue.length) {
    throw new Error("Invalid encoded value");
  }

  return decodedValue.value;
}

function main() {
  const command = process.argv[2];

  // You can use print statements as follows for debugging, they'll be visible when running tests.
  console.error("Logs from your program will appear here!");

  // TODO: Uncomment the code below to pass the first stage
   if (command === "decode") {
     const bencodedValue = process.argv[3];
  
     // In JavaScript, there's no need to manually convert bytes to string for printing
     // because JS doesn't distinguish between bytes and strings in the same way Python does.
     console.log(JSON.stringify(decodeBencode(bencodedValue)));
   } else {
     throw new Error(`Unknown command ${command}`);
   }
}

main();
