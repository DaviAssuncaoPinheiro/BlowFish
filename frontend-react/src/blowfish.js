import CryptoJS from 'crypto-js';

// Helper to convert Uint8Array to CryptoJS WordArray
function uint8ToWordArray(uint8) {
    const words = [];
    let i = 0;
    for (let j = 0; j < uint8.length; j++) {
        words[i >>> 2] |= (uint8[j] & 0xFF) << (24 - (i % 4) * 8);
        i++;
    }
    return CryptoJS.lib.WordArray.create(words, uint8.length);
}

// Helper to convert CryptoJS WordArray to Uint8Array
function wordArrayToUint8(wordArray) {
    const l = wordArray.sigBytes;
    const words = wordArray.words;
    const result = new Uint8Array(l);
    let i = 0;
    for (let j = 0; j < l; j++) {
        result[i++] = (words[j >>> 2] >>> (24 - (j % 4) * 8)) & 0xff;
    }
    return result;
}

function blowfishEncrypt(plaintext, key, iv) {
  const keyWordArray = uint8ToWordArray(key);
  const ivWordArray = uint8ToWordArray(iv);
  const plaintextWordArray = uint8ToWordArray(plaintext); // Convert plaintext to WordArray

  const encrypted = CryptoJS.Blowfish.encrypt(plaintextWordArray, keyWordArray, { iv: ivWordArray });
  return wordArrayToUint8(encrypted.ciphertext); // Return Uint8Array
}

function blowfishDecrypt(ciphertext, key, iv) {
  const keyWordArray = uint8ToWordArray(key);
  const ivWordArray = uint8ToWordArray(iv);
  const ciphertextWordArray = uint8ToWordArray(ciphertext); // Convert ciphertext to WordArray

  const decrypted = CryptoJS.Blowfish.decrypt({ ciphertext: ciphertextWordArray }, keyWordArray, { iv: ivWordArray });
  return wordArrayToUint8(decrypted); // Return Uint8Array
}

export { blowfishEncrypt, blowfishDecrypt };