import CryptoJS from 'crypto-js';

function blowfishEncrypt(plaintext, key, iv) {
  const keyHex = CryptoJS.enc.Utf8.parse(key);
  const ivHex = CryptoJS.enc.Utf8.parse(iv);
  const encrypted = CryptoJS.Blowfish.encrypt(plaintext, keyHex, { iv: ivHex });
  return encrypted.toString();
}

function blowfishDecrypt(ciphertext, key, iv) {
  const keyHex = CryptoJS.enc.Utf8.parse(key);
  const ivHex = CryptoJS.enc.Utf8.parse(iv);
  const decrypted = CryptoJS.Blowfish.decrypt({ ciphertext: CryptoJS.enc.Base64.parse(ciphertext) }, keyHex, { iv: ivHex });
  return decrypted.toString(CryptoJS.enc.Utf8);
}

export { blowfishEncrypt, blowfishDecrypt };