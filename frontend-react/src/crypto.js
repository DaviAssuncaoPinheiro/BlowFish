import CryptoJS from 'crypto-js';
import { blowfishEncrypt as bfEncrypt, blowfishDecrypt as bfDecrypt } from './blowfish.js';

// --- Helper Functions ---

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

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

function base64ToUint8(b64) {
    const wordArray = CryptoJS.enc.Base64.parse(b64);
    return wordArrayToUint8(wordArray);
}

function uint8ToBase64(bytes) {
    const wordArray = uint8ToWordArray(bytes);
    return CryptoJS.enc.Base64.stringify(wordArray);
}

// --- RSA Functions (Web Crypto API) ---

async function importRsaPublicKey(pem) {
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length).replace(/\s/g, '');
    const binaryDer = base64ToUint8(pemContents);

    return await window.crypto.subtle.importKey(
        "spki",
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["encrypt"]
    );
}

async function importRsaPrivateKey(pem) {
    const pemHeader = "-----BEGIN PRIVATE KEY-----";
    const pemFooter = "-----END PRIVATE KEY-----";
    const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length).replace(/\s/g, '');
    const binaryDer = base64ToUint8(pemContents);

    return await window.crypto.subtle.importKey(
        "pkcs8",
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["decrypt"]
    );
}


async function rsaEncrypt(publicKey, data) {
    const encrypted = await window.crypto.subtle.encrypt(
        {
            name: "RSA-OAEP"
        },
        publicKey,
        data
    );
    return new Uint8Array(encrypted);
}

// --- Blowfish Functions ---

function blowfishEncrypt(plaintext, key, iv) {
    return bfEncrypt(textEncoder.encode(plaintext), key, iv);
}

function blowfishDecrypt(ciphertext, key, iv) {
    return textDecoder.decode(bfDecrypt(ciphertext, key, iv));
}

// --- High-level API ---

function generateRandomBytes(length) {
    return window.crypto.getRandomValues(new Uint8Array(length));
}

async function rsaDecrypt(privateKey, ciphertext) {
    const decrypted = await window.crypto.subtle.decrypt(
        {
            name: "RSA-OAEP"
        },
        privateKey,
        ciphertext
    );
    return new Uint8Array(decrypted);
}

export {
    base64ToUint8,
    uint8ToBase64,
    importRsaPublicKey,
    importRsaPrivateKey,
    rsaEncrypt,
    rsaDecrypt,
    blowfishEncrypt,
    blowfishDecrypt,
    generateRandomBytes,
    textEncoder,
    textDecoder
};
