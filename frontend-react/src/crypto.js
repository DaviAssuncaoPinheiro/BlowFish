import { blowfishEncrypt as bfEncrypt, blowfishDecrypt as bfDecrypt } from './blowfish.js';

// --- Helper Functions ---

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function base64ToUint8(b64) {
    const binStr = atob(b64);
    const len = binStr.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binStr.charCodeAt(i);
    }
    return bytes;
}

function uint8ToBase64(bytes) {
    let binStr = '';
    const len = bytes.length;
    for (let i = 0; i < len; i++) {
        binStr += String.fromCharCode(bytes[i]);
    }
    return btoa(binStr);
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
    return bfEncrypt(plaintext, key, iv);
}

function blowfishDecrypt(ciphertext, key, iv) {
    return bfDecrypt(ciphertext, key, iv);
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
