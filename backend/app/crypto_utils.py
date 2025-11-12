from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
import base64
import os

BLOCK_SIZE = Blowfish.block_size

def rsa_generate_2048_pem_pair() -> Tuple[str, str]:
    print("--- [CRYPTO_UTILS] Gerando novo par de chaves RSA 2048 ---")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    print(f"--- [CRYPTO_UTILS] Chave Pública RSA Gerada:\n{pub_pem}")
    print(f"--- [CRYPTO_UTILS] Chave Privada RSA Gerada:\n{priv_pem}")
    return priv_pem, pub_pem

def rsa_encrypt(pub_pem: str, data: bytes) -> bytes:
    print(f"--- [CRYPTO_UTILS] Criptografando com chave pública RSA:\n{pub_pem[:80]}...")
    print(f"--- [CRYPTO_UTILS] Dados para criptografar (RSA): {data}")
    public_key = serialization.load_pem_public_key(pub_pem.encode())
    encrypted_data = public_key.encrypt(
        data,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    print(f"--- [CRYPTO_UTILS] Dados criptografados (RSA): {base64.b64encode(encrypted_data).decode()}")
    return encrypted_data

def rsa_decrypt(priv_pem: str, data: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    decrypted_data = private_key.decrypt(
        data,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted_data

def _pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Padding inválido.")
    return data[:-pad_len]

def blowfish_encrypt(plaintext: str, key: bytes):
    print(f"--- [CRYPTO_UTILS] Criptografando com Blowfish. Chave: {base64.b64encode(key).decode()}, Texto: '{plaintext}'")
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    ct = cipher.encrypt(_pkcs7_pad(plaintext.encode(), BLOCK_SIZE))
    print(f"--- [CRYPTO_UTILS] IV (Blowfish): {base64.b64encode(iv).decode()}")
    print(f"--- [CRYPTO_UTILS] Texto Cifrado (Blowfish): {base64.b64encode(ct).decode()}")
    return iv, ct

def blowfish_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> str:
    print(f"--- [CRYPTO_UTILS] Descriptografando com Blowfish. Chave: {base64.b64encode(key).decode()}, IV: {base64.b64encode(iv).decode()}")
    print(f"--- [CRYPTO_UTILS] Texto Cifrado para descriptografar (Blowfish): {base64.b64encode(ciphertext).decode()}")
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    pt = cipher.decrypt(ciphertext)
    unpadded_pt = _pkcs7_unpad(pt).decode()
    print(f"--- [CRYPTO_UTILS] Texto Descriptografado (Blowfish): '{unpadded_pt}'")
    return unpadded_pt

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_with_password(data: bytes, password: str, salt: bytes) -> Tuple[bytes, bytes]:
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len]) * pad_len
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ct

def decrypt_with_password(iv: bytes, ciphertext: bytes, password: str, salt: bytes) -> bytes:
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_pt = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded_pt[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding length during decryption.")
    return padded_pt[:-pad_len]

def _get_vault_key() -> bytes:
    vault_secret = os.getenv("VAULT_SECRET")
    if not vault_secret:
        raise ValueError("VAULT_SECRET environment variable not set.")
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(vault_secret.encode())
    return digest.finalize()

def encrypt_with_vault_secret(data: bytes) -> Tuple[bytes, bytes]:
    key = _get_vault_key()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len]) * pad_len
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ct

def decrypt_with_vault_secret(iv: bytes, ciphertext: bytes) -> bytes:
    key = _get_vault_key()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_pt = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded_pt[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding length during decryption with vault secret.")
    unpadded_pt = padded_pt[:-pad_len]
    return unpadded_pt
