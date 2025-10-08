from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes

BLOCK_SIZE = Blowfish.block_size

def debug(msg: str) -> None:
    print(f"[DEBUG] {msg}", flush=True)

def rsa_generate_2048_pem_pair() -> Tuple[str, str]:
    debug("Gerando par de chaves RSA 2048-bit (cryptography)...")
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
    return priv_pem, pub_pem

def rsa_encrypt(pub_pem: str, data: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(pub_pem.encode())
    return public_key.encrypt(
        data,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt(priv_pem: str, data: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    return private_key.decrypt(
        data,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def _pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Padding inválido.")
    return data[:-pad_len]

def blowfish_encrypt(plaintext: str, key: bytes):
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    ct = cipher.encrypt(_pkcs7_pad(plaintext.encode(), BLOCK_SIZE))
    return iv, ct

def blowfish_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> str:
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    pt = cipher.decrypt(ciphertext)
    return _pkcs7_unpad(pt).decode()
