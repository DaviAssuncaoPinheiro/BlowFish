from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import base64

#RSA
def rsa_encrypt(pub_pem: str, data: bytes) -> bytes:
    pub = RSA.import_key(pub_pem.encode())
    cipher = PKCS1_OAEP.new(pub)
    return cipher.encrypt(data)

def rsa_decrypt(priv_pem: str, data: bytes) -> bytes:
    priv = RSA.import_key(priv_pem.encode())
    cipher = PKCS1_OAEP.new(priv)
    return cipher.decrypt(data)

#Blowfish
BLOCK_SIZE = Blowfish.block_size  # 8 bytes

def _pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len]) * pad_len

def _unpad(data: bytes) -> bytes:
    return data[:-data[-1]]

def generate_blowfish_key(length: int = 32) -> bytes:
    return get_random_bytes(length)

def blowfish_encrypt(key: bytes, plaintext: bytes, conversation_id: str = "") -> dict:
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    pt_padded = _pad(plaintext)
    ct = cipher.encrypt(pt_padded)
    h = HMAC.new(key, digestmod=SHA256)
    h.update(iv + ct + conversation_id.encode())
    tag = h.digest()
    return {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "hmac": base64.b64encode(tag).decode()
    }

def blowfish_decrypt(key: bytes, iv_b64: str, ct_b64: str, hmac_b64: str, conversation_id: str = "") -> bytes:
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ct_b64)
    tag = base64.b64decode(hmac_b64)
    h = HMAC.new(key, digestmod=SHA256)
    h.update(iv + ct + conversation_id.encode())
    h.verify(tag)  
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return _unpad(pt)
