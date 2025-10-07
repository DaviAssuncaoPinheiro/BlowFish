from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import base64

def ensure_rsa_keypair(state):
    if "priv_pem" not in state or not state.priv_pem:
        k = RSA.generate(2048)
        state.priv_pem = k.export_key().decode()
        state.pub_pem = k.publickey().export_key().decode()
        print("frontend: rsa keypair generated")
    elif "pub_pem" not in state or not state.pub_pem:
        k = RSA.import_key(state.priv_pem.encode())
        state.pub_pem = k.publickey().export_key().decode()

def rsa_decrypt(priv_pem: str, data_b64: str) -> bytes:
    priv = RSA.import_key(priv_pem.encode())
    cipher = PKCS1_OAEP.new(priv)
    return cipher.decrypt(base64.b64decode(data_b64))

BLOCK = Blowfish.block_size

def _pad(b: bytes) -> bytes:
    pad = BLOCK - (len(b) % BLOCK)
    return b + bytes([pad]) * pad

def _unpad(b: bytes) -> bytes:
    return b[:-b[-1]]

def blowfish_encrypt(key: bytes, plaintext: str, conversation_id: int):
    iv = get_random_bytes(BLOCK)
    c = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    ct = c.encrypt(_pad(plaintext.encode()))
    h = HMAC.new(key, digestmod=SHA256)
    h.update(iv + ct + str(conversation_id).encode())
    tag = h.digest()
    return {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "hmac": base64.b64encode(tag).decode()
    }

def blowfish_decrypt(key: bytes, iv_b64: str, ct_b64: str, hmac_b64: str, conversation_id: int) -> str:
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ct_b64)
    tag = base64.b64decode(hmac_b64)
    h = HMAC.new(key, digestmod=SHA256)
    h.update(iv + ct + str(conversation_id).encode())
    h.verify(tag)
    c = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    pt = _unpad(c.decrypt(ct))
    return pt.decode()
