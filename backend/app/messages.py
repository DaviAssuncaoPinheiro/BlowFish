from fastapi import APIRouter, Request, HTTPException, status
import sqlite3
import os
import base64
from typing import List
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from .db import get_conn

try:
    from .realtime import manager
except Exception:
    manager = None

router = APIRouter()

def get_username_from_auth(request: Request):
    auth = request.headers.get("authorization") or ""
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid auth header")
    return auth.split(" ", 1)[1].strip()

def fetch_user_row(conn, username: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()

def fetch_user_public_key(conn, username: str):
    row = fetch_user_row(conn, username)
    return row["public_key"] if row else None

def fetch_user_private_key(conn, username: str):
    row = fetch_user_row(conn, username)
    return row["private_key"] if row else None

def rsa_encrypt_with_pem(public_pem: str, plaintext: bytes) -> bytes:
    pub = serialization.load_pem_public_key(public_pem.encode())
    ct = pub.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return ct

def rsa_decrypt_with_pem(private_pem: str, ciphertext: bytes) -> bytes:
    priv = serialization.load_pem_private_key(private_pem.encode(), password=None)
    pt = priv.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return pt

@router.post("/messages/send")
async def send_dm(data: dict, request: Request):
    sender = get_username_from_auth(request)
    to = data.get("to")
    message = data.get("message", "")
    if not to or not message:
        raise HTTPException(status_code=400, detail="to and message required")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username = ?", (to,))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="recipient not found")
    recipient_pub = fetch_user_public_key(conn, to)
    if not recipient_pub:
        conn.close()
        raise HTTPException(status_code=400, detail="recipient has no public key")
    session_key = os.urandom(16)
    iv = os.urandom(8)
    cipher = Blowfish.new(session_key, Blowfish.MODE_CBC, iv=iv)
    padded = pad(message.encode(), Blowfish.block_size)
    ciphertext = cipher.encrypt(padded)
    ciphertext_b64 = base64.b64encode(ciphertext).decode()
    encrypted_session = rsa_encrypt_with_pem(recipient_pub, session_key)
    encrypted_session_b64 = base64.b64encode(encrypted_session).decode()
    cur.execute("INSERT INTO messages (sender_username, receiver_username, encrypted_message, encrypted_session_key, iv) VALUES (?, ?, ?, ?, ?)",
                (sender, to, ciphertext_b64, encrypted_session_b64, iv.hex()))
    conn.commit()
    msg_id = cur.lastrowid
    conn.close()
    plaintext_for_payload = None
    try:
        conn2 = get_conn()
        recipient_priv = fetch_user_private_key(conn2, to)
        if recipient_priv:
            enc_bytes = base64.b64decode(encrypted_session_b64)
            decrypted_session = rsa_decrypt_with_pem(recipient_priv, enc_bytes)
            iv_bytes = iv
            cipher2 = Blowfish.new(decrypted_session, Blowfish.MODE_CBC, iv=iv_bytes)
            pt_padded = cipher2.decrypt(ciphertext)
            try:
                pt = unpad(pt_padded, Blowfish.block_size).decode()
                plaintext_for_payload = pt
            except Exception:
                plaintext_for_payload = "<decrypt error>"
        conn2.close()
    except Exception:
        plaintext_for_payload = None
    payload = {
        "type": "dm",
        "from": sender,
        "to": to,
        "message": plaintext_for_payload if plaintext_for_payload is not None else "<encrypted>",
        "msg_id": msg_id,
        "encrypted_message": ciphertext_b64,
        "encrypted_session_key": encrypted_session_b64,
        "iv": iv.hex()
    }
    if manager:
        await manager.send_to_user(to, payload)
    else:
        pass
    return {"ok": True, "id": msg_id}

@router.get("/messages/history")
async def history(peer: str, request: Request):
    me = get_username_from_auth(request)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""SELECT * FROM messages WHERE
                   (sender_username = ? AND receiver_username = ?)
                   OR (sender_username = ? AND receiver_username = ?)
                   ORDER BY timestamp ASC""", (me, peer, peer, me))
    rows = cur.fetchall()
    out = []
    priv = fetch_user_private_key(conn, me)
    for r in rows:
        enc_msg_b64 = r["encrypted_message"]
        enc_session_b64 = r["encrypted_session_key"]
        iv_hex = r["iv"]
        plaintext = None
        if r["receiver_username"] == me:
            if priv and enc_session_b64:
                try:
                    enc_session = base64.b64decode(enc_session_b64)
                    session = rsa_decrypt_with_pem(priv, enc_session)
                    iv = bytes.fromhex(iv_hex)
                    ct = base64.b64decode(enc_msg_b64)
                    cipher = Blowfish.new(session, Blowfish.MODE_CBC, iv=iv)
                    pt = unpad(cipher.decrypt(ct), Blowfish.block_size).decode()
                    plaintext = pt
                except Exception:
                    plaintext = "<decrypt error>"
            else:
                plaintext = "<no private key stored on server>"
        else:
            plaintext = "<encrypted>"
        out.append({
            "id": r["id"],
            "sender_username": r["sender_username"],
            "receiver_username": r["receiver_username"],
            "plaintext": plaintext,
            "timestamp": r["timestamp"]
        })
    conn.close()
    return out
