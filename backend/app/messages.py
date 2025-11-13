from fastapi import APIRouter, HTTPException, Depends
import sqlite3
import os
import base64
#so pra dar commit
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from .db import get_conn
from .auth import auth_required

try:
    from .realtime import manager
except Exception:
    manager = None

router = APIRouter()


def fetch_user_public_key(conn, username: str):
    cur = conn.cursor()
    cur.execute("SELECT public_key FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    return row["public_key"] if row else None


def fetch_user_private_key(conn, username: str):
    cur = conn.cursor()
    cur.execute("SELECT private_key FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    return row["private_key"] if row else None


def rsa_encrypt_with_pem(public_pem: str, plaintext: bytes) -> bytes:
    pub = serialization.load_pem_public_key(public_pem.encode())
    return pub.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt_with_pem(private_pem: str, ciphertext: bytes) -> bytes:
    priv = serialization.load_pem_private_key(private_pem.encode(), password=None)
    return priv.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


@router.post("/messages/send")
async def send_dm(data: dict, sender: str = Depends(auth_required)):
    to = data.get("to")
    message = data.get("message", "")
    if not to or not message:
        raise HTTPException(
            status_code=400, detail="Destinatário e mensagem são obrigatórios"
        )

    print(f"\n[CRYPTO-DEBUG] ===== INICIANDO ENVIO DE MENSAGEM: {sender} -> {to} =====")
    conn = get_conn()
    try:
        cur = conn.cursor()
        recipient_pub = fetch_user_public_key(conn, to)
        sender_pub = fetch_user_public_key(conn, sender)
        if not recipient_pub or not sender_pub:
            raise HTTPException(status_code=400, detail="Chave pública não encontrada")

        session_key = os.urandom(16)
        print(
            f"[CRYPTO-DEBUG] 1. Chave de sessão única (Blowfish) criada: {session_key.hex()}"
        )

        iv = os.urandom(8)
        cipher = Blowfish.new(session_key, Blowfish.MODE_CBC, iv=iv)
        padded = pad(message.encode(), Blowfish.block_size)
        ciphertext = cipher.encrypt(padded)
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        print(
            f"[CRYPTO-DEBUG] 2. Mensagem '{message}' criptografada com a chave de sessão. Ciphertext: {ciphertext_b64[:30]}..."
        )

        recipient_encrypted_session = rsa_encrypt_with_pem(recipient_pub, session_key)
        sender_encrypted_session = rsa_encrypt_with_pem(sender_pub, session_key)
        recipient_encrypted_b64 = base64.b64encode(recipient_encrypted_session).decode()
        sender_encrypted_b64 = base64.b64encode(sender_encrypted_session).decode()
        print(
            f"[CRYPTO-DEBUG] 3. Chave de sessão criptografada para o destinatário '{to}' usando a chave pública dele."
        )
        print(
            f"[CRYPTO-DEBUG] 4. Chave de sessão criptografada para o remetente '{sender}' usando a própria chave pública."
        )

        cur.execute(
            "INSERT INTO messages (sender_username, receiver_username, encrypted_message, encrypted_session_key, sender_encrypted_session_key, iv) VALUES (?, ?, ?, ?, ?, ?)",
            (
                sender,
                to,
                ciphertext_b64,
                recipient_encrypted_b64,
                sender_encrypted_b64,
                iv.hex(),
            ),
        )
        conn.commit()
        msg_id = cur.lastrowid
        print(
            f"[CRYPTO-DEBUG] 5. Mensagem e chaves criptografadas salvas no BD com ID: {msg_id}"
        )

    finally:
        if conn:
            conn.close()

    payload = {
        "type": "dm",
        "from": sender,
        "to": to,
        "message": message,
        "msg_id": msg_id,
    }
    if manager:
        await manager.send_to_user(to, payload)
        await manager.send_to_user(sender, payload)
    print("[CRYPTO-DEBUG] ===== FIM DO ENVIO DE MENSAGEM =====\n")
    return {"ok": True, "id": msg_id}


@router.get("/messages/history")
async def history(peer: str, me: str = Depends(auth_required)):
    print(f"\n[CRYPTO-DEBUG] ===== CARREGANDO HISTÓRICO: {me} <-> {peer} =====")
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM messages WHERE (sender_username = ? AND receiver_username = ?) OR (sender_username = ? AND receiver_username = ?) ORDER BY timestamp ASC",
        (me, peer, peer, me),
    )
    rows = cur.fetchall()

    out = []
    my_priv_key = fetch_user_private_key(conn, me)
    print(
        f"[CRYPTO-DEBUG] 1. Buscando chave privada de '{me}' para descriptografar mensagens."
    )

    for r in rows:
        plaintext = "<Erro>"
        encrypted_session_key_to_use = None

        if r["sender_username"] == me:
            encrypted_session_key_to_use = r["sender_encrypted_session_key"]
            print(
                f"[CRYPTO-DEBUG] 2. Descriptografando mensagem ENVIADA (ID: {r['id']}). Usando a 'sender_encrypted_session_key'."
            )
        else:
            encrypted_session_key_to_use = r["encrypted_session_key"]
            print(
                f"[CRYPTO-DEBUG] 2. Descriptografando mensagem RECEBIDA de '{r['sender_username']}' (ID: {r['id']}). Usando a 'encrypted_session_key'."
            )

        if my_priv_key and encrypted_session_key_to_use:
            try:
                enc_session_key = base64.b64decode(encrypted_session_key_to_use)
                session_key = rsa_decrypt_with_pem(my_priv_key, enc_session_key)
                print(
                    f"[CRYPTO-DEBUG] 3. Chave de sessão descriptografada com sucesso: {session_key.hex()}"
                )

                iv = bytes.fromhex(r["iv"])
                ciphertext = base64.b64decode(r["encrypted_message"])
                cipher = Blowfish.new(session_key, Blowfish.MODE_CBC, iv=iv)
                decrypted_padded = cipher.decrypt(ciphertext)
                plaintext = unpad(decrypted_padded, Blowfish.block_size).decode()
                print(f"[CRYPTO-DEBUG] 4. Mensagem descriptografada: '{plaintext}'")
            except Exception as e:
                plaintext = f"<Falha na descriptografia: {e}>"
                print(f"[CRYPTO-DEBUG] 4. ERRO ao descriptografar mensagem: {e}")

        out.append(
            {
                "id": r["id"],
                "sender_username": r["sender_username"],
                "plaintext": plaintext,
                "timestamp": r["timestamp"],
            }
        )

    conn.close()
    print("[CRYPTO-DEBUG] ===== FIM DO CARREGAMENTO DO HISTÓRICO =====\n")
    return out
