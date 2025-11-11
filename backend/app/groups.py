from fastapi import APIRouter, HTTPException, Depends
import sqlite3
import os
import base64
from typing import List
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


def fetch_group_members(conn, group_id: int) -> List[str]:
    cur = conn.cursor()
    cur.execute("SELECT username FROM group_members WHERE group_id = ?", (group_id,))
    return [r[0] for r in cur.fetchall()]


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


def add_group_member_db(conn, group_id: int, username: str):
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO group_members (group_id, username) VALUES (?, ?)",
        (group_id, username),
    )


def remove_group_member_db(conn, group_id: int, username: str):
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM group_members WHERE group_id = ? AND username = ?",
        (group_id, username),
    )


def store_encrypted_key(
    conn, group_id: int, version: int, username: str, encrypted_b64: str
):
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO group_keys (group_id, key_version, username, encrypted_key) VALUES (?, ?, ?, ?)",
        (group_id, version, username, encrypted_b64),
    )


def next_key_version(conn, group_id: int) -> int:
    cur = conn.cursor()
    cur.execute(
        "SELECT MAX(key_version) as v FROM group_keys WHERE group_id = ?", (group_id,)
    )
    row = cur.fetchone()
    v = row["v"] if row and row["v"] is not None else 0
    return v + 1


@router.post("/groups/create")
async def create_new_group(data: dict, me: str = Depends(auth_required)):
    print(f"\n[CRYPTO-DEBUG] ===== CRIANDO NOVO GRUPO (Requerente: {me}) =====")
    name = data.get("name") or f"Grupo de {me}"
    members = list(set(data.get("members", [])))
    if me not in members:
        members.append(me)

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO groups (name) VALUES (?)", (name,))
    group_id = cur.lastrowid
    print(f"[CRYPTO-DEBUG] 1. Grupo criado no BD com ID: {group_id}")

    for member in members:
        add_group_member_db(conn, group_id, member)

    version = 1
    session_key = os.urandom(16)
    print(
        f"[CRYPTO-DEBUG] 2. Gerada a primeira chave de sessão do grupo (Versão {version}): {session_key.hex()}"
    )
    print("[CRYPTO-DEBUG] 3. Distribuindo a chave de sessão para os membros:")
    for member in members:
        public_pem = fetch_user_public_key(conn, member)
        if not public_pem:
            continue
        encrypted = rsa_encrypt_with_pem(public_pem, session_key)
        encrypted_b64 = base64.b64encode(encrypted).decode()
        store_encrypted_key(conn, group_id, version, member, encrypted_b64)
        print(f"   - Chave criptografada para '{member}' e salva no BD.")

    conn.commit()
    conn.close()
    print("[CRYPTO-DEBUG] ===== FIM DA CRIAÇÃO DO GRUPO =====\n")
    return {"ok": True, "id": group_id}


@router.post("/groups/{group_id}/add")
async def add_member(
    group_id: int, data: dict, requester: str = Depends(auth_required)
):
    new_username = data.get("username")
    print(
        f"\n[CRYPTO-DEBUG] ===== ADICIONANDO MEMBRO '{new_username}' AO GRUPO {group_id} (Requerente: {requester}) ====="
    )

    conn = get_conn()
    add_group_member_db(conn, group_id, new_username)
    print(f"[CRYPTO-DEBUG] 1. Usuário '{new_username}' adicionado ao grupo no BD.")

    version = next_key_version(conn, group_id)
    print(f"[CRYPTO-DEBUG] 2. ROTAÇÃO DE CHAVES INICIADA. Nova versão será: {version}")

    new_session_key = os.urandom(16)
    print(
        f"[CRYPTO-DEBUG] 3. Nova chave de sessão do grupo gerada: {new_session_key.hex()}"
    )

    updated_members = fetch_group_members(conn, group_id)
    print(
        f"[CRYPTO-DEBUG] 4. Distribuindo a NOVA chave para a lista atualizada de membros: {updated_members}"
    )
    for member in updated_members:
        public_pem = fetch_user_public_key(conn, member)
        if not public_pem:
            continue
        encrypted = rsa_encrypt_with_pem(public_pem, new_session_key)
        encrypted_b64 = base64.b64encode(encrypted).decode()
        store_encrypted_key(conn, group_id, version, member, encrypted_b64)
        print(f"   - Nova chave criptografada para '{member}' e salva no BD.")

    conn.commit()
    conn.close()
    print("[CRYPTO-DEBUG] ===== FIM DA ADIÇÃO DE MEMBRO =====\n")
    return {"ok": True}


@router.post("/groups/{group_id}/remove")
async def remove_member(
    group_id: int, data: dict, requester: str = Depends(auth_required)
):
    username_to_remove = data.get("username")
    print(
        f"\n[CRYPTO-DEBUG] ===== REMOVENDO MEMBRO '{username_to_remove}' DO GRUPO {group_id} (Requerente: {requester}) ====="
    )

    conn = get_conn()
    remove_group_member_db(conn, group_id, username_to_remove)
    print(f"[CRYPTO-DEBUG] 1. Usuário '{username_to_remove}' removido do grupo no BD.")

    version = next_key_version(conn, group_id)
    print(f"[CRYPTO-DEBUG] 2. ROTAÇÃO DE CHAVES INICIADA. Nova versão será: {version}")

    new_session_key = os.urandom(16)
    print(
        f"[CRYPTO-DEBUG] 3. Nova chave de sessão do grupo gerada: {new_session_key.hex()}"
    )

    remaining_members = fetch_group_members(conn, group_id)
    print(
        f"[CRYPTO-DEBUG] 4. Distribuindo a NOVA chave para os membros restantes: {remaining_members}"
    )
    for member in remaining_members:
        public_pem = fetch_user_public_key(conn, member)
        if not public_pem:
            continue
        encrypted = rsa_encrypt_with_pem(public_pem, new_session_key)
        encrypted_b64 = base64.b64encode(encrypted).decode()
        store_encrypted_key(conn, group_id, version, member, encrypted_b64)
        print(f"   - Nova chave criptografada para '{member}' e salva no BD.")

    conn.commit()
    conn.close()
    print("[CRYPTO-DEBUG] ===== FIM DA REMOÇÃO DE MEMBRO =====\n")
    return {"ok": True}


@router.get("/groups")
async def list_user_groups(me: str = Depends(auth_required)):
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT group_id FROM group_members WHERE username = ?", (me,))
    group_ids = [row["group_id"] for row in cur.fetchall()]

    groups_out = []
    for group_id in group_ids:
        cur.execute("SELECT id, name FROM groups WHERE id = ?", (group_id,))
        group_row = cur.fetchone()
        if not group_row:
            continue

        members = fetch_group_members(conn, group_id)

        cur.execute(
            "SELECT MAX(key_version) as v FROM group_keys WHERE group_id = ?",
            (group_id,),
        )
        version_row = cur.fetchone()
        latest_version = (
            version_row["v"] if version_row and version_row["v"] is not None else 0
        )

        groups_out.append(
            {
                "id": group_row["id"],
                "name": group_row["name"],
                "members": members,
                "key_version": latest_version,
            }
        )
    conn.close()
    return groups_out


@router.post("/groups/{group_id}/send")
async def send_group_message(
    group_id: int, data: dict, sender: str = Depends(auth_required)
):
    message = data.get("message")
    if not message:
        raise HTTPException(status_code=400, detail="Mensagem não pode ser vazia")

    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute(
        "SELECT 1 FROM group_members WHERE group_id = ? AND username = ?",
        (group_id, sender),
    )
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="Você não é membro deste grupo")

    cur.execute(
        "SELECT MAX(key_version) as v FROM group_keys WHERE group_id = ?", (group_id,)
    )
    latest_version = cur.fetchone()["v"]

    cur.execute(
        "SELECT encrypted_key FROM group_keys WHERE group_id = ? AND key_version = ? AND username = ?",
        (group_id, latest_version, sender),
    )
    key_row = cur.fetchone()
    if not key_row:
        conn.close()
        raise HTTPException(
            status_code=400, detail="Não foi possível encontrar a chave de sessão."
        )

    sender_priv_key = fetch_user_private_key(conn, sender)
    if not sender_priv_key:
        raise HTTPException(
            status_code=500, detail="Chave privada do remetente não encontrada."
        )

    try:
        encrypted_session_key = base64.b64decode(key_row["encrypted_key"])
        session_key = rsa_decrypt_with_pem(sender_priv_key, encrypted_session_key)
    except Exception as e:
        conn.close()
        raise HTTPException(
            status_code=500, detail=f"Erro ao descriptografar chave de sessão: {e}"
        )

    iv = os.urandom(8)
    cipher = Blowfish.new(session_key, Blowfish.MODE_CBC, iv)
    padded_message = pad(message.encode(), Blowfish.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    encrypted_message_b64 = base64.b64encode(encrypted_message).decode()

    cur.execute(
        "INSERT INTO group_messages (group_id, sender_username, encrypted_message, iv, key_version) VALUES (?, ?, ?, ?, ?)",
        (group_id, sender, encrypted_message_b64, iv.hex(), latest_version),
    )
    msg_id = cur.lastrowid
    conn.commit()
    conn.close()

    members = fetch_group_members(get_conn(), group_id)
    payload = {
        "type": "group",
        "from": sender,
        "conversation_id": group_id,
        "message": message,
        "msg_id": msg_id,
        "key_version": latest_version,
    }
    if manager:
        await manager.broadcast(members, payload)

    return {"ok": True, "id": msg_id}


@router.get("/groups/{group_id}/history")
async def get_group_history(group_id: int, me: str = Depends(auth_required)):
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute(
        "SELECT 1 FROM group_members WHERE group_id = ? AND username = ?",
        (group_id, me),
    )
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="Acesso negado")

    my_priv_key = fetch_user_private_key(conn, me)
    if not my_priv_key:
        conn.close()
        raise HTTPException(status_code=400, detail="Chave privada não encontrada")

    user_keys = {}
    cur.execute(
        "SELECT key_version, encrypted_key FROM group_keys WHERE group_id = ? AND username = ?",
        (group_id, me),
    )
    for row in cur.fetchall():
        try:
            encrypted_key = base64.b64decode(row["encrypted_key"])
            session_key = rsa_decrypt_with_pem(my_priv_key, encrypted_key)
            user_keys[row["key_version"]] = session_key
        except Exception:
            continue

    cur.execute(
        "SELECT * FROM group_messages WHERE group_id = ? ORDER BY timestamp ASC",
        (group_id,),
    )
    messages = []
    for msg in cur.fetchall():
        key_version = msg["key_version"]
        if key_version in user_keys:
            plaintext = "<Falha na descriptografia>"
            try:
                session_key = user_keys[key_version]
                iv = bytes.fromhex(msg["iv"])
                encrypted_message = base64.b64decode(msg["encrypted_message"])
                cipher = Blowfish.new(session_key, Blowfish.MODE_CBC, iv)
                decrypted_padded = cipher.decrypt(encrypted_message)
                plaintext = unpad(decrypted_padded, Blowfish.block_size).decode()

                messages.append(
                    {
                        "id": msg["id"],
                        "sender_username": msg["sender_username"],
                        "plaintext": plaintext,
                        "key_version": key_version,
                        "timestamp": msg["timestamp"],
                    }
                )
            except Exception:
                continue

    conn.close()
    return messages
