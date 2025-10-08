# backend/app/groups.py
from fastapi import APIRouter, Request, HTTPException, status
import sqlite3
import os
import base64
import threading
from typing import List, Dict
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from .db import get_conn

try:
    from .realtime import manager
except Exception:
    manager = None

router = APIRouter()
lock = threading.Lock()

def fetch_user_row(conn, username: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()

def fetch_user_public_key(conn, username: str):
    row = fetch_user_row(conn, username)
    return row["public_key"] if row else None

def fetch_group_members(conn, group_id: int) -> List[str]:
    cur = conn.cursor()
    cur.execute("SELECT username FROM group_members WHERE group_id = ?", (group_id,))
    return [r["username"] for r in cur.fetchall()]

def next_key_version(conn, group_id: int) -> int:
    cur = conn.cursor()
    cur.execute("SELECT MAX(key_version) as v FROM group_keys WHERE group_id = ?", (group_id,))
    row = cur.fetchone()
    v = row["v"] if row and row["v"] is not None else 0
    return v + 1

def store_encrypted_key(conn, group_id: int, version: int, username: str, encrypted_b64: str):
    cur = conn.cursor()
    cur.execute("INSERT INTO group_keys (group_id, key_version, username, encrypted_key) VALUES (?, ?, ?, ?)",
                (group_id, version, username, encrypted_b64))
    conn.commit()

def add_group_member_db(conn, group_id: int, username: str):
    cur = conn.cursor()
    cur.execute("INSERT INTO group_members (group_id, username) VALUES (?, ?)", (group_id, username))
    conn.commit()

def remove_group_member_db(conn, group_id: int, username: str):
    cur = conn.cursor()
    cur.execute("DELETE FROM group_members WHERE group_id = ? AND username = ?", (group_id, username))
    conn.commit()

def rsa_encrypt_with_pem(public_pem: str, plaintext: bytes) -> bytes:
    pub = serialization.load_pem_public_key(public_pem.encode())
    ct = pub.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return ct

def get_username_from_auth(request: Request):
    auth = request.headers.get("authorization") or ""
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid auth header")
    return auth.split(" ", 1)[1].strip()

@router.post("/groups/{group_id}/add")
async def add_member(group_id: int, data: dict, request: Request):
    requester = get_username_from_auth(request)
    new_username = data.get("username")
    if not new_username:
        raise HTTPException(status_code=400, detail="username required")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM groups WHERE id = ?", (group_id,))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="group not found")
    cur.execute("SELECT username FROM group_members WHERE group_id = ? AND username = ?", (group_id, requester))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="requester not a member")
    cur.execute("SELECT username FROM users WHERE username = ?", (new_username,))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="user not found")
    cur.execute("SELECT username FROM group_members WHERE group_id = ? AND username = ?", (group_id, new_username))
    if cur.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="user already member")
    add_group_member_db(conn, group_id, new_username)
    print(f"[DEBUG] Usuário '{new_username}' adicionado ao grupo {group_id} por '{requester}'")
    version = next_key_version(conn, group_id)
    print(f"[DEBUG] Rotacionando chaves do grupo {group_id} para versão {version}...")
    members = fetch_group_members(conn, group_id)
    for member in members:
        public_pem = fetch_user_public_key(conn, member)
        if not public_pem:
            print(f"[DEBUG] Sem chave pública para {member}; pulando.")
            continue
        session_key = os.urandom(16)
        session_hex = session_key.hex()
        session_b64 = base64.b64encode(session_key).decode()
        print(f"[DEBUG] Gerando chave de sessão Blowfish para membro '{member}' -> hex:{session_hex} base64:{session_b64}")
        try:
            encrypted = rsa_encrypt_with_pem(public_pem, session_key)
            encrypted_b64 = base64.b64encode(encrypted).decode()
            store_encrypted_key(conn, group_id, version, member, encrypted_b64)
            print(f"[DEBUG] Armazenada chave cifrada para {member} (base64 prefix={encrypted_b64[:32]}...)")
        except Exception as e:
            print(f"[DEBUG] Erro cifrando para {member}: {e}")
    conn.close()
    payload = {
        "type": "group",
        "conversation_id": group_id,
        "system_note": f"Usuário '{new_username}' adicionado. Chaves rotacionadas para versão {version}.",
        "key_version": version
    }
    if manager:
        await manager.broadcast(members, payload)
        print(f"[DEBUG] Broadcast enviado para membros: {members}")
    else:
        print(f"[DEBUG] Manager não disponível, skipping broadcast. payload={payload}")
    return {"ok": True, "added": new_username, "key_version": version}

@router.post("/groups/{group_id}/remove")
async def remove_member(group_id: int, data: dict, request: Request):
    requester = get_username_from_auth(request)
    rem_username = data.get("username")
    if not rem_username:
        raise HTTPException(status_code=400, detail="username required")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM groups WHERE id = ?", (group_id,))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="group not found")
    cur.execute("SELECT username FROM group_members WHERE group_id = ? AND username = ?", (group_id, requester))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="requester not a member")
    cur.execute("SELECT username FROM group_members WHERE group_id = ? AND username = ?", (group_id, rem_username))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="user not in group")
    remove_group_member_db(conn, group_id, rem_username)
    print(f"[DEBUG] Usuário '{rem_username}' removido do grupo {group_id} por '{requester}'")
    version = next_key_version(conn, group_id)
    print(f"[DEBUG] Rotacionando chaves do grupo {group_id} para versão {version} após remoção...")
    members = fetch_group_members(conn, group_id)
    for member in members:
        public_pem = fetch_user_public_key(conn, member)
        if not public_pem:
            print(f"[DEBUG] Sem chave pública para {member}; pulando.")
            continue
        session_key = os.urandom(16)
        session_hex = session_key.hex()
        session_b64 = base64.b64encode(session_key).decode()
        print(f"[DEBUG] Gerando chave de sessão Blowfish para membro '{member}' -> hex:{session_hex} base64:{session_b64}")
        try:
            encrypted = rsa_encrypt_with_pem(public_pem, session_key)
            encrypted_b64 = base64.b64encode(encrypted).decode()
            store_encrypted_key(conn, group_id, version, member, encrypted_b64)
            print(f"[DEBUG] Armazenada chave cifrada para {member} (base64 prefix={encrypted_b64[:32]}...)")
        except Exception as e:
            print(f"[DEBUG] Erro cifrando para {member}: {e}")
    conn.close()
    payload = {
        "type": "group",
        "conversation_id": group_id,
        "system_note": f"Usuário '{rem_username}' removido. Chaves rotacionadas para versão {version}.",
        "key_version": version
    }
    if manager:
        await manager.broadcast(members, payload)
        print(f"[DEBUG] Broadcast enviado para membros: {members}")
    else:
        print(f"[DEBUG] Manager não disponível, skipping broadcast. payload={payload}")
    return {"ok": True, "removed": rem_username, "key_version": version}

@router.get("/groups/{group_id}/keys")
async def list_group_keys(group_id: int, request: Request):
    _ = get_username_from_auth(request)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT key_version, username, encrypted_key, created_at FROM group_keys WHERE group_id = ? ORDER BY key_version DESC, id DESC", (group_id,))
    rows = cur.fetchall()
    result = []
    for r in rows:
        result.append({
            "key_version": r["key_version"],
            "username": r["username"],
            "encrypted_key": r["encrypted_key"],
            "created_at": r["created_at"]
        })
    conn.close()
    print(f"[DEBUG] Chaves listadas para group {group_id}, count={len(result)}")
    return result
