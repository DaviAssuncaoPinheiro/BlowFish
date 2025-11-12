from fastapi import APIRouter, HTTPException, Depends
import os
import base64
from typing import List
from bson import ObjectId
from datetime import datetime

from .db import get_db
from .auth import auth_required
from .crypto_utils import rsa_encrypt, decrypt_with_vault_secret, rsa_decrypt, blowfish_decrypt

try:
    from .realtime import manager
except Exception:
    manager = None

router = APIRouter()


def fetch_user_public_key(username: str):
    db = get_db()
    user = db.users.find_one({"username": username}, {"public_key": 1})
    return user["public_key"] if user else None


@router.post("/groups/create")
async def create_new_group(data: dict, me: str = Depends(auth_required)):
    name = data.get("name") or f"Grupo de {me}"
    members = list(set(data.get("members", [])))
    if me not in members:
        members.append(me)

    db = get_db()

    version = 1
    session_key = os.urandom(16)

    keys_for_members = []
    for member in members:
        public_pem = fetch_user_public_key(member)
        if not public_pem:
            continue
        encrypted = rsa_encrypt(public_pem, session_key)
        encrypted_b64 = base64.b64encode(encrypted).decode()
        keys_for_members.append({
            "username": member,
            "encrypted_key": encrypted_b64
        })

    group_doc = {
        "name": name,
        "members": members,
        "key_versions": [
            {
                "version": 1,
                "created_at": datetime.utcnow(),
                "keys": keys_for_members
            }
        ]
    }
    result = db.groups.insert_one(group_doc)
    group_id = result.inserted_id

    return {"ok": True, "id": str(group_id)}


@router.post("/groups/{group_id}/add")
async def add_member(
    group_id: str, data: dict, requester: str = Depends(auth_required)
):
    new_username = data.get("username")

    db = get_db()
    group_oid = ObjectId(group_id)

    group = db.groups.find_one({"_id": group_oid})
    if not group:
        raise HTTPException(404, "Grupo não encontrado")

    if requester not in group["members"]:
        raise HTTPException(403, "Você não tem permissão para adicionar membros a este grupo")

    db.groups.update_one({"_id": group_oid}, {"$addToSet": {"members": new_username}})

    current_version = max(v['version'] for v in group['key_versions'])
    new_version = current_version + 1
    new_session_key = os.urandom(16)

    updated_members = group['members'] + [new_username]
    keys_for_members = []
    for member in updated_members:
        public_pem = fetch_user_public_key(member)
        if not public_pem:
            continue
        encrypted = rsa_encrypt(public_pem, new_session_key)
        encrypted_b64 = base64.b64encode(encrypted).decode()
        keys_for_members.append({"username": member, "encrypted_key": encrypted_b64})

    db.groups.update_one({"_id": group_oid}, {
        "$push": {
            "key_versions": {
                "version": new_version,
                "created_at": datetime.utcnow(),
                "keys": keys_for_members
            }
        }
    })

    return {"ok": True}


@router.post("/groups/{group_id}/remove")
async def remove_member(
    group_id: str, data: dict, requester: str = Depends(auth_required)
):
    username_to_remove = data.get("username")

    db = get_db()
    group_oid = ObjectId(group_id)

    group = db.groups.find_one({"_id": group_oid})
    if not group:
        raise HTTPException(404, "Grupo não encontrado")

    if requester not in group["members"]:
        raise HTTPException(403, "Você não tem permissão para remover membros deste grupo")

    if username_to_remove not in group["members"]:
        raise HTTPException(404, "Usuário não encontrado no grupo")

    db.groups.update_one({"_id": group_oid}, {"$pull": {"members": username_to_remove}})

    current_version = max(v['version'] for v in group['key_versions'])
    new_version = current_version + 1
    new_session_key = os.urandom(16)

    remaining_members = [m for m in group["members"] if m != username_to_remove]
    keys_for_members = []
    for member in remaining_members:
        public_pem = fetch_user_public_key(member)
        if not public_pem:
            continue
        encrypted = rsa_encrypt(public_pem, new_session_key)
        encrypted_b64 = base64.b64encode(encrypted).decode()
        keys_for_members.append({"username": member, "encrypted_key": encrypted_b64})

    db.groups.update_one({"_id": group_oid}, {
        "$push": {
            "key_versions": {
                "version": new_version,
                "created_at": datetime.utcnow(),
                "keys": keys_for_members
            }
        }
    })

    return {"ok": True}


@router.get("/groups")
async def list_user_groups(me: str = Depends(auth_required)):
    db = get_db()
    user_groups = db.groups.find({"members": me})
    groups_out = []
    for group in user_groups:
        latest_version = max(v['version'] for v in group['key_versions'])

        groups_out.append(
            {
                "id": str(group["_id"]),
                "name": group["name"],
                "members": group["members"],
                "key_version": latest_version,
                "key_versions": group["key_versions"],
            }
        )
    return groups_out


@router.post("/groups/{group_id}/send")
async def send_group_message(group_id: str, data: dict, sender: str = Depends(auth_required)):
    encrypted_message = data.get("encrypted_message")
    iv = data.get("iv")
    key_version = data.get("key_version")

    if not all([encrypted_message, iv, key_version]):
        raise HTTPException(400, "Payload incompleto")

    db = get_db()
    group_oid = ObjectId(group_id)

    group = db.groups.find_one({"_id": group_oid}, {"members": 1})
    if not group:
        raise HTTPException(404, "Grupo não encontrado")

    if sender not in group["members"]:
        raise HTTPException(status_code=403, detail="Você não é membro deste grupo")

    msg_doc = {
        "group_id": group_oid,
        "sender_username": sender,
        "encrypted_message": encrypted_message,
        "iv": iv,
        "key_version": key_version,
        "timestamp": datetime.utcnow()
    }
    result = db.group_messages.insert_one(msg_doc)
    msg_id = result.inserted_id

    payload = {
        "type": "group",
        "from": sender,
        "conversation_id": group_id,
        "msg_id": str(msg_id),
        "key_version": key_version,
    }
    if manager:
        await manager.broadcast(group["members"], payload)

    try:
        recipient_username = next((m for m in group["members"] if m != sender), None)
        if not recipient_username:
            raise Exception("Nenhum outro membro no grupo para usar como exemplo.")
        recipient_user = db.users.find_one({"username": recipient_username})
        priv_key_iv = bytes.fromhex(recipient_user["encrypted_private_key_iv"])
        priv_key_ct = bytes.fromhex(recipient_user["encrypted_private_key_ciphertext"])
        recipient_priv_key_pem = decrypt_with_vault_secret(priv_key_iv, priv_key_ct)

        full_group = db.groups.find_one({"_id": group_oid})
        key_version_data = next((v for v in full_group["key_versions"] if v["version"] == key_version), None)
        if not key_version_data:
            raise Exception(f"Versão da chave {key_version} não encontrada para o grupo.")

        user_key_data = next((k for k in key_version_data["keys"] if k["username"] == recipient_username), None)
        encrypted_session_key = base64.b64decode(user_key_data["encrypted_key"])
        session_key = rsa_decrypt(recipient_priv_key_pem.decode(), encrypted_session_key)
        print(f"--- [DEBUG] 3. Chave de sessão do grupo descriptografada com RSA.")

        encrypted_message_bytes = base64.b64decode(encrypted_message)
        iv_bytes = base64.b64decode(iv)
        plaintext = blowfish_decrypt(iv_bytes, encrypted_message_bytes, session_key)
        print(f"--- [DEBUG] 4. MENSAGEM DE GRUPO DESCRIPTOGRAFADA COM BLOWFISH: '{plaintext}'")
    except Exception as e:
        print(f"--- [DEBUG] Falha ao tentar descriptografar a mensagem de grupo no backend: {e}")

    return {"ok": True, "id": str(msg_id)}


@router.get("/groups/{group_id}/history")
async def get_group_history(group_id: str, me: str = Depends(auth_required)):
    db = get_db()
    group_oid = ObjectId(group_id)

    group = db.groups.find_one({"_id": group_oid}, {"members": 1, "key_versions": 1})
    if not group or me not in group["members"]:
        raise HTTPException(status_code=403, detail="Acesso negado")

    group_msgs_cursor = db.group_messages.find({"group_id": group_oid}).sort("timestamp", 1)
    
    messages = []
    for msg in group_msgs_cursor:
        msg["_id"] = str(msg["_id"])
        msg["group_id"] = str(msg["group_id"])
        messages.append(msg)

    return {
        "messages": messages,
        "key_versions": group.get("key_versions", [])
    }
