from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime
from bson import ObjectId
import base64

from .db import get_db
from .auth import auth_required
from .schemas import DirectMessageIn
from .crypto_utils import decrypt_with_vault_secret, rsa_decrypt, blowfish_decrypt

try:
    from .realtime import manager
except Exception:
    manager = None

router = APIRouter()

@router.post("/messages/send")
async def send_dm(data: DirectMessageIn, sender: str = Depends(auth_required)):
    db = get_db()
    
    recipient = db.users.find_one({"username": data.to})
    if not recipient:
        raise HTTPException(status_code=404, detail="Destinatário não encontrado")

    print("\n--- [MESSAGES] Nova mensagem direta recebida ---")
    print(f"De: {sender} | Para: {data.to}")
    print(f"Mensagem Criptografada: {data.encrypted_message}")

    msg_doc = {
        "sender_username": sender,
        "receiver_username": data.to,
        "encrypted_message": data.encrypted_message,
        "encrypted_session_key": data.encrypted_session_key,
        "sender_encrypted_session_key": data.sender_encrypted_session_key,
        "iv": data.iv,
        "timestamp": datetime.utcnow(),
    }
    
    result = db.direct_messages.insert_one(msg_doc)
    msg_id = result.inserted_id

    payload = {
        "type": "dm",
        "_id": str(msg_id),
        "sender_username": sender,
        "receiver_username": data.to,
        "encrypted_message": data.encrypted_message,
        "encrypted_session_key": data.encrypted_session_key,
        "sender_encrypted_session_key": data.sender_encrypted_session_key,
        "iv": data.iv,
        "timestamp": msg_doc['timestamp'].isoformat() + "Z",
    }

    try:
        recipient_user = db.users.find_one({"username": data.to})
        priv_key_iv = bytes.fromhex(recipient_user["encrypted_private_key_iv"])
        priv_key_ct = bytes.fromhex(recipient_user["encrypted_private_key_ciphertext"])
        recipient_priv_key_pem = decrypt_with_vault_secret(priv_key_iv, priv_key_ct)

        encrypted_session_key = base64.b64decode(data.encrypted_session_key)
        session_key = rsa_decrypt(recipient_priv_key_pem.decode(), encrypted_session_key)
        print(f"--- [DEBUG] 3. Chave de sessão descriptografada com RSA.")

        encrypted_message = base64.b64decode(data.encrypted_message)
        iv_bytes = base64.b64decode(data.iv)
        plaintext = blowfish_decrypt(iv_bytes, encrypted_message, session_key)
        print(f"--- [DEBUG] 4. MENSAGEM DESCRIPTOGRAFADA COM BLOWFISH: '{plaintext}'")

    except Exception as e:
        print(f"--- [DEBUG] Falha ao tentar descriptografar a mensagem no backend: {e}")

    if manager:
        await manager.send_to_user(data.to, payload)
        print(f"--- [MESSAGES] Mensagem encaminhada para '{data.to}' via WebSocket.")
        await manager.send_to_user(sender, payload)

    return {"ok": True, "id": str(msg_id)}


@router.get("/messages/history")
async def history(peer: str, me: str = Depends(auth_required)):
    db = get_db()
    
    query = {
        "$or": [
            {"sender_username": me, "receiver_username": peer},
            {"sender_username": peer, "receiver_username": me},
        ]
    }
    
    messages_cursor = db.direct_messages.find(query).sort("timestamp", 1)
    
    messages = []
    for msg in messages_cursor:
        msg["_id"] = str(msg["_id"])
        messages.append(msg)
        
    return messages
