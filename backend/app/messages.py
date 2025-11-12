from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime
from bson import ObjectId

from .db import get_db
from .auth import auth_required
from .schemas import DirectMessageIn

try:
    from .realtime import manager
except Exception:
    manager = None

router = APIRouter()

@router.post("/messages/send")
async def send_dm(data: DirectMessageIn, sender: str = Depends(auth_required)):
    db = get_db()
    
    # Ensure the recipient exists
    recipient = db.users.find_one({"username": data.to})
    if not recipient:
        raise HTTPException(status_code=404, detail="Destinatário não encontrado")

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
    if manager:
        await manager.send_to_user(data.to, payload)
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
