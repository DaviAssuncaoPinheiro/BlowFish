from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select
from .db import engine
from .models import User, Conversation, Participant, Message
from .schemas import ConversationCreateIn, MessageIn, MessageOut, SessionInfoOut
from .crypto_utils import rsa_encrypt, generate_blowfish_key
from .auth import auth_required
import base64

router = APIRouter(prefix="/conversations", tags=["conversations"])

@router.post("/")
def create_conversation(data: ConversationCreateIn, user_id: int = Depends(auth_required)):
    print(f"backend: create conversation by {user_id} members={data.member_ids}")
    with Session(engine) as s:
        members = set(data.member_ids or [])
        members.add(user_id)
        conv = Conversation(name=data.name, is_group=(len(members) > 2))
        s.add(conv); s.commit(); s.refresh(conv)
        session_key = generate_blowfish_key()
        for uid in sorted(members):
            user = s.get(User, uid)
            if not user or not user.rsa_pubkey_pem:
                raise HTTPException(status_code=400, detail=f"user {uid} invalid (no pubkey?)")
            enc = rsa_encrypt(user.rsa_pubkey_pem, session_key)
            p = s.exec(select(Participant).where(
                Participant.conversation_id == conv.id,
                Participant.user_id == uid
            )).first()
            if p:
                p.session_key_encrypted = enc
                p.key_version = 1
            else:
                s.add(Participant(
                    conversation_id=conv.id,
                    user_id=uid,
                    session_key_encrypted=enc,
                    key_version=1
                ))
        s.commit()
        return {"conversation_id": conv.id, "key_version": 1}

@router.get("/{conv_id}/session_info", response_model=SessionInfoOut)
def get_session_info(conv_id: int, user_id: int = Depends(auth_required)):
    print(f"backend: session_info conv={conv_id} user={user_id}")
    with Session(engine) as s:
        p = s.exec(select(Participant).where(
            Participant.conversation_id == conv_id,
            Participant.user_id == user_id
        )).first()
        if not p:
            raise HTTPException(403, "not a participant")
        return {
            "key_version": p.key_version,
            "session_key_encrypted_b64": base64.b64encode(p.session_key_encrypted).decode()
        }

@router.get("/{conv_id}/messages", response_model=list[MessageOut])
def list_messages(conv_id: int, limit: int = Query(50, ge=1, le=200), user_id: int = Depends(auth_required)):
    print(f"backend: list_messages conv={conv_id} user={user_id} limit={limit}")
    with Session(engine) as s:
        part = s.exec(select(Participant).where(
            Participant.conversation_id == conv_id,
            Participant.user_id == user_id
        )).first()
        if not part:
            raise HTTPException(403, "not a participant")
        rows = s.exec(select(Message).where(
            Message.conversation_id == conv_id
        ).order_by(Message.id.desc()).limit(limit)).all()
        out = []
        for m in reversed(rows):
            out.append(MessageOut(
                id=m.id,
                sender_id=m.sender_id,
                iv=base64.b64encode(m.iv).decode(),
                ciphertext=base64.b64encode(m.ciphertext).decode(),
                hmac=base64.b64encode(m.hmac).decode(),
                key_version=m.key_version
            ))
        return out

@router.post("/{conv_id}/rekey")
def rekey_conversation(conv_id: int, removed_user_id: int, user_id: int = Depends(auth_required)):
    print(f"backend: rekey conv={conv_id} removed={removed_user_id} by={user_id}")
    with Session(engine) as s:
        conv = s.get(Conversation, conv_id)
        if not conv:
            raise HTTPException(404, "conversation not found")
        parts = s.exec(select(Participant).where(Participant.conversation_id == conv_id)).all()
        if not parts:
            raise HTTPException(400, "no participants")
        for p in parts:
            if p.user_id == removed_user_id:
                s.delete(p)
        s.commit()
        remaining = s.exec(select(Participant).where(Participant.conversation_id == conv_id)).all()
        if not remaining:
            raise HTTPException(400, "no remaining participants")
        new_version = max(p.key_version for p in remaining) + 1
        new_key = generate_blowfish_key()
        for p in remaining:
            user = s.get(User, p.user_id)
            enc = rsa_encrypt(user.rsa_pubkey_pem, new_key)
            p.session_key_encrypted = enc
            p.key_version = new_version
        s.commit()
        return {"message": "rekey complete", "key_version": new_version}

@router.post("/send")
def send_message(msg: MessageIn, user_id: int = Depends(auth_required)):
    print(f"backend: send conv={msg.conversation_id} user={user_id} kv={msg.key_version}")
    with Session(engine) as s:
        part = s.exec(select(Participant).where(
            Participant.conversation_id == msg.conversation_id,
            Participant.user_id == user_id
        )).first()
        if not part:
            raise HTTPException(403, "not a participant")
        m = Message(
            conversation_id=msg.conversation_id,
            sender_id=user_id,
            iv=base64.b64decode(msg.iv),
            ciphertext=base64.b64decode(msg.ciphertext),
            hmac=base64.b64decode(msg.hmac),
            key_version=msg.key_version
        )
        s.add(m); s.commit()
        return {"ok": True, "id": m.id}
