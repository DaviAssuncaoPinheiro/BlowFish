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
    with Session(engine) as s:
        if not data.member_ids:
            raise HTTPException(400, "member_ids empty")

        conv = Conversation(name=data.name, is_group=(len(data.member_ids) > 2))
        s.add(conv); s.commit(); s.refresh(conv)

        session_key = generate_blowfish_key()

        # cifra a chave para cada membro
        for uid in data.member_ids:
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
    with Session(engine) as s:
        # checa participação
        part = s.exec(select(Participant).where(
            Participant.conversation_id == conv_id,
            Participant.user_id == user_id
        )).first()
        if not part:
            raise HTTPException(403, "not a participant")

        rows = s.exec(select(Message).where(
            Message.conversation_id == conv_id
        ).order_by(Message.id.desc()).limit(limit)).all()

        # prepara saída base64
        out = []
        for m in reversed(rows):  # ordem crescente
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
    with Session(engine) as s:
        conv = s.get(Conversation, conv_id)
        if not conv:
            raise HTTPException(404, "conversation not found")

        # participantes atuais
        parts = s.exec(select(Participant).where(Participant.conversation_id == conv_id)).all()
        if not parts:
            raise HTTPException(400, "no participants")

        # remove usuário (se existir)
        for p in parts:
            if p.user_id == removed_user_id:
                s.delete(p)
        s.commit()

        # nova versão
        remaining = s.exec(select(Participant).where(Participant.conversation_id == conv_id)).all()
        if not remaining:
            raise HTTPException(400, "no remaining participants")

        new_version = max(p.key_version for p in remaining) + 1
        new_key = generate_blowfish_key()

        # recifrar para cada restante
        for p in remaining:
            user = s.get(User, p.user_id)
            enc = rsa_encrypt(user.rsa_pubkey_pem, new_key)
            p.session_key_encrypted = enc
            p.key_version = new_version

        s.commit()
        return {"message": "rekey complete", "key_version": new_version}

@router.post("/send")
def send_message(msg: MessageIn, user_id: int = Depends(auth_required)):
    with Session(engine) as s:
        # garante que o remetente participa e que a versão existe
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
