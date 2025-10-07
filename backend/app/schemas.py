from pydantic import BaseModel
from typing import List, Optional

class RegisterIn(BaseModel):
    username: str
    password: str
    rsa_pubkey_pem: str

class LoginIn(BaseModel):
    username: str
    password: str

class TokenOut(BaseModel):
    token: str

class UserOut(BaseModel):
    id: int
    username: str
    class Config:
        orm_mode = True

class ConversationCreateIn(BaseModel):
    name: Optional[str] = None
    member_ids: List[int]

class MessageIn(BaseModel):
    conversation_id: int
    iv: str
    ciphertext: str
    hmac: str
    key_version: int

class MessageOut(BaseModel):
    id: int
    sender_id: int
    iv: str
    ciphertext: str
    hmac: str
    key_version: int
    class Config:
        orm_mode = True

class SessionInfoOut(BaseModel):
    key_version: int
    session_key_encrypted_b64: str
