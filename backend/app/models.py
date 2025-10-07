from sqlmodel import SQLModel, Field, Relationship
from typing import Optional
from datetime import datetime

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str
    password_hash: str
    rsa_pubkey_pem: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Conversation(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: Optional[str] = None
    is_group: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Participant(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    conversation_id: int
    user_id: int
    session_key_encrypted: bytes
    key_version: int = 1
    joined_at: datetime = Field(default_factory=datetime.utcnow)

class Message(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    conversation_id: int
    sender_id: int
    iv: bytes
    ciphertext: bytes
    hmac: bytes
    key_version: int
    sent_at: datetime = Field(default_factory=datetime.utcnow)
