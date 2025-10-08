from pydantic import BaseModel
from typing import List, Optional

class RegisterIn(BaseModel):
    username: str
    password: str

class LoginIn(BaseModel):
    username: str
    password: str

class TokenOut(BaseModel):
    token: str

class UserOut(BaseModel):
    username: str

class SendMessageIn(BaseModel):
    to_username: str
    message: str

class MessageOut(BaseModel):
    id: int
    sender_username: str
    receiver_username: str
    plaintext: str
    timestamp: str

class GroupCreateIn(BaseModel):
    name: Optional[str] = None
    members: List[str]

class GroupOut(BaseModel):
    id: int
    name: str
    members: List[str]
    key_version: int

class GroupSendIn(BaseModel):
    conversation_id: int
    message: str

class GroupRemoveIn(BaseModel):
    conversation_id: int
    remove_username: str

class GroupMessageOut(BaseModel):
    id: int
    sender_username: str
    plaintext: str
    key_version: int
    timestamp: str
