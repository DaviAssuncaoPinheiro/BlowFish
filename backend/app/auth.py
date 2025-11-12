import os
import time
from datetime import datetime, timedelta
import jwt
import bcrypt
from fastapi import HTTPException, Depends, WebSocket, Query, APIRouter
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from .db import get_db
from .crypto_utils import rsa_generate_2048_pem_pair, encrypt_with_password, decrypt_with_password, encrypt_with_vault_secret, decrypt_with_vault_secret
from .vault import vault
import os

router = APIRouter()

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    JWT_SECRET = "dev-secret-change-me"
JWT_ALG = "HS256"
security = HTTPBearer()

def make_hash(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_hash(pw: str, ph: str) -> bool:
    return bcrypt.checkpw(pw.encode(), ph.encode())

from datetime import datetime, timedelta

from datetime import datetime, timedelta

def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=24),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def auth_required(creds: HTTPAuthorizationCredentials = Depends(security)) -> str:
    try:
        data = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        return data["sub"]
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")

async def get_current_user_ws(token: str = Query(...)) -> str:
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return data["sub"]
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")

@router.get("/users/{username}/public-key")
def get_user_public_key(username: str):
    db = get_db()
    user = db.users.find_one({"username": username}, {"public_key": 1})
    if not user or not user.get("public_key"):
        raise HTTPException(404, "User or public key not found")
    return {"public_key": user["public_key"]}

def generate_and_store_user_keys(username: str, password: str) -> dict:
    priv_pem, pub_pem = rsa_generate_2048_pem_pair()
    
    iv, encrypted_priv_pem_bytes = encrypt_with_vault_secret(priv_pem.encode())
    
    return {
        "public_key": pub_pem, 
        "encrypted_private_key_iv": iv.hex(),
        "encrypted_private_key_ciphertext": encrypted_priv_pem_bytes.hex(),
        "private_key_pem": priv_pem
    }