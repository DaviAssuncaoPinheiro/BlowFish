import os, jwt, time, bcrypt
from fastapi import HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
security = HTTPBearer()

def make_hash(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_hash(pw: str, ph: str) -> bool:
    return bcrypt.checkpw(pw.encode(), ph.encode())

def create_token(user_id: int) -> str:
    payload = {"sub": str(user_id), "iat": int(time.time())}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def auth_required(creds: HTTPAuthorizationCredentials = Depends(security)) -> int:
    try:
        data = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        return int(data["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")
