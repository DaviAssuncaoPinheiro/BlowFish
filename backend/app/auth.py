import os, time, jwt, bcrypt
from fastapi import HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from .db import get_conn
from .crypto_utils import rsa_generate_2048_pem_pair, debug

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
security = HTTPBearer()

def make_hash(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_hash(pw: str, ph: str) -> bool:
    return bcrypt.checkpw(pw.encode(), ph.encode())

def create_token(username: str) -> str:
    payload = {"sub": username, "iat": int(time.time())}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def auth_required(creds: HTTPAuthorizationCredentials = Depends(security)) -> str:
    try:
        data = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        return data["sub"]
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")

def ensure_keys_after_first_login(username: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT public_key, private_key FROM users WHERE username = ?;", (username,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "user not found")
    pub, priv = row
    if pub and priv:
        conn.close()
        return

    print(f"\n[CRYPTO-DEBUG] Usuário '{username}' não possui chaves. Gerando novo par de chaves RSA 2048-bit...")
    priv_pem, pub_pem = rsa_generate_2048_pem_pair()
    print(f"[CRYPTO-DEBUG] Chave Privada para '{username}' (início): {priv_pem[:70].strip()}...")
    print(f"[CRYPTO-DEBUG] Chave Pública para '{username}' (início): {pub_pem[:70].strip()}...")
    
    cur.execute("UPDATE users SET public_key = ?, private_key = ? WHERE username = ?;", (pub_pem, priv_pem, username))
    conn.commit()
    conn.close()
    print(f"[CRYPTO-DEBUG] Chaves de '{username}' salvas no banco de dados.\n")