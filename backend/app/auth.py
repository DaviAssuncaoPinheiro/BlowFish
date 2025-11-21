import os
import time
from datetime import datetime, timedelta
import jwt
import bcrypt
from fastapi import HTTPException, Depends, WebSocket, Query, APIRouter
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from .db import get_db
from .crypto_utils import rsa_generate_2048_pem_pair, encrypt_with_vault_secret, decrypt_with_vault_secret
from .vault import vault
import os

# Novas importações do Google
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google_auth_oauthlib.flow import Flow

from .schemas import TokenOut # Importar o schema de resposta

router = APIRouter()

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    JWT_SECRET = "dev-secret-change-me"

# --- CORREÇÃO AQUI ---
# O algoritmo correto é HS256 (256 bits), não HS265.
JWT_ALG = "HS256" 
# --- FIM DA CORREÇÃO ---

security = HTTPBearer()

def make_hash(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_hash(pw: str, ph: str) -> bool:
    return bcrypt.checkpw(pw.encode(), ph.encode())

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

def generate_and_store_user_keys(username: str, password: str) -> dict:
    priv_pem, pub_pem = rsa_generate_2048_pem_pair()
    
    iv, encrypted_priv_pem_bytes = encrypt_with_vault_secret(priv_pem.encode())
    
    return {
        "public_key": pub_pem, 
        "encrypted_private_key_iv": iv.hex(),
        "encrypted_private_key_ciphertext": encrypted_priv_pem_bytes.hex(),
        "private_key_pem": priv_pem # Chave privada para retornar ao cliente
    }

@router.post("/google", response_model=TokenOut)
def auth_google(data: dict):
    db = get_db()
    code = data.get("code")
    
    if not code:
        raise HTTPException(status_code=400, detail="Código (code) não fornecido.")

    try:
        # 1. Definir a configuração do cliente primeiro
        client_config = {
            "web": {
                "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URI")]
            }
        }

        # 2. Inicializar o Flow a partir do config, não de um arquivo
        flow = Flow.from_client_config(
            client_config,
            scopes=None, # Escopos não são necessários
            redirect_uri=os.getenv("GOOGLE_REDIRECT_URI")
        )
        
        # 3. Trocar o 'code' pelo token de ID do Google
        credentials = flow.fetch_token(code=code)
        id_token_info = id_token.verify_oauth2_token(
            credentials['id_token'], 
            google_requests.Request(), 
            os.getenv("GOOGLE_CLIENT_ID")
        )

        email = id_token_info.get("email")
        google_sub = id_token_info.get("sub") 
        username = email 

        if not email or not google_sub:
            raise HTTPException(status_code=400, detail="Não foi possível obter informações do Google.")

        # 4. Encontrar ou Criar o Usuário
        user = db.users.find_one({"google_sub": google_sub})
        
        if not user:
            # Usuário não existe, vamos criá-lo
            print(f"--- [AUTH] Criando novo usuário via Google: {username} ---")
            
            if db.users.find_one({"username": username}):
                 raise HTTPException(400, "Este email já está em uso por uma conta local.")
                 
            key_data = generate_and_store_user_keys(username, None)

            new_user = {
                "username": username,
                "google_sub": google_sub, 
                "password_hash": None, 
                "public_key": key_data["public_key"],
                "encrypted_private_key_iv": key_data["encrypted_private_key_iv"],
                "encrypted_private_key_ciphertext": key_data["encrypted_private_key_ciphertext"],
            }
            db.users.insert_one(new_user)
            
            return {
                "token": create_token(username),
                "username": username,
                "private_key": key_data["private_key_pem"], 
                "public_key": key_data["public_key"]
            }

        else:
            # Usuário existe, vamos fazer login
            print(f"--- [AUTH] Logando usuário via Google: {username} ---")
            
            iv = bytes.fromhex(user["encrypted_private_key_iv"])
            ciphertext = bytes.fromhex(user["encrypted_private_key_ciphertext"])
            
            try:
                private_key_pem = decrypt_with_vault_secret(iv, ciphertext).decode()
            except Exception as e:
                raise HTTPException(500, f"Failed to decrypt private key: {e}")

            return {
                "token": create_token(user["username"]),
                "username": user["username"],
                "private_key": private_key_pem, 
                "public_key": user["public_key"]
            }

    except Exception as e:
        print(f"Erro na autenticação Google: {e}")
        # Retornar o erro real para depuração no frontend
        raise HTTPException(status_code=500, detail=f"Falha na autenticação Google: {e}")