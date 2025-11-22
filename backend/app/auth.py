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
from .email_utils import generate_otp, send_otp_email # <--- IMPORTADO

# Novas importações do Google
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google_auth_oauthlib.flow import Flow

from .schemas import TokenOut 

router = APIRouter()

JWT_SECRET = os.getenv("JWT_SECRET") or "dev-secret-change-me"
JWT_ALG = "HS256"
security = HTTPBearer()

# ... (Funções auxiliares: make_hash, verify_hash, create_token, auth_required, get_current_user_ws mantidas iguais) ...
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
        "private_key_pem": priv_pem 
    }

# --- PASSO 1: LOGIN GOOGLE E ENVIO DE E-MAIL ---

@router.post("/google") # Note: Retorno genérico (dict) pois pode ser Token ou Status 2FA
def auth_google(data: dict):
    db = get_db()
    code = data.get("code")
    
    if not code:
        raise HTTPException(status_code=400, detail="Código (code) não fornecido.")

    try:
        client_config = {
            "web": {
                "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URI")]
            }
        }

        flow = Flow.from_client_config(
            client_config,
            scopes=None, 
            redirect_uri=os.getenv("GOOGLE_REDIRECT_URI")
        )
        
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
            raise HTTPException(status_code=400, detail="Erro Google: E-mail não encontrado.")

        user = db.users.find_one({"google_sub": google_sub})
        
        if not user:
            # Se usuário não existe, cria a conta primeiro
            if db.users.find_one({"username": username}):
                 raise HTTPException(400, "Este email já está em uso.")
                 
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
            user = db.users.find_one({"username": username}) # Recarrega o usuário criado

        # --- GERAÇÃO DE CÓDIGO 2FA ---
        otp_code = generate_otp()
        otp_expires = datetime.utcnow() + timedelta(minutes=5)

        # Salva o código no banco do usuário
        db.users.update_one(
            {"username": username},
            {"$set": {"otp_code": otp_code, "otp_expires": otp_expires}}
        )

        # Envia o e-mail
        sent = send_otp_email(username, otp_code)
        if not sent:
             raise HTTPException(500, "Falha ao enviar e-mail de verificação.")

        # Retorna instrução para o Frontend mudar de tela
        return {
            "require_2fa": True,
            "username": username,
            "message": f"Código enviado para {username}"
        }

    except Exception as e:
        print(f"Erro Auth Google: {e}")
        raise HTTPException(status_code=500, detail=f"Erro interno: {e}")


# --- PASSO 2: VALIDAÇÃO DO CÓDIGO 2FA ---

@router.post("/verify-2fa", response_model=TokenOut)
def verify_2fa(data: dict):
    username = data.get("username")
    code = data.get("code")

    if not username or not code:
        raise HTTPException(400, "Dados incompletos.")

    db = get_db()
    user = db.users.find_one({"username": username})

    if not user:
        raise HTTPException(404, "Usuário não encontrado.")

    # Verifica validade do código
    stored_code = user.get("otp_code")
    stored_expiry = user.get("otp_expires")

    if not stored_code or not stored_expiry:
        raise HTTPException(400, "Nenhum código de verificação pendente.")

    if datetime.utcnow() > stored_expiry:
        raise HTTPException(400, "O código expirou. Faça login novamente.")

    if code != stored_code:
        raise HTTPException(400, "Código incorreto.")

    # --- SUCESSO: Limpa o código e libera o acesso ---
    db.users.update_one({"username": username}, {"$unset": {"otp_code": "", "otp_expires": ""}})

    # Descriptografa a chave privada
    iv = bytes.fromhex(user["encrypted_private_key_iv"])
    ciphertext = bytes.fromhex(user["encrypted_private_key_ciphertext"])
    
    try:
        private_key_pem = decrypt_with_vault_secret(iv, ciphertext).decode()
    except Exception as e:
        raise HTTPException(500, f"Erro ao descriptografar chaves: {e}")

    return {
        "token": create_token(user["username"]),
        "username": user["username"],
        "private_key": private_key_pem, 
        "public_key": user["public_key"]
    }