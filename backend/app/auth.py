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
from .email_utils import generate_otp, send_otp_email

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

# --- PASSO 1: VERIFICAÇÃO GOOGLE ---

@router.post("/google") 
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

        if not email or not google_sub:
            raise HTTPException(status_code=400, detail="Erro Google: E-mail não encontrado.")

        user = db.users.find_one({"google_sub": google_sub})
        
        # --- LÓGICA MUDADA AQUI ---
        if not user:
            # Se usuário NÃO existe, não cria automático.
            # Retorna um token temporário de registro para o frontend pedir o Username.
            
            # Verifica se o email já existe como conta normal (conflito)
            if db.users.find_one({"username": email}): 
                 # Edge case: email google igual a um username existente
                 # Ainda assim, vamos pedir um novo username
                 pass

            # Token temporário com os dados do Google
            register_payload = {
                "type": "google_register",
                "email": email,
                "google_sub": google_sub,
                "exp": datetime.utcnow() + timedelta(minutes=10)
            }
            register_token = jwt.encode(register_payload, JWT_SECRET, algorithm=JWT_ALG)

            return {
                "status": "REGISTRATION_REQUIRED",
                "register_token": register_token,
                "default_email": email
            }

        # Se usuário JÁ existe, segue o fluxo de 2FA normal
        username = user["username"]
        return start_2fa_flow(username, db)

    except Exception as e:
        print(f"Erro Auth Google: {e}")
        raise HTTPException(status_code=500, detail=f"Erro interno: {e}")


# --- NOVO ENDPOINT: COMPLETAR REGISTRO ---

@router.post("/google/complete-register")
def complete_google_register(data: dict):
    register_token = data.get("register_token")
    chosen_username = data.get("username", "").strip()

    if not register_token or not chosen_username:
        raise HTTPException(400, "Dados incompletos.")

    # 1. Validar o token de registro
    try:
        payload = jwt.decode(register_token, JWT_SECRET, algorithms=[JWT_ALG])
        if payload.get("type") != "google_register":
            raise HTTPException(400, "Token inválido.")
        
        email = payload["email"]
        google_sub = payload["google_sub"]
    except Exception:
        raise HTTPException(400, "Sessão de registro expirada ou inválida.")

    db = get_db()

    # 2. Verificar se o Username escolhido já existe
    if db.users.find_one({"username": chosen_username}):
        raise HTTPException(400, f"O usuário '{chosen_username}' já está em uso. Escolha outro.")

    # 3. Criar o usuário
    key_data = generate_and_store_user_keys(chosen_username, None)
    new_user = {
        "username": chosen_username,
        "email": email, # Salva o email original para referência
        "google_sub": google_sub, 
        "password_hash": None, 
        "public_key": key_data["public_key"],
        "encrypted_private_key_iv": key_data["encrypted_private_key_iv"],
        "encrypted_private_key_ciphertext": key_data["encrypted_private_key_ciphertext"],
    }
    db.users.insert_one(new_user)

    # 4. Iniciar fluxo de 2FA imediatamente
    return start_2fa_flow(chosen_username, db)


# --- FUNÇÃO AUXILIAR DE 2FA (Reutilizável) ---

def start_2fa_flow(username: str, db):
    # GERAÇÃO DE CÓDIGO 2FA
    otp_code = generate_otp()
    otp_expires = datetime.utcnow() + timedelta(minutes=5)

    # Como agora o username pode ser diferente do email, precisamos achar o email
    # Se foi login direto, o email pode não estar salvo explicitamente no modelo antigo,
    # mas para novos usuários teremos. Para compatibilidade, vamos tentar enviar
    # para o username se ele parecer um email, ou buscar no banco.
    
    user = db.users.find_one({"username": username})
    # Tenta pegar o email salvo, senão assume que o username antigo é o email (legado)
    email_to_send = user.get("email", username) 

    # Salva o código no banco do usuário
    db.users.update_one(
        {"username": username},
        {"$set": {"otp_code": otp_code, "otp_expires": otp_expires}}
    )

    # Envia o e-mail
    sent = send_otp_email(email_to_send, otp_code)
    if not sent:
            raise HTTPException(500, "Falha ao enviar e-mail de verificação.")

    return {
        "status": "2FA_REQUIRED",
        "username": username,
        "message": f"Código enviado para o e-mail cadastrado."
    }


# --- PASSO 2: VALIDAÇÃO DO CÓDIGO 2FA (Mantido) ---

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

    stored_code = user.get("otp_code")
    stored_expiry = user.get("otp_expires")

    if not stored_code or not stored_expiry:
        raise HTTPException(400, "Nenhum código de verificação pendente.")

    if datetime.utcnow() > stored_expiry:
        raise HTTPException(400, "O código expirou. Faça login novamente.")

    if code != stored_code:
        raise HTTPException(400, "Código incorreto.")

    db.users.update_one({"username": username}, {"$unset": {"otp_code": "", "otp_expires": ""}})

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