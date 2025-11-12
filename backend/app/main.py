from dotenv import load_dotenv
load_dotenv()



from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from .db import get_db, create_indexes
from .schemas import RegisterIn, LoginIn, TokenOut, UserOut
from .auth import make_hash, verify_hash, create_token, auth_required, generate_and_store_user_keys
from .crypto_utils import decrypt_with_password # Add this import
from .messages import router as messages_router
from .realtime import router as ws_router
from .groups import router as groups_router


app = FastAPI(title="Secure Chat Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

@app.on_event("startup")
def _startup():
    create_indexes()

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/auth/register", response_model=TokenOut)
def register(data: RegisterIn):
    try:
        username = data.username.strip()
        if not username or not data.password or len(data.password) < 8:
            raise HTTPException(400, "invalid payload, password must be at least 8 characters")
        db = get_db()
        if db.users.find_one({"username": username}):
            raise HTTPException(400, "username exists")
        pw_hash = make_hash(data.password)
        
        key_data = generate_and_store_user_keys(username, data.password)

        db.users.insert_one({
            "username": username,
            "password_hash": pw_hash,
            "public_key": key_data["public_key"],
            "encrypted_private_key_iv": key_data["encrypted_private_key_iv"],
            "encrypted_private_key_ciphertext": key_data["encrypted_private_key_ciphertext"],
        })
        
        return {
            "token": create_token(username), 
            "private_key": key_data["private_key_pem"], 
            "public_key": key_data["public_key"]
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(500, f"Internal server error: {e}")

@app.post("/auth/login", response_model=TokenOut)
def login(data: LoginIn):
    try:
        username = data.username.strip()
        db = get_db()
        user = db.users.find_one({"username": username})

        if not user or not verify_hash(data.password, user["password_hash"]):
            raise HTTPException(401, "invalid credentials")
        
        user = db.users.find_one({"username": username})

        if not user.get("encrypted_private_key_iv") or \
           not user.get("encrypted_private_key_ciphertext"):
            raise HTTPException(500, "Private key information missing for user")

        iv = bytes.fromhex(user["encrypted_private_key_iv"])
        ciphertext = bytes.fromhex(user["encrypted_private_key_ciphertext"])
        
        try:
            private_key_pem = decrypt_with_vault_secret(iv, ciphertext).decode()
        except Exception as e:
            raise HTTPException(500, f"Failed to decrypt private key: {e}")

        return {
            "token": create_token(username), 
            "private_key": private_key_pem, 
            "public_key": user["public_key"]
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(500, f"Internal server error: {e}")

@app.get("/users", response_model=list[UserOut])
def list_users(me: str = Depends(auth_required)):
    db = get_db()
    users = db.users.find({"username": {"$ne": me}}, {"username": 1}).sort("username", 1)
    return [UserOut(username=u["username"]) for u in users]

@app.get("/users/{username}/public_key")
def get_user_public_key(username: str, me: str = Depends(auth_required)):
    db = get_db()
    user = db.users.find_one({"username": username}, {"public_key": 1})
    if not user or not user.get("public_key"):
        raise HTTPException(status_code=404, detail="Public key not found for user")
    return {"public_key": user["public_key"]}

app.include_router(messages_router, dependencies=[Depends(auth_required)])
app.include_router(groups_router, dependencies=[Depends(auth_required)])
app.include_router(ws_router)
