from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select
from .db import init_db, engine
from .models import User
from .schemas import RegisterIn, LoginIn, TokenOut, UserOut
from .auth import make_hash, verify_hash, create_token, auth_required
from .conversations import router as conv_router

app = FastAPI(title="Hybrid Crypto Chat Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"], allow_credentials=True
)

@app.on_event("startup")
def on_startup():
    init_db()
    print("backend: started")

@app.get("/health")
def health():
    print("backend: health")
    return {"ok": True}

@app.post("/auth/register", response_model=TokenOut)
def register(data: RegisterIn):
    print(f"backend: register {data.username}")
    with Session(engine) as s:
        exists = s.exec(select(User).where(User.username == data.username)).first()
        if exists:
            raise HTTPException(400, "username exists")
        user = User(username=data.username, password_hash=make_hash(data.password), rsa_pubkey_pem=data.rsa_pubkey_pem)
        s.add(user)
        s.commit()
        s.refresh(user)
        token = create_token(user.id)
        return {"token": token}

@app.post("/auth/login", response_model=TokenOut)
def login(data: LoginIn):
    print(f"backend: login {data.username}")
    with Session(engine) as s:
        user = s.exec(select(User).where(User.username == data.username)).first()
        if not user or not verify_hash(data.password, user.password_hash):
            raise HTTPException(401, "invalid credentials")
        return {"token": create_token(user.id)}

@app.post("/auth/update_pubkey")
def update_pubkey(pubkey_pem: str, user_id: int = Depends(auth_required)):
    print(f"backend: update_pubkey user={user_id}")
    with Session(engine) as s:
        user = s.get(User, user_id)
        if not user:
            raise HTTPException(404, "user not found")
        user.rsa_pubkey_pem = pubkey_pem
        s.add(user)
        s.commit()
        return {"ok": True}

@app.get("/users", response_model=list[UserOut])
def list_users():
    print("backend: list users")
    with Session(engine) as s:
        users = s.exec(select(User)).all()
        return users

app.include_router(conv_router, dependencies=[Depends(auth_required)])
