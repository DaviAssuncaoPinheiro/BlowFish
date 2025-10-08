from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from .db import init_db, get_conn
from .schemas import RegisterIn, LoginIn, TokenOut, UserOut
from .auth import make_hash, verify_hash, create_token, auth_required, ensure_keys_after_first_login
from .messages import router as messages_router
from .realtime import router as ws_router
from .groups import router as groups_router


app = FastAPI(title="Secure Chat Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"], allow_credentials=True
)

@app.on_event("startup")
def _startup():
    init_db()
    print("[DEBUG] backend: started", flush=True)

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/auth/register", response_model=TokenOut)
def register(data: RegisterIn):
    username = data.username.strip()
    if not username or not data.password:
        raise HTTPException(400, "invalid payload")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?;", (username,))
    if cur.fetchone():
        conn.close()
        raise HTTPException(400, "username exists")
    pw_hash = make_hash(data.password)
    cur.execute("INSERT INTO users (username, password_hash, public_key, private_key) VALUES (?, ?, ?, ?);", (username, pw_hash, "", ""))
    conn.commit()
    conn.close()
    ensure_keys_after_first_login(username)
    return {"token": create_token(username)}

@app.post("/auth/login", response_model=TokenOut)
def login(data: LoginIn):
    username = data.username.strip()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username = ?;", (username,))
    row = cur.fetchone()
    conn.close()
    if not row or not verify_hash(data.password, row[0]):
        raise HTTPException(401, "invalid credentials")
    ensure_keys_after_first_login(username)
    return {"token": create_token(username)}

@app.get("/users", response_model=list[UserOut])
def list_users(me: str = Depends(auth_required)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username != ? ORDER BY username;", (me,))
    rows = cur.fetchall()
    conn.close()
    return [UserOut(username=r[0]) for r in rows]

app.include_router(messages_router, dependencies=[Depends(auth_required)])
app.include_router(groups_router, dependencies=[Depends(auth_required)])
app.include_router(ws_router)
