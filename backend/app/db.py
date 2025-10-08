# backend/app/db.py
import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "chat_app.db")

def get_conn():
    # check_same_thread=False para permitir acesso do FastAPI em threads diferentes
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT,
      public_key TEXT,
      private_key TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS groups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS group_members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      group_id INTEGER NOT NULL,
      username TEXT NOT NULL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS group_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      group_id INTEGER NOT NULL,
      key_version INTEGER NOT NULL,
      username TEXT NOT NULL,
      encrypted_key TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_username TEXT NOT NULL,
      receiver_username TEXT NOT NULL,
      encrypted_message TEXT NOT NULL,
      encrypted_session_key TEXT NOT NULL,
      iv TEXT NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

# garante que o DB e tabelas existam ao importar
try:
    init_db()
    print("[DEBUG] Banco de dados 'chat_app.db' verificado/criado.")
except Exception as e:
    # não quebrar a importação; mostre erro no terminal para diagnóstico
    print(f"[DEBUG] Erro inicializando DB: {e}")
