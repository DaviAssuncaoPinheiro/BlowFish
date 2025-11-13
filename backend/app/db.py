import os
from pymongo import MongoClient
from pymongo.database import Database

MONGO_URI = os.getenv("MONGO_URI", "mongodb://secure_chat_user:supersecretpassword@localhost:27017/")
DB_NAME = "secure_chat_app"

try:
    client = MongoClient(MONGO_URI)
    client.admin.command('ping')
    print("✅ Conexão com o MongoDB estabelecida com sucesso.")
except Exception as e:
    print(f"❌ Falha ao conectar com o MongoDB: {e}")
    client = None

def get_db() -> Database:
    if client is None:
        raise Exception("O cliente MongoDB não está conectado. Verifique a inicialização do app.")
    return client[DB_NAME]

def create_indexes():
    db = get_db()
    db.users.create_index("username", unique=True)
    db.direct_messages.create_index([("sender_username", 1), ("receiver_username", 1)])
    db.direct_messages.create_index("timestamp")
    db.groups.create_index("members")
    db.group_messages.create_index("group_id")
    db.group_messages.create_index("timestamp")
    print("Índices do MongoDB verificados/criados.")