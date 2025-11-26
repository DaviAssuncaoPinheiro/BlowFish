"""
Script para migrar usernames no banco de dados.
Transforma emails completos em apenas o nome da conta (antes do @).
"""

import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()


def migrate_usernames():
    # Conectar ao MongoDB
    mongo_url = os.getenv("MONGO_URL", "mongodb://localhost:27017")
    client = MongoClient(mongo_url)
    db = client["secure_chat"]

    users = db.users.find({})

    for user in users:
        username = user.get("username", "")

        # Se o username contém @, é um email - converter para apenas o nome
        if "@" in username:
            new_username = username.split("@")[0]
            print(f"Migrando: {username} → {new_username}")

            # Se não tiver email ainda, usar o username antigo (email completo)
            email_value = user.get("email", username)

            # Atualizar o documento
            db.users.update_one(
                {"_id": user["_id"]},
                {"$set": {"username": new_username, "email": email_value}},
            )
        else:
            # Username já está em formato correto
            print(f"OK: {username}")

    print("✅ Migração concluída!")


if __name__ == "__main__":
    migrate_usernames()
