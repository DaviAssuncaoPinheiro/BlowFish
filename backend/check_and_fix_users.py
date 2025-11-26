"""
Script para verificar e corrigir usernames no banco de dados.
"""

import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()


def check_and_fix_users():
    # Conectar ao MongoDB com as mesmas credenciais do app
    mongo_uri = os.getenv(
        "MONGO_URI", "mongodb://secure_chat_user:supersecretpassword@localhost:27017/"
    )
    db_name = "secure_chat_app"

    client = MongoClient(mongo_uri)
    db = client[db_name]

    users = list(db.users.find({}))

    print(f"\nTotal de usuarios: {len(users)}\n")

    if len(users) == 0:
        print("Nenhum usuário encontrado no banco.")
        return

    for i, user in enumerate(users):
        username = user.get("username", "N/A")
        email = user.get("email", "N/A")
        print(f"{i + 1}. Username: [{username}] | Email: [{email}]")

        # Se username contém @, é um email - converter para apenas o nome
        if "@" in username:
            new_username = username.split("@")[0]
            print(f"   ✓ CORRIGINDO: {username} → {new_username}")

            # Atualizar
            db.users.update_one(
                {"_id": user["_id"]},
                {"$set": {"username": new_username, "email": email or username}},
            )

    print("\n✅ Verificação e correção concluída!")


if __name__ == "__main__":
    check_and_fix_users()
