"""
Script para verificar usernames no banco de dados.
"""

import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()


def check_users():
    # Conectar ao MongoDB
    mongo_url = os.getenv("MONGO_URL", "mongodb://localhost:27017")
    client = MongoClient(mongo_url)

    # Lista todos os bancos de dados
    databases = client.list_database_names()
    print(f"Bancos de dados disponíveis: {databases}\n")

    # Procura em cada banco
    for db_name in databases:
        if db_name in ["admin", "config", "local"]:
            continue
        db = client[db_name]
        if "users" in db.list_collection_names():
            print(f"=== BANCO: {db_name} ===")
            users = list(db.users.find({}))
            print(f"Total de usuarios: {len(users)}")
            for i, user in enumerate(users):
                username = user.get("username", "N/A")
                email = user.get("email", "N/A")
                print(f"{i + 1}. Username: [{username}] | Email: [{email}]")
            print()


if __name__ == "__main__":
    check_users()
