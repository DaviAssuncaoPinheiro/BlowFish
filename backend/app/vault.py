import os
from cryptography.fernet import Fernet

class Vault:
    def __init__(self):
        self._master_key = os.environ.get("VAULT_SECRET")
        if not self._master_key:
            print("[VAULT] Chave mestra não encontrada. Gerando uma nova.")
            self._master_key = Fernet.generate_key().decode()
        
        self._fernet = Fernet(self._master_key.encode())

    def encrypt(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        return self._fernet.decrypt(token)

vault = Vault()
