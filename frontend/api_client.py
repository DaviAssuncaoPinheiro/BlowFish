# frontend/api_client.py
import requests

BASE = "http://127.0.0.1:8000"

def _auth_headers(token: str):
    return {"Authorization": f"Bearer {token}"} if token else {}

def register(username: str, password: str, rsa_pubkey_pem: str):
    r = requests.post(f"{BASE}/auth/register", json={
        "username": username, "password": password, "rsa_pubkey_pem": rsa_pubkey_pem
    })
    r.raise_for_status(); return r.json()["token"]

def login(username: str, password: str):
    r = requests.post(f"{BASE}/auth/login", json={"username": username, "password": password})
    r.raise_for_status(); return r.json()["token"]

def list_users():
    r = requests.get(f"{BASE}/users"); r.raise_for_status()
    return r.json()

def create_conversation(token: str, member_ids: list[int], name: str|None=None):
    r = requests.post(f"{BASE}/conversations/", headers=_auth_headers(token), json={
        "name": name, "member_ids": member_ids
    })
    r.raise_for_status(); return r.json()

def session_info(token: str, conversation_id: int):
    r = requests.get(f"{BASE}/conversations/{conversation_id}/session_info", headers=_auth_headers(token))
    r.raise_for_status(); return r.json()

def send_message(token: str, conversation_id: int, iv: str, ciphertext: str, hmac_: str, key_version: int):
    r = requests.post(f"{BASE}/conversations/send", headers=_auth_headers(token), json={
        "conversation_id": conversation_id,
        "iv": iv, "ciphertext": ciphertext, "hmac": hmac_, "key_version": key_version
    })
    r.raise_for_status(); return r.json()

def list_messages(token: str, conversation_id: int, limit: int = 50):
    r = requests.get(f"{BASE}/conversations/{conversation_id}/messages", headers=_auth_headers(token), params={"limit": limit})
    r.raise_for_status(); return r.json()

def rekey_remove(token: str, conversation_id: int, removed_user_id: int):
    r = requests.post(f"{BASE}/conversations/{conversation_id}/rekey", headers=_auth_headers(token), params={"removed_user_id": removed_user_id})
    r.raise_for_status(); return r.json()
