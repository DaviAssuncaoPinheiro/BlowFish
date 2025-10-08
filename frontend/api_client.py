# api_client.py
import os
import requests

BASE = os.getenv("CHAT_API_BASE", "http://127.0.0.1:8000")

def _auth_headers(token: str):
    return {"Authorization": f"Bearer {token}"} if token else {}

def register(username: str, password: str):
    r = requests.post(f"{BASE}/auth/register", json={"username": username, "password": password})
    r.raise_for_status()
    print("frontend: register ok")
    return r.json()["token"]

def login(username: str, password: str):
    r = requests.post(f"{BASE}/auth/login", json={"username": username, "password": password})
    r.raise_for_status()
    print("frontend: login ok")
    return r.json()["token"]

def list_users(token: str):
    r = requests.get(f"{BASE}/users", headers=_auth_headers(token))
    r.raise_for_status()
    return r.json()

def send_message(token: str, to_username: str, message: str):
    r = requests.post(f"{BASE}/messages/send", headers=_auth_headers(token), json={"to_username": to_username, "message": message})
    r.raise_for_status()
    print("frontend: message sent")
    return r.json()

def history(token: str, peer: str):
    r = requests.get(f"{BASE}/messages/history", headers=_auth_headers(token), params={"peer": peer})
    r.raise_for_status()
    return r.json()
