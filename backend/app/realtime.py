from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import threading
import json
from typing import Dict, Set, List, Optional

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.connections: Dict[str, Set[WebSocket]] = {}
        self.lock = threading.Lock()

    async def connect(self, username: str, websocket: WebSocket):
        await websocket.accept()
        with self.lock:
            if username not in self.connections:
                self.connections[username] = set()
            self.connections[username].add(websocket)
        print(f"[DEBUG] WS connect: {username}")

    def disconnect(self, username: str, websocket: Optional[WebSocket] = None):
        with self.lock:
            if username in self.connections:
                if websocket:
                    self.connections[username].discard(websocket)
                if not self.connections[username]:
                    del self.connections[username]
        print(f"[DEBUG] WS disconnect: {username}")

    async def send_to_user(self, username: str, payload: dict):
        with self.lock:
            sockets = list(self.connections.get(username, []))
        dead = []
        for ws in sockets:
            try:
                await ws.send_text(json.dumps(payload))
            except Exception:
                dead.append(ws)
        if dead:
            with self.lock:
                for d in dead:
                    self.connections.get(username, set()).discard(d)

    async def broadcast(self, usernames: List[str], payload: dict):
        for u in set(usernames):
            await self.send_to_user(u, payload)

manager = ConnectionManager()

@router.websocket("/ws/{username}")
async def ws_user_endpoint_path(websocket: WebSocket, username: str):
    await manager.connect(username, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(username, websocket)
    except Exception:
        manager.disconnect(username, websocket)

@router.websocket("/ws")
async def ws_user_endpoint_query(websocket: WebSocket):
    # suporta ?username=xxx para compatibilidade com clientes antigos
    params = websocket.query_params
    username = params.get("username")
    if not username:
        # fecha com código 1008 (policy violation)
        await websocket.close(code=1008)
        print("[DEBUG] WS rejected: missing username query param")
        return
    await manager.connect(username, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(username, websocket)
    except Exception:
        manager.disconnect(username, websocket)

# helpers compatíveis
async def push_to_user(username: str, payload: dict):
    await manager.send_to_user(username, payload)

async def push_to_many(usernames: List[str], payload: dict):
    await manager.broadcast(usernames, payload)
