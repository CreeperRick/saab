"""
Tracks which user_id is connected on which live WebSocket, so we can push
messages instantly when both parties are online. Offline messages just sit
in the DB (still only ciphertext) until the recipient reconnects and pulls
their backlog.
"""

from fastapi import WebSocket
from typing import Dict


class ConnectionManager:
    def __init__(self):
        self.active: Dict[int, WebSocket] = {}

    async def connect(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        self.active[user_id] = websocket

    def disconnect(self, user_id: int):
        self.active.pop(user_id, None)

    def is_online(self, user_id: int) -> bool:
        return user_id in self.active

    async def send_to_user(self, user_id: int, payload: dict) -> bool:
        ws = self.active.get(user_id)
        if ws is None:
            return False
        try:
            await ws.send_json(payload)
            return True
        except Exception:
            self.disconnect(user_id)
            return False


manager = ConnectionManager()
