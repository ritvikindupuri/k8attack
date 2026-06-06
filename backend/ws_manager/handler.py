import asyncio
import json
import time
from typing import Set, Dict, Any
from fastapi import WebSocket, WebSocketDisconnect


class WebSocketManager:
    def __init__(self):
        self.connections: Set[WebSocket] = set()
        self.connection_metadata: Dict[WebSocket, Dict] = {}

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.connections.add(websocket)
        self.connection_metadata[websocket] = {
            "connected_at": time.time(),
            "ip": websocket.client.host if websocket.client else "unknown",
        }
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to K8s Attack Platform",
            "client_info": self.connection_metadata[websocket],
        })

    async def disconnect(self, websocket: WebSocket):
        self.connections.discard(websocket)
        self.connection_metadata.pop(websocket, None)

    async def broadcast(self, message: Dict[str, Any]):
        dead_connections = set()
        for ws in self.connections:
            try:
                await ws.send_json(message)
            except WebSocketDisconnect:
                dead_connections.add(ws)
            except Exception:
                dead_connections.add(ws)

        for ws in dead_connections:
            self.connections.discard(ws)
            self.connection_metadata.pop(ws, None)

    async def send_to(self, websocket: WebSocket, message: Dict[str, Any]):
        try:
            await websocket.send_json(message)
        except WebSocketDisconnect:
            await self.disconnect(websocket)

    @property
    def connection_count(self):
        return len(self.connections)
