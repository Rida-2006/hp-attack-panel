import asyncio
from fastapi import WebSocket


class WebSocketManager:
    def __init__(self) -> None:
        self.connected_clients: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.connected_clients.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.connected_clients.discard(websocket)

    async def broadcast(self, details: dict[str, object]) -> None:
        clients = tuple(self.connected_clients)
        results = await asyncio.gather(*(asyncio.wait_for(client.send_json(details), timeout=1) for client in clients), return_exceptions=True)
        for client, result in zip(clients, results):
            if isinstance(result, BaseException):
                self.connected_clients.discard(client)
