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
        stale_clients: list[WebSocket] = []
        for client in tuple(self.connected_clients):
            try:
                await client.send_json(details)
            except Exception:
                stale_clients.append(client)

        for client in stale_clients:
            self.connected_clients.discard(client)
