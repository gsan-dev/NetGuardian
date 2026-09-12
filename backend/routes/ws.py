"""Endpoint WebSocket: streaming en tiempo real de ventanas de tráfico y alertas."""
from __future__ import annotations

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from auth import decode_token
from common.config import settings
from ws_manager import manager

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str | None = Query(default=None)):
    if settings.auth_enabled:
        username = decode_token(token) if token else None
        if username is None:
            await websocket.close(code=4401)
            return

    await manager.connect(websocket)
    try:
        while True:
            # No esperamos mensajes del cliente; solo mantenemos la conexión
            # viva y detectamos la desconexión.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
