"""NetGuardian backend: FastAPI + WebSocket.

Expone servicios activos, alertas y ventanas de tráfico vía REST, y
retransmite las novedades en tiempo real vía WebSocket sondeando la
base de datos (el sensor escribe, el backend solo lee — así ambos
procesos quedan desacoplados y pueden desplegarse por separado).
"""
from __future__ import annotations

import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from common.config import settings
from common.db import get_repository
from routes import alerts, auth_routes, reports_routes, services, traffic, ws
from ws_manager import manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("netguardian.backend")

POLL_INTERVAL_SECONDS = 2


async def _poll_and_broadcast_loop() -> None:
    """Sondea la BD y reenvía por WebSocket lo nuevo desde la última vuelta."""
    repo = get_repository()
    last_window_id = 0
    last_alert_id = 0

    while True:
        try:
            new_windows = repo.list_traffic_windows_after(last_window_id)
            for window in new_windows:
                last_window_id = max(last_window_id, window["id"])
                await manager.broadcast({"type": "traffic_window", "data": window})

            new_alerts = repo.list_alerts_after(last_alert_id)
            for alert in new_alerts:
                last_alert_id = max(last_alert_id, alert["id"])
                await manager.broadcast({"type": "alert", "data": alert})
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Error en el bucle de sondeo/broadcast")

        await asyncio.sleep(POLL_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_repository()  # crea el esquema si no existe todavía
    task = asyncio.create_task(_poll_and_broadcast_loop())
    logger.info("NetGuardian backend arrancado")
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="NetGuardian API",
    description=(
        "IDS con detección de anomalías para homelab. Expone servicios "
        "activos, alertas de anomalías y streaming en tiempo real por "
        "WebSocket. Documentación interactiva en /docs."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_routes.router)
app.include_router(services.router)
app.include_router(alerts.router)
app.include_router(traffic.router)
app.include_router(reports_routes.router)
app.include_router(ws.router)


@app.get("/api/health", tags=["health"])
async def health() -> dict:
    return {"status": "ok", "websocket_clients": manager.active_connections}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host=settings.api_host, port=settings.api_port, reload=True)
