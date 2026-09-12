"""Endpoints REST de ventanas de tráfico (para la carga inicial del gráfico,
antes de que el WebSocket empiece a empujar datos en vivo)."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from auth import get_current_user
from common.db import get_repository

router = APIRouter(prefix="/api/traffic", tags=["traffic"])


@router.get("/windows")
async def list_windows(limit: int = 100, user: str = Depends(get_current_user)):
    repo = get_repository()
    return repo.list_traffic_windows(limit=limit)


@router.get("/windows/{window_id}/ips")
async def list_window_ips(window_id: int, user: str = Depends(get_current_user)):
    repo = get_repository()
    return repo.list_ip_window_stats(window_id)
