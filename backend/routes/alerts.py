"""Endpoints REST de alertas de anomalías e IPs bloqueadas."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from auth import get_current_user
from common.db import get_repository

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("")
async def list_alerts(limit: int = 100, user: str = Depends(get_current_user)):
    repo = get_repository()
    return repo.list_alerts(limit=limit)


@router.get("/blocked-ips")
async def list_blocked_ips(user: str = Depends(get_current_user)):
    """IPs bloqueadas automáticamente (mejora futura: auto-bloqueo vía iptables)."""
    repo = get_repository()
    return repo.list_active_blocked_ips()
