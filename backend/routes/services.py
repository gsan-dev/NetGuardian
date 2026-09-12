"""Endpoints REST de servicios activos detectados por el sensor."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from auth import get_current_user
from common.db import get_repository

router = APIRouter(prefix="/api/services", tags=["services"])


@router.get("")
async def list_services(active_only: bool = True, user: str = Depends(get_current_user)):
    repo = get_repository()
    return repo.list_services(active_only=active_only)
