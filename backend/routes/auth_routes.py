"""Endpoint de login del panel."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from auth import LoginRequest, TokenResponse, create_access_token, verify_credentials

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest) -> TokenResponse:
    if not verify_credentials(payload.username, payload.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas"
        )
    return create_access_token(payload.username)
