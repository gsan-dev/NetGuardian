"""Autenticación del panel (mejora futura del README ya integrada).

Login simple de usuario/contraseña (un único admin configurado por
variables de entorno) que emite un JWT. Se puede desactivar por
completo con AUTH_ENABLED=false para desarrollo local.
"""
from __future__ import annotations

import time
from typing import Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from common.config import settings

ALGORITHM = "HS256"
bearer_scheme = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


def verify_credentials(username: str, password: str) -> bool:
    if username != settings.admin_username:
        return False
    if not settings.admin_password_hash:
        # Sin hash configurado no se puede autenticar a nadie: falla seguro
        # en vez de aceptar cualquier contraseña.
        return False
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"), settings.admin_password_hash.encode("utf-8")
        )
    except ValueError:
        return False


def create_access_token(username: str) -> TokenResponse:
    expire_seconds = settings.auth_token_expire_minutes * 60
    now = int(time.time())
    payload = {"sub": username, "iat": now, "exp": now + expire_seconds}
    token = jwt.encode(payload, settings.auth_secret_key, algorithm=ALGORITHM)
    return TokenResponse(access_token=token, expires_in=expire_seconds)


def decode_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, settings.auth_secret_key, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> str:
    """Dependency de FastAPI: exige un JWT válido en el header Authorization
    cuando AUTH_ENABLED=true; si está desactivado, deja pasar sin comprobar.
    """
    if not settings.auth_enabled:
        return "anonymous"

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No autenticado"
        )

    username = decode_token(credentials.credentials)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido o expirado"
        )

    return username
