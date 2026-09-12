"""Carga centralizada de configuración desde variables de entorno / .env.

Tanto el sensor como el backend importan `settings` desde aquí para no
duplicar lógica de parseo ni arriesgarse a que ambos procesos lean la
configuración de forma distinta.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(REPO_ROOT / ".env")


def _bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    val = os.getenv(name)
    if val is None or val == "":
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    val = os.getenv(name)
    if val is None or val == "":
        return default
    try:
        return float(val)
    except ValueError:
        return default


def _list(name: str, default: list[str] | None = None) -> list[str]:
    val = os.getenv(name)
    if not val:
        return default or []
    return [item.strip() for item in val.split(",") if item.strip()]


@dataclass
class Settings:
    # Sensor
    network_interface: str = os.getenv("NETWORK_INTERFACE", "eth0")
    window_seconds: int = field(default_factory=lambda: _int("WINDOW_SECONDS", 30))
    discovery_interval_seconds: int = field(
        default_factory=lambda: _int("DISCOVERY_INTERVAL_SECONDS", 15)
    )

    # Base de datos
    db_backend: str = os.getenv("DB_BACKEND", "sqlite")
    db_path: str = os.getenv("DB_PATH", "./data/netguardian.db")
    influxdb_url: str = os.getenv("INFLUXDB_URL", "http://localhost:8086")
    influxdb_token: str = os.getenv("INFLUXDB_TOKEN", "")
    influxdb_org: str = os.getenv("INFLUXDB_ORG", "netguardian")
    influxdb_bucket: str = os.getenv("INFLUXDB_BUCKET", "netguardian")

    # Modelo ML
    model_mode: str = os.getenv("MODEL_MODE", "global")  # "global" | "per_ip"
    model_contamination: float = field(
        default_factory=lambda: _float("MODEL_CONTAMINATION", 0.05)
    )
    model_min_samples_per_ip: int = field(
        default_factory=lambda: _int("MODEL_MIN_SAMPLES_PER_IP", 50)
    )

    # Notificaciones
    telegram_bot_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    telegram_chat_id: str = os.getenv("TELEGRAM_CHAT_ID", "")
    discord_webhook_url: str = os.getenv("DISCORD_WEBHOOK_URL", "")
    notify_min_severity: str = os.getenv("NOTIFY_MIN_SEVERITY", "medium")
    notify_cooldown_seconds: int = field(
        default_factory=lambda: _int("NOTIFY_COOLDOWN_SECONDS", 300)
    )

    # Bloqueo automático
    auto_block_enabled: bool = field(
        default_factory=lambda: _bool("AUTO_BLOCK_ENABLED", False)
    )
    auto_block_min_severity: str = os.getenv("AUTO_BLOCK_MIN_SEVERITY", "high")
    auto_block_whitelist: list[str] = field(
        default_factory=lambda: _list(
            "AUTO_BLOCK_WHITELIST", ["127.0.0.1", "::1"]
        )
    )
    auto_block_duration_seconds: int = field(
        default_factory=lambda: _int("AUTO_BLOCK_DURATION_SECONDS", 3600)
    )

    # Backend / API
    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    api_port: int = field(default_factory=lambda: _int("API_PORT", 8000))
    cors_origins: list[str] = field(
        default_factory=lambda: _list("CORS_ORIGINS", ["http://localhost:5173"])
    )

    # Autenticación
    auth_enabled: bool = field(default_factory=lambda: _bool("AUTH_ENABLED", True))
    auth_secret_key: str = os.getenv("AUTH_SECRET_KEY", "insecure-dev-secret")
    auth_token_expire_minutes: int = field(
        default_factory=lambda: _int("AUTH_TOKEN_EXPIRE_MINUTES", 720)
    )
    admin_username: str = os.getenv("ADMIN_USERNAME", "admin")
    admin_password_hash: str = os.getenv("ADMIN_PASSWORD_HASH", "")

    # Informes
    weekly_report_enabled: bool = field(
        default_factory=lambda: _bool("WEEKLY_REPORT_ENABLED", True)
    )
    reports_dir: str = os.getenv("REPORTS_DIR", "./reports")

    @property
    def db_path_absolute(self) -> Path:
        path = Path(self.db_path)
        if not path.is_absolute():
            path = REPO_ROOT / path
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def reports_dir_absolute(self) -> Path:
        path = Path(self.reports_dir)
        if not path.is_absolute():
            path = REPO_ROOT / path
        path.mkdir(parents=True, exist_ok=True)
        return path


settings = Settings()
