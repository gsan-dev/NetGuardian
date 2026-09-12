"""Envío de notificaciones de alertas a Telegram y/o Discord.

Reglas configurables desde el .env (no hardcodeadas):
- NOTIFY_MIN_SEVERITY: severidad mínima para notificar.
- NOTIFY_COOLDOWN_SECONDS: tiempo mínimo entre notificaciones repetidas
  de la misma IP origen, para no saturar el chat/canal con la misma
  anomalía persistente.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import requests

from common.severity import meets_threshold

logger = logging.getLogger("netguardian.notifier")


class Notifier:
    def __init__(
        self,
        telegram_bot_token: str = "",
        telegram_chat_id: str = "",
        discord_webhook_url: str = "",
        min_severity: str = "medium",
        cooldown_seconds: int = 300,
    ):
        self.telegram_bot_token = telegram_bot_token
        self.telegram_chat_id = telegram_chat_id
        self.discord_webhook_url = discord_webhook_url
        self.min_severity = min_severity
        self.cooldown_seconds = cooldown_seconds
        self._last_notified: dict[str, float] = {}

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_chat_id)

    @property
    def discord_enabled(self) -> bool:
        return bool(self.discord_webhook_url)

    def _in_cooldown(self, key: str, now: float) -> bool:
        last = self._last_notified.get(key)
        return last is not None and (now - last) < self.cooldown_seconds

    @staticmethod
    def _format_message(alert: dict[str, Any]) -> str:
        source_ip = alert.get("source_ip") or "desconocida"
        port = alert.get("port")
        port_str = f":{port}" if port else ""
        return (
            f"NetGuardian [{alert['severity'].upper()}]\n"
            f"IP origen: {source_ip}{port_str}\n"
            f"Motivo: {alert['reason']}"
        )

    def _send_telegram(self, text: str) -> bool:
        url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
        try:
            response = requests.post(
                url, json={"chat_id": self.telegram_chat_id, "text": text}, timeout=10
            )
            response.raise_for_status()
            return True
        except requests.RequestException:
            logger.exception("Error enviando notificación a Telegram")
            return False

    def _send_discord(self, text: str) -> bool:
        try:
            response = requests.post(
                self.discord_webhook_url, json={"content": text}, timeout=10
            )
            response.raise_for_status()
            return True
        except requests.RequestException:
            logger.exception("Error enviando notificación a Discord")
            return False

    def notify(self, alert: dict[str, Any], now: float | None = None) -> bool:
        """Envía la alerta si supera el umbral de severidad y no está en cooldown.

        Devuelve True si se envió por al menos un canal habilitado.
        """
        now = now if now is not None else time.time()

        if not meets_threshold(alert["severity"], self.min_severity):
            return False

        cooldown_key = alert.get("source_ip") or "global"
        if self._in_cooldown(cooldown_key, now):
            logger.debug("Alerta de %s en cooldown, no se notifica de nuevo", cooldown_key)
            return False

        if not self.telegram_enabled and not self.discord_enabled:
            logger.debug("Ningún canal de notificación configurado")
            return False

        text = self._format_message(alert)
        sent = False
        if self.telegram_enabled:
            sent = self._send_telegram(text) or sent
        if self.discord_enabled:
            sent = self._send_discord(text) or sent

        if sent:
            self._last_notified[cooldown_key] = now
        return sent
