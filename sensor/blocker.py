"""Bloqueo automático de IPs sospechosas vía iptables.

Mejora futura del README ya integrada, pero deshabilitada por defecto
(AUTO_BLOCK_ENABLED=false): bloquear tráfico automáticamente es una
acción de riesgo — un falso positivo del modelo puede cortarte el
acceso a tu propia red. Salvaguardas aplicadas:

- Solo actúa si AUTO_BLOCK_ENABLED=true.
- Nunca bloquea una IP de la whitelist (AUTO_BLOCK_WHITELIST) ni
  direcciones loopback/link-local/multicast, pase lo que pase.
- El bloqueo expira solo (AUTO_BLOCK_DURATION_SECONDS), no es
  permanente sin revisión humana.
- Los comandos de iptables se ejecutan vía subprocess con un runner
  inyectable (para tests) y fallan de forma controlada si no existe
  iptables (p. ej. en Windows), sin tirar el sensor abajo.
"""
from __future__ import annotations

import ipaddress
import logging
import subprocess
import time
from typing import Callable

from common.severity import meets_threshold

logger = logging.getLogger("netguardian.blocker")

Runner = Callable[..., subprocess.CompletedProcess]


class IpBlocker:
    def __init__(
        self,
        enabled: bool,
        min_severity: str,
        whitelist: list[str],
        duration_seconds: int,
        runner: Runner = subprocess.run,
    ):
        self.enabled = enabled
        self.min_severity = min_severity
        self.whitelist = set(whitelist)
        self.duration_seconds = duration_seconds
        self._runner = runner

    def is_whitelisted(self, ip: str) -> bool:
        if ip in self.whitelist:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified

    def should_block(self, ip: str | None, severity: str) -> bool:
        if not self.enabled or not ip:
            return False
        if self.is_whitelisted(ip):
            logger.debug("IP %s está en whitelist, no se bloquea", ip)
            return False
        return meets_threshold(severity, self.min_severity)

    def block(self, ip: str, reason: str) -> bool:
        """Ejecuta `iptables -I INPUT -s <ip> -j DROP`. Devuelve True si tuvo éxito."""
        try:
            result = self._runner(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (FileNotFoundError, OSError) as exc:
            logger.warning(
                "No se pudo ejecutar iptables (¿sistema sin iptables o sin permisos root?): %s",
                exc,
            )
            return False

        if result.returncode != 0:
            logger.warning("iptables devolvió error bloqueando %s: %s", ip, result.stderr)
            return False

        logger.warning("IP %s bloqueada por iptables (motivo: %s)", ip, reason)
        return True

    def unblock(self, ip: str) -> bool:
        """Ejecuta `iptables -D INPUT -s <ip> -j DROP` para retirar el bloqueo."""
        try:
            result = self._runner(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (FileNotFoundError, OSError) as exc:
            logger.warning("No se pudo ejecutar iptables para desbloquear %s: %s", ip, exc)
            return False
        return result.returncode == 0

    def expires_at(self, now: float | None = None) -> float:
        now = now if now is not None else time.time()
        return now + self.duration_seconds
