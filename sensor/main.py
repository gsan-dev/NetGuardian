"""Orquestación del sensor de NetGuardian.

Bucle principal:
1. Cada DISCOVERY_INTERVAL_SECONDS refresca la lista de servicios activos
   (psutil + Docker) y expira los bloqueos de IP ya cumplidos.
2. TrafficCapture entrega una ventana de paquetes cada WINDOW_SECONDS:
   - se calculan features globales y por IP
   - el modelo global se entrena en cuanto hay muestras suficientes, y
     se reentrena periódicamente para adaptarse a la red real
   - se puntúa la ventana (y cada IP si MODEL_MODE=per_ip); las
     anomalías generan una alerta, se notifican y, si
     AUTO_BLOCK_ENABLED, se bloquea la IP de origen
   - todo se persiste en la base de datos configurada
"""
from __future__ import annotations

import logging
import signal
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from blocker import IpBlocker
from capture import PacketRecord, TrafficCapture
from common.config import settings
from common.db import get_repository
from discovery import discover_services
from features import IpWindowFeatures, extract_ip_window_features, extract_window_features
from model import DEFAULT_MODEL_DIR, MIN_TRAINING_SAMPLES, AnomalyModel, PerIpModelRegistry
from notifier import Notifier

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger("netguardian.sensor")

MAX_TRAINING_BUFFER = 2000
RETRAIN_EVERY_N_WINDOWS = 200


class Sensor:
    def __init__(self) -> None:
        self.repo = get_repository()
        self.global_model = AnomalyModel(contamination=settings.model_contamination)
        self.per_ip_registry = PerIpModelRegistry(
            contamination=settings.model_contamination,
            min_samples=settings.model_min_samples_per_ip,
            global_model=self.global_model,
        )
        self.notifier = Notifier(
            telegram_bot_token=settings.telegram_bot_token,
            telegram_chat_id=settings.telegram_chat_id,
            discord_webhook_url=settings.discord_webhook_url,
            min_severity=settings.notify_min_severity,
            cooldown_seconds=settings.notify_cooldown_seconds,
        )
        self.blocker = IpBlocker(
            enabled=settings.auto_block_enabled,
            min_severity=settings.auto_block_min_severity,
            whitelist=settings.auto_block_whitelist,
            duration_seconds=settings.auto_block_duration_seconds,
        )
        self._training_buffer: list[list[float]] = []
        self._windows_since_retrain = 0
        self._stop = False

        self._load_persisted_models()

    # --- Modelos persistidos ---

    def _load_persisted_models(self) -> None:
        global_path = DEFAULT_MODEL_DIR / "global_model.joblib"
        if global_path.exists():
            try:
                self.global_model = AnomalyModel.load(global_path)
                self.per_ip_registry.global_model = self.global_model
                logger.info("Modelo global cargado desde disco (%s)", global_path)
            except Exception:
                logger.exception("No se pudo cargar el modelo global persistido")
        if settings.model_mode == "per_ip":
            self.per_ip_registry.load_all(DEFAULT_MODEL_DIR / "per_ip")

    def _persist_models(self) -> None:
        if self.global_model.is_trained:
            self.global_model.save(DEFAULT_MODEL_DIR / "global_model.joblib")
        if settings.model_mode == "per_ip":
            self.per_ip_registry.save_all(DEFAULT_MODEL_DIR / "per_ip")

    # --- Descubrimiento de servicios ---

    def run_discovery_once(self) -> None:
        services = discover_services()
        seen_keys: set[tuple] = set()
        for service in services:
            self.repo.upsert_service(service.to_dict())
            seen_keys.add(
                (service.port, service.protocol, service.process_name or None, service.container_id or None)
            )
        self.repo.mark_stale_services_inactive(seen_keys)
        logger.info("Descubrimiento: %d servicios activos", len(services))

    # --- Modelo ML ---

    def _maybe_train_global_model(self) -> None:
        if len(self._training_buffer) < MIN_TRAINING_SAMPLES:
            return
        if not self.global_model.is_trained or self._windows_since_retrain >= RETRAIN_EVERY_N_WINDOWS:
            try:
                self.global_model.train(self._training_buffer[-MAX_TRAINING_BUFFER:])
                self._windows_since_retrain = 0
                logger.info(
                    "Modelo global (re)entrenado con %d ventanas de histórico",
                    len(self._training_buffer),
                )
            except ValueError:
                pass

    # --- Procesado de cada ventana de tráfico ---

    def on_window(self, window_start: float, window_end: float, packets: list[PacketRecord]) -> None:
        window_features = extract_window_features(window_start, window_end, packets)
        vector = window_features.to_vector()

        self._training_buffer.append(vector)
        if len(self._training_buffer) > MAX_TRAINING_BUFFER:
            self._training_buffer.pop(0)
        self._windows_since_retrain += 1
        self._maybe_train_global_model()

        window_row: dict[str, Any] = window_features.__dict__.copy()
        if self.global_model.is_trained:
            result = self.global_model.score(vector)
            window_row.update(
                is_anomaly=result.is_anomaly, severity=result.severity, anomaly_score=result.score
            )
        window_id = self.repo.insert_traffic_window(window_row)

        ip_rows = []
        for ip_feat in extract_ip_window_features(window_start, window_end, packets):
            ip_rows.append(self._score_ip_window(ip_feat, window_id))

        self.repo.insert_ip_window_stats(window_id, ip_rows)

        if settings.model_mode == "per_ip":
            self.per_ip_registry.train_all_ready()

    def _score_ip_window(self, ip_feat: IpWindowFeatures, window_id: int) -> dict[str, Any]:
        vector = ip_feat.to_vector()
        row: dict[str, Any] = ip_feat.__dict__.copy()

        if settings.model_mode == "per_ip":
            self.per_ip_registry.observe(ip_feat.src_ip, vector)
            if not self.global_model.is_trained:
                return row
            result = self.per_ip_registry.score(ip_feat.src_ip, vector)
        elif self.global_model.is_trained:
            result = self.global_model.score(vector)
        else:
            return row

        row.update(is_anomaly=result.is_anomaly, severity=result.severity, anomaly_score=result.score)
        if result.is_anomaly:
            self._raise_alert(ip_feat, result.severity, window_id)
        return row

    def _raise_alert(self, ip_feat: IpWindowFeatures, severity: str, window_id: int) -> None:
        reason = (
            f"Tráfico anómalo desde {ip_feat.src_ip}: {ip_feat.num_connections} conexiones, "
            f"{ip_feat.num_unique_ports} puertos únicos, {ip_feat.total_bytes} bytes en la ventana"
        )
        alert_id = self.repo.insert_alert(
            {
                "severity": severity,
                "source_ip": ip_feat.src_ip,
                "port": None,
                "reason": reason,
                "window_id": window_id,
            }
        )

        alert = {"id": alert_id, "severity": severity, "source_ip": ip_feat.src_ip, "reason": reason}
        if self.notifier.notify(alert):
            self.repo.mark_alert_notified(alert_id)

        if self.blocker.should_block(ip_feat.src_ip, severity):
            if self.blocker.block(ip_feat.src_ip, reason=reason):
                self.repo.insert_blocked_ip(
                    {
                        "ip": ip_feat.src_ip,
                        "reason": reason,
                        "expires_at": self.blocker.expires_at(),
                    }
                )
                self.repo.mark_alert_blocked(alert_id)

    def expire_blocks_once(self) -> None:
        for ip in self.repo.expire_blocked_ips():
            self.blocker.unblock(ip)
            logger.info("Bloqueo de %s expirado, IP desbloqueada", ip)

    # --- Bucle principal ---

    def run(self) -> None:
        logger.info(
            "Iniciando NetGuardian sensor (interfaz=%s, ventana=%ss, modo modelo=%s)",
            settings.network_interface,
            settings.window_seconds,
            settings.model_mode,
        )
        capture = TrafficCapture(
            interface=settings.network_interface,
            window_seconds=settings.window_seconds,
            on_window=self.on_window,
        )
        capture.start()

        def _handle_signal(signum, frame) -> None:
            logger.info("Señal %s recibida, deteniendo sensor...", signum)
            self._stop = True

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        last_discovery = 0.0
        try:
            while not self._stop:
                now = time.time()
                if now - last_discovery >= settings.discovery_interval_seconds:
                    self.run_discovery_once()
                    self.expire_blocks_once()
                    last_discovery = now
                time.sleep(1)
        finally:
            capture.stop()
            self._persist_models()
            logger.info("Sensor detenido")


def main() -> None:
    Sensor().run()


if __name__ == "__main__":
    main()
