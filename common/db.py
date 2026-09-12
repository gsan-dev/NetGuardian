"""Capa de acceso a datos de NetGuardian.

Define una interfaz abstracta (`Repository`) para que sensor y backend
no dependan del motor de base de datos concreto. Hoy solo hay una
implementación real (`SQLiteRepository`), pero la interfaz ya está lista
para la mejora futura del README: migrar a InfluxDB para análisis
histórico de series temporales sin tocar el resto del código
(`InfluxDBRepository` está aquí como stub explícito).

Se usa sqlite3 puro (sin ORM) para no añadir dependencias pesadas: cada
operación abre y cierra su propia conexión de corta vida, lo que es
seguro para acceso concurrente desde varios hilos/procesos (sensor +
backend) en el volumen de datos de un homelab.
"""
from __future__ import annotations

import sqlite3
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    status TEXT NOT NULL,
    pid INTEGER,
    process_name TEXT,
    is_docker INTEGER NOT NULL DEFAULT 0,
    container_id TEXT,
    container_name TEXT,
    container_image TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    UNIQUE(port, protocol, process_name, container_id)
);

CREATE TABLE IF NOT EXISTS traffic_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start REAL NOT NULL,
    window_end REAL NOT NULL,
    num_packets INTEGER NOT NULL,
    num_connections INTEGER NOT NULL,
    num_unique_src_ips INTEGER NOT NULL,
    num_unique_dst_ips INTEGER NOT NULL,
    num_unique_ports INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL,
    avg_packet_size REAL NOT NULL,
    syn_count INTEGER NOT NULL,
    tcp_ratio REAL NOT NULL,
    udp_ratio REAL NOT NULL,
    icmp_ratio REAL NOT NULL,
    anomaly_score REAL,
    is_anomaly INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'none'
);
CREATE INDEX IF NOT EXISTS idx_traffic_windows_start ON traffic_windows(window_start);

CREATE TABLE IF NOT EXISTS ip_window_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_id INTEGER NOT NULL REFERENCES traffic_windows(id) ON DELETE CASCADE,
    src_ip TEXT NOT NULL,
    num_packets INTEGER NOT NULL,
    num_connections INTEGER NOT NULL,
    num_unique_dst_ips INTEGER NOT NULL,
    num_unique_ports INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL,
    syn_count INTEGER NOT NULL,
    anomaly_score REAL,
    is_anomaly INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'none'
);
CREATE INDEX IF NOT EXISTS idx_ip_window_stats_ip ON ip_window_stats(src_ip);
CREATE INDEX IF NOT EXISTS idx_ip_window_stats_window ON ip_window_stats(window_id);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    severity TEXT NOT NULL,
    source_ip TEXT,
    port INTEGER,
    reason TEXT NOT NULL,
    window_id INTEGER REFERENCES traffic_windows(id) ON DELETE SET NULL,
    notified INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    reason TEXT,
    blocked_at REAL NOT NULL,
    expires_at REAL,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip);
"""


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)


class Repository(ABC):
    """Interfaz de persistencia independiente del motor de base de datos."""

    @abstractmethod
    def init_schema(self) -> None: ...

    @abstractmethod
    def upsert_service(self, service: dict[str, Any]) -> int: ...

    @abstractmethod
    def mark_stale_services_inactive(self, seen_ports_keys: set[tuple]) -> None: ...

    @abstractmethod
    def list_services(self, active_only: bool = True) -> list[dict[str, Any]]: ...

    @abstractmethod
    def insert_traffic_window(self, window: dict[str, Any]) -> int: ...

    @abstractmethod
    def insert_ip_window_stats(self, window_id: int, stats: list[dict[str, Any]]) -> None: ...

    @abstractmethod
    def list_traffic_windows(self, limit: int = 100, since: float | None = None) -> list[dict[str, Any]]: ...

    @abstractmethod
    def list_traffic_windows_after(self, after_id: int, limit: int = 50) -> list[dict[str, Any]]: ...

    @abstractmethod
    def list_ip_window_stats(self, window_id: int) -> list[dict[str, Any]]: ...

    @abstractmethod
    def insert_alert(self, alert: dict[str, Any]) -> int: ...

    @abstractmethod
    def list_alerts(self, limit: int = 100, since: float | None = None) -> list[dict[str, Any]]: ...

    @abstractmethod
    def list_alerts_after(self, after_id: int, limit: int = 50) -> list[dict[str, Any]]: ...

    @abstractmethod
    def mark_alert_notified(self, alert_id: int) -> None: ...

    @abstractmethod
    def mark_alert_blocked(self, alert_id: int) -> None: ...

    @abstractmethod
    def insert_blocked_ip(self, blocked: dict[str, Any]) -> int: ...

    @abstractmethod
    def list_active_blocked_ips(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def expire_blocked_ips(self, now: float | None = None) -> list[str]: ...

    @abstractmethod
    def traffic_summary_since(self, since: float) -> dict[str, Any]: ...


class SQLiteRepository(Repository):
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # --- Servicios ---

    def upsert_service(self, service: dict[str, Any]) -> int:
        now = time.time()
        # NULL nunca es igual a NULL en una UNIQUE constraint de SQLite, así
        # que normalizamos process_name/container_id ausentes a '' para que
        # el ON CONFLICT deduplique correctamente.
        process_name = service.get("process_name") or ""
        container_id = service.get("container_id") or ""
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO services (
                    port, protocol, status, pid, process_name, is_docker,
                    container_id, container_name, container_image,
                    first_seen, last_seen, active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(port, protocol, process_name, container_id) DO UPDATE SET
                    status = excluded.status,
                    pid = excluded.pid,
                    is_docker = excluded.is_docker,
                    container_name = excluded.container_name,
                    container_image = excluded.container_image,
                    last_seen = excluded.last_seen,
                    active = 1
                """,
                (
                    service["port"],
                    service["protocol"],
                    service["status"],
                    service.get("pid"),
                    process_name,
                    int(service.get("is_docker", False)),
                    container_id,
                    service.get("container_name"),
                    service.get("container_image"),
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT id FROM services WHERE port=? AND protocol=? AND "
                "process_name=? AND container_id=?",
                (service["port"], service["protocol"], process_name, container_id),
            ).fetchone()
            return row["id"] if row else cur.lastrowid

    def mark_stale_services_inactive(self, seen_ports_keys: set[tuple]) -> None:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, port, protocol, process_name, container_id FROM services WHERE active = 1"
            ).fetchall()
            for row in rows:
                key = (
                    row["port"],
                    row["protocol"],
                    row["process_name"] or None,
                    row["container_id"] or None,
                )
                if key not in seen_ports_keys:
                    conn.execute("UPDATE services SET active = 0 WHERE id = ?", (row["id"],))

    def list_services(self, active_only: bool = True) -> list[dict[str, Any]]:
        query = "SELECT * FROM services"
        if active_only:
            query += " WHERE active = 1"
        query += " ORDER BY last_seen DESC"
        with self._connect() as conn:
            return [_row_to_dict(r) for r in conn.execute(query).fetchall()]

    # --- Tráfico ---

    def insert_traffic_window(self, window: dict[str, Any]) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO traffic_windows (
                    window_start, window_end, num_packets, num_connections,
                    num_unique_src_ips, num_unique_dst_ips, num_unique_ports,
                    total_bytes, avg_packet_size, syn_count, tcp_ratio,
                    udp_ratio, icmp_ratio, anomaly_score, is_anomaly, severity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    window["window_start"],
                    window["window_end"],
                    window["num_packets"],
                    window["num_connections"],
                    window["num_unique_src_ips"],
                    window["num_unique_dst_ips"],
                    window["num_unique_ports"],
                    window["total_bytes"],
                    window["avg_packet_size"],
                    window["syn_count"],
                    window["tcp_ratio"],
                    window["udp_ratio"],
                    window["icmp_ratio"],
                    window.get("anomaly_score"),
                    int(window.get("is_anomaly", False)),
                    window.get("severity", "none"),
                ),
            )
            return cur.lastrowid

    def insert_ip_window_stats(self, window_id: int, stats: list[dict[str, Any]]) -> None:
        if not stats:
            return
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO ip_window_stats (
                    window_id, src_ip, num_packets, num_connections,
                    num_unique_dst_ips, num_unique_ports, total_bytes,
                    syn_count, anomaly_score, is_anomaly, severity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        window_id,
                        s["src_ip"],
                        s["num_packets"],
                        s["num_connections"],
                        s["num_unique_dst_ips"],
                        s["num_unique_ports"],
                        s["total_bytes"],
                        s["syn_count"],
                        s.get("anomaly_score"),
                        int(s.get("is_anomaly", False)),
                        s.get("severity", "none"),
                    )
                    for s in stats
                ],
            )

    def list_traffic_windows(self, limit: int = 100, since: float | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM traffic_windows"
        params: list[Any] = []
        if since is not None:
            query += " WHERE window_start >= ?"
            params.append(since)
        query += " ORDER BY window_start DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = [_row_to_dict(r) for r in conn.execute(query, params).fetchall()]
        return list(reversed(rows))

    def list_traffic_windows_after(self, after_id: int, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM traffic_windows WHERE id > ? ORDER BY id ASC LIMIT ?",
                (after_id, limit),
            ).fetchall()
            return [_row_to_dict(r) for r in rows]

    def list_ip_window_stats(self, window_id: int) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM ip_window_stats WHERE window_id = ? ORDER BY total_bytes DESC",
                (window_id,),
            ).fetchall()
            return [_row_to_dict(r) for r in rows]

    # --- Alertas ---

    def insert_alert(self, alert: dict[str, Any]) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO alerts (created_at, severity, source_ip, port, reason, window_id, notified, blocked)
                VALUES (?, ?, ?, ?, ?, ?, 0, 0)
                """,
                (
                    alert.get("created_at", time.time()),
                    alert["severity"],
                    alert.get("source_ip"),
                    alert.get("port"),
                    alert["reason"],
                    alert.get("window_id"),
                ),
            )
            return cur.lastrowid

    def list_alerts(self, limit: int = 100, since: float | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM alerts"
        params: list[Any] = []
        if since is not None:
            query += " WHERE created_at >= ?"
            params.append(since)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            return [_row_to_dict(r) for r in conn.execute(query, params).fetchall()]

    def list_alerts_after(self, after_id: int, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE id > ? ORDER BY id ASC LIMIT ?",
                (after_id, limit),
            ).fetchall()
            return [_row_to_dict(r) for r in rows]

    def mark_alert_notified(self, alert_id: int) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE alerts SET notified = 1 WHERE id = ?", (alert_id,))

    def mark_alert_blocked(self, alert_id: int) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE alerts SET blocked = 1 WHERE id = ?", (alert_id,))

    # --- Bloqueo automático de IPs ---

    def insert_blocked_ip(self, blocked: dict[str, Any]) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO blocked_ips (ip, reason, blocked_at, expires_at, active)
                VALUES (?, ?, ?, ?, 1)
                """,
                (
                    blocked["ip"],
                    blocked.get("reason"),
                    blocked.get("blocked_at", time.time()),
                    blocked.get("expires_at"),
                ),
            )
            return cur.lastrowid

    def list_active_blocked_ips(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM blocked_ips WHERE active = 1 ORDER BY blocked_at DESC"
            ).fetchall()
            return [_row_to_dict(r) for r in rows]

    def expire_blocked_ips(self, now: float | None = None) -> list[str]:
        now = now if now is not None else time.time()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, ip FROM blocked_ips WHERE active = 1 AND expires_at IS NOT NULL AND expires_at <= ?",
                (now,),
            ).fetchall()
            ids = [r["id"] for r in rows]
            ips = [r["ip"] for r in rows]
            if ids:
                conn.executemany(
                    "UPDATE blocked_ips SET active = 0 WHERE id = ?", [(i,) for i in ids]
                )
            return ips

    # --- Informes ---

    def traffic_summary_since(self, since: float) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS num_windows,
                    COALESCE(SUM(num_packets), 0) AS total_packets,
                    COALESCE(SUM(total_bytes), 0) AS total_bytes,
                    COALESCE(SUM(is_anomaly), 0) AS num_anomalous_windows
                FROM traffic_windows WHERE window_start >= ?
                """,
                (since,),
            ).fetchone()
            alerts_row = conn.execute(
                "SELECT COUNT(*) AS num_alerts FROM alerts WHERE created_at >= ?",
                (since,),
            ).fetchone()
            top_ips = conn.execute(
                """
                SELECT src_ip, COUNT(*) AS anomaly_count
                FROM ip_window_stats
                WHERE is_anomaly = 1 AND window_id IN (
                    SELECT id FROM traffic_windows WHERE window_start >= ?
                )
                GROUP BY src_ip ORDER BY anomaly_count DESC LIMIT 10
                """,
                (since,),
            ).fetchall()
            return {
                **_row_to_dict(row),
                **_row_to_dict(alerts_row),
                "top_anomalous_ips": [_row_to_dict(r) for r in top_ips],
            }


class InfluxDBRepository(Repository):
    """Stub para la mejora futura: migrar de SQLite a InfluxDB.

    InfluxDB está pensado para series temporales de verdad (retención,
    downsampling, Grafana nativo). No se implementa todavía porque
    requiere levantar un servidor InfluxDB en el homelab; cuando se
    quiera dar el salto, esta clase debe implementar exactamente la
    misma interfaz `Repository` usando el cliente `influxdb-client`,
    de modo que sensor/backend no cambien ni una línea.
    """

    def __init__(self, url: str, token: str, org: str, bucket: str):
        self.url = url
        self.token = token
        self.org = org
        self.bucket = bucket

    def _not_implemented(self) -> None:
        raise NotImplementedError(
            "InfluxDBRepository todavía no está implementado. Configura "
            "DB_BACKEND=sqlite en .env mientras tanto (ver Mejoras futuras en el README)."
        )

    def init_schema(self) -> None:
        self._not_implemented()

    def upsert_service(self, service: dict[str, Any]) -> int:
        self._not_implemented()

    def mark_stale_services_inactive(self, seen_ports_keys: set[tuple]) -> None:
        self._not_implemented()

    def list_services(self, active_only: bool = True) -> list[dict[str, Any]]:
        self._not_implemented()

    def insert_traffic_window(self, window: dict[str, Any]) -> int:
        self._not_implemented()

    def insert_ip_window_stats(self, window_id: int, stats: list[dict[str, Any]]) -> None:
        self._not_implemented()

    def list_traffic_windows(self, limit: int = 100, since: float | None = None) -> list[dict[str, Any]]:
        self._not_implemented()

    def list_traffic_windows_after(self, after_id: int, limit: int = 50) -> list[dict[str, Any]]:
        self._not_implemented()

    def list_ip_window_stats(self, window_id: int) -> list[dict[str, Any]]:
        self._not_implemented()

    def insert_alert(self, alert: dict[str, Any]) -> int:
        self._not_implemented()

    def list_alerts(self, limit: int = 100, since: float | None = None) -> list[dict[str, Any]]:
        self._not_implemented()

    def list_alerts_after(self, after_id: int, limit: int = 50) -> list[dict[str, Any]]:
        self._not_implemented()

    def mark_alert_notified(self, alert_id: int) -> None:
        self._not_implemented()

    def mark_alert_blocked(self, alert_id: int) -> None:
        self._not_implemented()

    def insert_blocked_ip(self, blocked: dict[str, Any]) -> int:
        self._not_implemented()

    def list_active_blocked_ips(self) -> list[dict[str, Any]]:
        self._not_implemented()

    def expire_blocked_ips(self, now: float | None = None) -> list[str]:
        self._not_implemented()

    def traffic_summary_since(self, since: float) -> dict[str, Any]:
        self._not_implemented()


_repository_singleton: Repository | None = None


def get_repository() -> Repository:
    """Factoría: devuelve la implementación de Repository según DB_BACKEND."""
    global _repository_singleton
    if _repository_singleton is not None:
        return _repository_singleton

    from common.config import settings  # import diferido para evitar ciclos

    if settings.db_backend == "influxdb":
        repo: Repository = InfluxDBRepository(
            url=settings.influxdb_url,
            token=settings.influxdb_token,
            org=settings.influxdb_org,
            bucket=settings.influxdb_bucket,
        )
    else:
        repo = SQLiteRepository(settings.db_path_absolute)
        repo.init_schema()

    _repository_singleton = repo
    return repo
