"""Pruebas de la capa de persistencia SQLite."""
import time

import pytest

from common.db import InfluxDBRepository, SQLiteRepository


@pytest.fixture
def repo(tmp_path):
    r = SQLiteRepository(tmp_path / "test.db")
    r.init_schema()
    return r


def _service(port=8080, protocol="tcp", process_name="nginx", **overrides):
    data = {
        "port": port,
        "protocol": protocol,
        "status": "LISTEN",
        "pid": 123,
        "process_name": process_name,
        "is_docker": False,
        "container_id": None,
        "container_name": None,
        "container_image": None,
    }
    data.update(overrides)
    return data


def test_upsert_service_inserts_and_updates(repo):
    service_id = repo.upsert_service(_service())
    same_id = repo.upsert_service(_service(status="ESTABLISHED"))

    assert service_id == same_id

    services = repo.list_services()
    assert len(services) == 1
    assert services[0]["status"] == "ESTABLISHED"
    assert services[0]["active"] == 1


def test_mark_stale_services_inactive(repo):
    repo.upsert_service(_service(port=80, process_name="nginx"))
    repo.upsert_service(_service(port=443, process_name="nginx"))

    still_seen_key = (80, "tcp", "nginx", None)
    repo.mark_stale_services_inactive({still_seen_key})

    services = {s["port"]: s for s in repo.list_services(active_only=False)}
    assert services[80]["active"] == 1
    assert services[443]["active"] == 0

    active_only = repo.list_services(active_only=True)
    assert len(active_only) == 1
    assert active_only[0]["port"] == 80


def _window(**overrides):
    data = {
        "window_start": time.time() - 30,
        "window_end": time.time(),
        "num_packets": 42,
        "num_connections": 5,
        "num_unique_src_ips": 2,
        "num_unique_dst_ips": 3,
        "num_unique_ports": 4,
        "total_bytes": 5000,
        "avg_packet_size": 119.0,
        "syn_count": 1,
        "tcp_ratio": 0.8,
        "udp_ratio": 0.2,
        "icmp_ratio": 0.0,
        "anomaly_score": -0.1,
        "is_anomaly": False,
        "severity": "none",
    }
    data.update(overrides)
    return data


def test_insert_and_list_traffic_windows(repo):
    window_id = repo.insert_traffic_window(_window())
    assert isinstance(window_id, int)

    windows = repo.list_traffic_windows(limit=10)
    assert len(windows) == 1
    assert windows[0]["num_packets"] == 42


def test_insert_and_list_ip_window_stats(repo):
    window_id = repo.insert_traffic_window(_window())
    repo.insert_ip_window_stats(
        window_id,
        [
            {
                "src_ip": "10.0.0.5",
                "num_packets": 20,
                "num_connections": 3,
                "num_unique_dst_ips": 2,
                "num_unique_ports": 2,
                "total_bytes": 2000,
                "syn_count": 0,
                "anomaly_score": -0.2,
                "is_anomaly": True,
                "severity": "high",
            }
        ],
    )

    stats = repo.list_ip_window_stats(window_id)
    assert len(stats) == 1
    assert stats[0]["src_ip"] == "10.0.0.5"
    assert stats[0]["is_anomaly"] == 1


def test_insert_and_list_alerts(repo):
    alert_id = repo.insert_alert(
        {"severity": "high", "source_ip": "10.0.0.5", "port": 22, "reason": "SSH brute force sospechoso"}
    )
    alerts = repo.list_alerts()

    assert len(alerts) == 1
    assert alerts[0]["id"] == alert_id
    assert alerts[0]["notified"] == 0

    repo.mark_alert_notified(alert_id)
    repo.mark_alert_blocked(alert_id)

    alerts = repo.list_alerts()
    assert alerts[0]["notified"] == 1
    assert alerts[0]["blocked"] == 1


def test_blocked_ips_lifecycle(repo):
    now = time.time()
    repo.insert_blocked_ip({"ip": "1.2.3.4", "reason": "flood", "blocked_at": now, "expires_at": now - 1})
    repo.insert_blocked_ip({"ip": "5.6.7.8", "reason": "scan", "blocked_at": now, "expires_at": now + 3600})

    active = repo.list_active_blocked_ips()
    assert {b["ip"] for b in active} == {"1.2.3.4", "5.6.7.8"}

    expired = repo.expire_blocked_ips(now=now)
    assert expired == ["1.2.3.4"]

    active_after = repo.list_active_blocked_ips()
    assert {b["ip"] for b in active_after} == {"5.6.7.8"}


def test_traffic_summary_since(repo):
    since = time.time() - 3600
    window_id = repo.insert_traffic_window(_window(is_anomaly=True, severity="high"))
    repo.insert_ip_window_stats(
        window_id,
        [
            {
                "src_ip": "10.0.0.9",
                "num_packets": 5,
                "num_connections": 1,
                "num_unique_dst_ips": 1,
                "num_unique_ports": 1,
                "total_bytes": 500,
                "syn_count": 0,
                "anomaly_score": -0.3,
                "is_anomaly": True,
                "severity": "high",
            }
        ],
    )
    repo.insert_alert({"severity": "high", "source_ip": "10.0.0.9", "port": 22, "reason": "test"})

    summary = repo.traffic_summary_since(since)

    assert summary["num_windows"] == 1
    assert summary["num_anomalous_windows"] == 1
    assert summary["num_alerts"] == 1
    assert summary["top_anomalous_ips"][0]["src_ip"] == "10.0.0.9"


def test_influxdb_repository_raises_not_implemented():
    repo = InfluxDBRepository(url="http://localhost:8086", token="x", org="o", bucket="b")
    with pytest.raises(NotImplementedError):
        repo.init_schema()
