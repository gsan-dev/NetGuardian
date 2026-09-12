"""Pruebas de integración del backend FastAPI (REST + auth + WebSocket)."""
import importlib.util
import sys
import time
from pathlib import Path

import bcrypt
import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module(path: Path, name: str):
    """Carga backend/main.py bajo un nombre único para no chocar con
    sensor/main.py cuando ambos coexisten en sys.modules durante los tests.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def backend_app(tmp_path):
    import common.db as db_module
    from common.config import settings

    settings.db_path = str(tmp_path / "test_backend.db")
    settings.auth_enabled = True
    settings.admin_username = "admin"
    settings.admin_password_hash = bcrypt.hashpw(b"s3cret-pass", bcrypt.gensalt()).decode()
    settings.auth_secret_key = "test-secret-key"
    db_module._repository_singleton = None

    module = _load_module(REPO_ROOT / "backend" / "main.py", "netguardian_backend_main_test")
    yield module

    db_module._repository_singleton = None


@pytest.fixture
def client(backend_app):
    with TestClient(backend_app.app) as c:
        yield c


def _auth_headers(client) -> dict:
    response = client.post(
        "/api/auth/login", json={"username": "admin", "password": "s3cret-pass"}
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_health_does_not_require_auth(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_login_success(client):
    response = client.post(
        "/api/auth/login", json={"username": "admin", "password": "s3cret-pass"}
    )
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"


def test_login_wrong_password(client):
    response = client.post(
        "/api/auth/login", json={"username": "admin", "password": "wrong"}
    )
    assert response.status_code == 401


def test_services_endpoint_requires_auth(client):
    response = client.get("/api/services")
    assert response.status_code == 401


def test_services_endpoint_with_valid_token(client):
    headers = _auth_headers(client)
    response = client.get("/api/services", headers=headers)
    assert response.status_code == 200
    assert response.json() == []


def test_traffic_and_alerts_endpoints_return_seeded_data(client, backend_app):
    from common.db import get_repository

    repo = get_repository()
    window_id = repo.insert_traffic_window(
        {
            "window_start": time.time() - 30,
            "window_end": time.time(),
            "num_packets": 10,
            "num_connections": 2,
            "num_unique_src_ips": 1,
            "num_unique_dst_ips": 1,
            "num_unique_ports": 1,
            "total_bytes": 1000,
            "avg_packet_size": 100.0,
            "syn_count": 0,
            "tcp_ratio": 1.0,
            "udp_ratio": 0.0,
            "icmp_ratio": 0.0,
            "anomaly_score": -0.1,
            "is_anomaly": False,
            "severity": "none",
        }
    )
    repo.insert_alert(
        {"severity": "high", "source_ip": "10.0.0.9", "port": 22, "reason": "test alert"}
    )

    headers = _auth_headers(client)

    windows_resp = client.get("/api/traffic/windows", headers=headers)
    assert windows_resp.status_code == 200
    assert len(windows_resp.json()) == 1
    assert windows_resp.json()[0]["id"] == window_id

    alerts_resp = client.get("/api/alerts", headers=headers)
    assert alerts_resp.status_code == 200
    assert len(alerts_resp.json()) == 1
    assert alerts_resp.json()[0]["reason"] == "test alert"


def test_weekly_report_returns_pdf(client):
    headers = _auth_headers(client)
    response = client.get("/api/reports/weekly", headers=headers)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"


def test_websocket_rejected_without_token(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/ws"):
            pass


def test_websocket_accepted_with_valid_token(client):
    headers = _auth_headers(client)
    token = headers["Authorization"].split(" ")[1]
    with client.websocket_connect(f"/ws?token={token}") as ws:
        assert ws is not None
