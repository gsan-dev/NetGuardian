"""Pruebas de orquestación de sensor/main.py.

sklearn no se puede importar en esta máquina de desarrollo (una
directiva de Windows bloquea su DLL nativa, ver tests/test_model.py),
así que aquí sustituimos sensor/model.py por un doble de prueba
equivalente en sys.modules ANTES de importar sensor/main.py. Esto deja
probar toda la orquestación (descubrimiento, ventanas, alertas,
notificaciones, bloqueo y expiración) sin tocar sklearn en absoluto.
"""
import importlib.util
import sys
import types
from pathlib import Path

import pytest

from capture import PacketRecord
from discovery import Service

REPO_ROOT = Path(__file__).resolve().parent.parent


class _FakeAnomalyResult:
    def __init__(self, is_anomaly, score, severity):
        self.is_anomaly = is_anomaly
        self.score = score
        self.severity = severity


class _FakeAnomalyModel:
    """Se entrena con >=10 muestras y marca anómalo si num_packets > 1000."""

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.contamination = contamination
        self._trained = False

    @property
    def is_trained(self) -> bool:
        return self._trained

    def train(self, feature_vectors):
        if len(feature_vectors) < 10:
            raise ValueError("insufficient samples")
        self._trained = True

    def score(self, feature_vector):
        is_anomaly = feature_vector[0] > 1000
        if is_anomaly:
            return _FakeAnomalyResult(True, -0.9, "high")
        return _FakeAnomalyResult(False, 0.1, "none")

    def save(self, path):
        pass

    @classmethod
    def load(cls, path):
        raise FileNotFoundError(path)


class _FakePerIpModelRegistry:
    def __init__(self, contamination, min_samples, global_model):
        self.global_model = global_model
        self.min_samples = min_samples
        self._models: dict = {}

    def observe(self, src_ip, feature_vector):
        pass

    def has_model(self, src_ip):
        return src_ip in self._models

    def train_ip(self, src_ip):
        return False

    def train_all_ready(self):
        return []

    def score(self, src_ip, feature_vector):
        return self.global_model.score(feature_vector)

    def save_all(self, directory):
        pass

    def load_all(self, directory):
        pass


@pytest.fixture(autouse=True)
def fake_model_module(monkeypatch):
    fake_module = types.ModuleType("model")
    fake_module.AnomalyModel = _FakeAnomalyModel
    fake_module.PerIpModelRegistry = _FakePerIpModelRegistry
    fake_module.MIN_TRAINING_SAMPLES = 10
    fake_module.DEFAULT_MODEL_DIR = REPO_ROOT / "data" / "models"
    monkeypatch.setitem(sys.modules, "model", fake_module)
    yield


def _load_sensor_main():
    spec = importlib.util.spec_from_file_location(
        "netguardian_sensor_main_test", REPO_ROOT / "sensor" / "main.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["netguardian_sensor_main_test"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def sensor(tmp_path):
    import common.db as db_module
    from common.config import settings

    settings.db_path = str(tmp_path / "sensor_test.db")
    settings.model_mode = "global"
    settings.auto_block_enabled = False
    settings.telegram_bot_token = ""
    settings.telegram_chat_id = ""
    settings.discord_webhook_url = ""
    settings.notify_min_severity = "low"
    db_module._repository_singleton = None

    sensor_main = _load_sensor_main()
    instance = sensor_main.Sensor()
    yield instance

    db_module._repository_singleton = None


def _small_packets(n=5, src_ip="10.0.0.5"):
    return [
        PacketRecord(
            timestamp=0.0, src_ip=src_ip, dst_ip="10.0.0.1", protocol="tcp",
            length=100, src_port=51000 + i, dst_port=443,
        )
        for i in range(n)
    ]


def _huge_packets(n=1001, src_ip="10.0.0.6"):
    return [
        PacketRecord(
            timestamp=0.0, src_ip=src_ip, dst_ip="10.0.0.1", protocol="tcp",
            length=64, src_port=51000 + (i % 500), dst_port=443,
        )
        for i in range(n)
    ]


def test_on_window_without_trained_model_persists_window_without_anomaly(sensor):
    sensor.on_window(0.0, 30.0, _small_packets())

    windows = sensor.repo.list_traffic_windows()
    assert len(windows) == 1
    assert windows[0]["is_anomaly"] == 0
    assert windows[0]["severity"] == "none"


def test_sensor_trains_model_and_flags_anomalous_window(sensor):
    for _ in range(10):
        sensor.on_window(0.0, 30.0, _small_packets())

    assert sensor.global_model.is_trained is True

    sensor.on_window(0.0, 30.0, _huge_packets())

    windows = sensor.repo.list_traffic_windows(limit=20)
    assert windows[-1]["is_anomaly"] == 1
    assert windows[-1]["severity"] == "high"


def test_anomalous_ip_window_creates_alert(sensor):
    for _ in range(10):
        sensor.on_window(0.0, 30.0, _small_packets())

    sensor.on_window(0.0, 30.0, _huge_packets(src_ip="10.0.0.99"))

    alerts = sensor.repo.list_alerts()
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "10.0.0.99"
    assert alerts[0]["severity"] == "high"


def test_run_discovery_once_upserts_and_marks_stale(sensor, monkeypatch):
    first_services = [
        Service(port=80, protocol="tcp", status="LISTEN", process_name="nginx"),
        Service(port=443, protocol="tcp", status="LISTEN", process_name="nginx"),
    ]
    monkeypatch.setattr(
        sys.modules["netguardian_sensor_main_test"], "discover_services", lambda: first_services
    )
    sensor.run_discovery_once()

    active = sensor.repo.list_services()
    assert {s["port"] for s in active} == {80, 443}

    second_services = [Service(port=80, protocol="tcp", status="LISTEN", process_name="nginx")]
    monkeypatch.setattr(
        sys.modules["netguardian_sensor_main_test"], "discover_services", lambda: second_services
    )
    sensor.run_discovery_once()

    active_after = sensor.repo.list_services(active_only=True)
    assert {s["port"] for s in active_after} == {80}

    all_services = sensor.repo.list_services(active_only=False)
    assert len(all_services) == 2


def test_expire_blocks_once_unblocks_expired_ips(sensor):
    sensor.repo.insert_blocked_ip(
        {"ip": "1.2.3.4", "reason": "test", "blocked_at": 0.0, "expires_at": 0.0}
    )

    sensor.expire_blocks_once()

    assert sensor.repo.list_active_blocked_ips() == []
