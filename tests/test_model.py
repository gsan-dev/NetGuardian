"""Pruebas del modelo de detección de anomalías (Isolation Forest)."""
import random

import pytest

from model import AnomalyModel, PerIpModelRegistry


def _normal_samples(n=200, seed=42):
    rng = random.Random(seed)
    return [
        [
            rng.uniform(20, 40),  # num_packets
            rng.uniform(5, 15),  # num_connections
            rng.uniform(1, 3),  # num_unique_src_ips
            rng.uniform(1, 5),  # num_unique_dst_ips
            rng.uniform(1, 6),  # num_unique_ports
            rng.uniform(2000, 6000),  # total_bytes
            rng.uniform(60, 120),  # avg_packet_size
            rng.uniform(0, 2),  # syn_count
            rng.uniform(0.6, 0.9),  # tcp_ratio
            rng.uniform(0.05, 0.3),  # udp_ratio
            rng.uniform(0, 0.05),  # icmp_ratio
        ]
        for _ in range(n)
    ]


def _extreme_outlier():
    return [5000.0, 3000.0, 200.0, 500.0, 400.0, 5_000_000.0, 1400.0, 2000.0, 0.99, 0.5, 0.5]


def test_train_requires_minimum_samples():
    model = AnomalyModel()
    with pytest.raises(ValueError):
        model.train([[1, 2, 3]] * 5)


def test_train_and_score_normal_vs_outlier():
    model = AnomalyModel(contamination=0.05)
    model.train(_normal_samples())

    assert model.is_trained

    normal_result = model.score(_normal_samples(n=1, seed=99)[0])
    outlier_result = model.score(_extreme_outlier())

    assert outlier_result.is_anomaly is True
    assert outlier_result.severity in {"low", "medium", "high"}
    assert outlier_result.score < normal_result.score


def test_score_before_training_raises():
    model = AnomalyModel()
    with pytest.raises(RuntimeError):
        model.score([1, 2, 3])


def test_save_and_load_round_trip(tmp_path):
    model = AnomalyModel(contamination=0.05)
    model.train(_normal_samples())

    path = tmp_path / "model.joblib"
    model.save(path)
    assert path.exists()

    loaded = AnomalyModel.load(path)
    assert loaded.is_trained

    outlier_result = loaded.score(_extreme_outlier())
    assert outlier_result.is_anomaly is True


def test_per_ip_registry_falls_back_to_global_when_not_enough_samples():
    global_model = AnomalyModel(contamination=0.05)
    global_model.train(_normal_samples())

    registry = PerIpModelRegistry(contamination=0.05, min_samples=50, global_model=global_model)
    registry.observe("10.0.0.5", _normal_samples(n=1)[0])  # solo 1 muestra, insuficiente

    assert registry.train_ip("10.0.0.5") is False
    assert registry.has_model("10.0.0.5") is False

    result = registry.score("10.0.0.5", _extreme_outlier())
    assert result.is_anomaly is True  # usa el modelo global como fallback


def test_per_ip_registry_trains_own_model_with_enough_samples():
    global_model = AnomalyModel(contamination=0.05)
    global_model.train(_normal_samples())

    registry = PerIpModelRegistry(contamination=0.05, min_samples=20, global_model=global_model)
    for sample in _normal_samples(n=30):
        registry.observe("10.0.0.6", sample)

    trained = registry.train_all_ready()

    assert "10.0.0.6" in trained
    assert registry.has_model("10.0.0.6") is True

    result = registry.score("10.0.0.6", _extreme_outlier())
    assert result.is_anomaly is True


def test_per_ip_registry_save_and_load_all(tmp_path):
    global_model = AnomalyModel(contamination=0.05)
    global_model.train(_normal_samples())

    registry = PerIpModelRegistry(contamination=0.05, min_samples=20, global_model=global_model)
    for sample in _normal_samples(n=30):
        registry.observe("192.168.1.50", sample)
    registry.train_all_ready()
    registry.save_all(tmp_path)

    new_registry = PerIpModelRegistry(contamination=0.05, min_samples=20, global_model=global_model)
    new_registry.load_all(tmp_path)

    assert new_registry.has_model("192.168.1.50") is True
