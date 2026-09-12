"""Entrenamiento e inferencia del modelo de detección de anomalías.

Usa Isolation Forest (scikit-learn): no supervisado, rápido, sin GPU,
ideal para aprender "qué es normal" a partir de ventanas de tráfico sin
necesitar ataques etiquetados.

Incluye `PerIpModelRegistry`, que implementa la mejora futura del README
("entrenar un modelo por dispositivo/IP en vez de uno global"): cada IP
con histórico suficiente tiene su propio Isolation Forest; las que no,
caen al modelo global para no generar falsos positivos por falta de datos.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger("netguardian.model")

DEFAULT_MODEL_DIR = Path(__file__).resolve().parent.parent / "data" / "models"
MIN_TRAINING_SAMPLES = 10


@dataclass
class AnomalyResult:
    is_anomaly: bool
    score: float  # score_samples de sklearn: más negativo = más anómalo
    severity: str  # "none" | "low" | "medium" | "high"


class AnomalyModel:
    """Envoltorio sobre IsolationForest: entrena, puntúa y persiste a disco."""

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self._model: IsolationForest | None = None
        self._n_features: int | None = None

    @property
    def is_trained(self) -> bool:
        return self._model is not None

    def train(self, feature_vectors: list[list[float]]) -> None:
        if len(feature_vectors) < MIN_TRAINING_SAMPLES:
            raise ValueError(
                f"Se necesitan al menos {MIN_TRAINING_SAMPLES} muestras para "
                f"entrenar (recibidas: {len(feature_vectors)})"
            )
        X = np.array(feature_vectors, dtype=float)
        self._n_features = X.shape[1]
        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100,
        )
        self._model.fit(X)
        logger.info(
            "Modelo entrenado con %d muestras y %d features", X.shape[0], X.shape[1]
        )

    def score(self, feature_vector: list[float]) -> AnomalyResult:
        if not self.is_trained:
            raise RuntimeError("El modelo no está entrenado todavía")

        X = np.array([feature_vector], dtype=float)
        prediction = self._model.predict(X)[0]  # 1 = normal, -1 = anómalo
        raw_score = float(self._model.score_samples(X)[0])
        is_anomaly = prediction == -1

        if not is_anomaly:
            severity = "none"
        elif raw_score < -0.6:
            severity = "high"
        elif raw_score < -0.5:
            severity = "medium"
        else:
            severity = "low"

        return AnomalyResult(is_anomaly=is_anomaly, score=raw_score, severity=severity)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self._model,
                "n_features": self._n_features,
                "contamination": self.contamination,
            },
            path,
        )

    @classmethod
    def load(cls, path: Path) -> "AnomalyModel":
        payload = joblib.load(path)
        instance = cls(contamination=payload["contamination"])
        instance._model = payload["model"]
        instance._n_features = payload["n_features"]
        return instance


def _ip_to_filename(ip: str) -> str:
    return f"model_{ip.replace(':', '_').replace('.', '-')}.joblib"


def _filename_to_ip(stem: str) -> str:
    ip_part = stem.removeprefix("model_")
    return ip_part.replace("-", ".").replace("_", ":")


class PerIpModelRegistry:
    """Mantiene un AnomalyModel independiente por IP origen (modo "per_ip").

    Las IPs con menos de `min_samples` observaciones acumuladas usan el
    modelo global como fallback, evitando entrenar modelos poco fiables
    con muy pocos datos.
    """

    def __init__(
        self,
        contamination: float,
        min_samples: int,
        global_model: AnomalyModel,
    ):
        self.contamination = contamination
        self.min_samples = min_samples
        self.global_model = global_model
        self._models: dict[str, AnomalyModel] = {}
        self._training_buffers: dict[str, list[list[float]]] = defaultdict(list)

    def observe(self, src_ip: str, feature_vector: list[float]) -> None:
        """Acumula una muestra de una IP para entrenar (o reentrenar) su modelo."""
        self._training_buffers[src_ip].append(feature_vector)

    def has_model(self, src_ip: str) -> bool:
        return src_ip in self._models

    def train_ip(self, src_ip: str) -> bool:
        """Entrena el modelo de una IP si ya tiene muestras suficientes."""
        samples = self._training_buffers.get(src_ip, [])
        if len(samples) < self.min_samples:
            return False
        model = AnomalyModel(contamination=self.contamination)
        model.train(samples)
        self._models[src_ip] = model
        logger.info("Modelo per-IP entrenado para %s (%d muestras)", src_ip, len(samples))
        return True

    def train_all_ready(self) -> list[str]:
        """Entrena todas las IPs que ya alcanzaron el mínimo de muestras."""
        trained = []
        for src_ip in list(self._training_buffers.keys()):
            if self.train_ip(src_ip):
                trained.append(src_ip)
        return trained

    def score(self, src_ip: str, feature_vector: list[float]) -> AnomalyResult:
        model = self._models.get(src_ip)
        if model is None or not model.is_trained:
            return self.global_model.score(feature_vector)
        return model.score(feature_vector)

    def save_all(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        for ip, model in self._models.items():
            model.save(directory / _ip_to_filename(ip))

    def load_all(self, directory: Path) -> None:
        if not directory.exists():
            return
        for path in directory.glob("model_*.joblib"):
            ip = _filename_to_ip(path.stem)
            try:
                self._models[ip] = AnomalyModel.load(path)
            except Exception:
                logger.exception("No se pudo cargar el modelo per-IP %s", path)
