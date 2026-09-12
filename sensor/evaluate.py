"""Evalúa el modelo de detección de anomalías con tráfico sintético.

No sustituye a probarlo contra el tráfico real de tu red — para eso,
deja el sensor corriendo unos días y mira la pestaña de alertas — pero
da una primera señal de si el Isolation Forest distingue patrones de
ataque típicos (escaneo de puertos, flood, exfiltración) de tráfico
normal antes de dejarlo en producción.

Uso:
    cd sensor
    python evaluate.py
"""
from __future__ import annotations

import random

from model import AnomalyModel

FEATURE_NAMES = [
    "num_packets", "num_connections", "num_unique_src_ips", "num_unique_dst_ips",
    "num_unique_ports", "total_bytes", "avg_packet_size", "syn_count",
    "tcp_ratio", "udp_ratio", "icmp_ratio",
]


def make_normal_sample(rng: random.Random) -> list[float]:
    return [
        rng.uniform(20, 40),
        rng.uniform(5, 15),
        rng.uniform(1, 3),
        rng.uniform(1, 5),
        rng.uniform(1, 6),
        rng.uniform(2000, 6000),
        rng.uniform(60, 120),
        rng.uniform(0, 2),
        rng.uniform(0.6, 0.9),
        rng.uniform(0.05, 0.3),
        rng.uniform(0, 0.05),
    ]


def make_anomalous_sample(rng: random.Random, kind: str) -> list[float]:
    """Simula un patrón de ataque distorsionando las features que ese
    ataque afecta de verdad, dejando el resto como tráfico normal."""
    sample = make_normal_sample(rng)
    if kind == "port_scan":
        sample[4] = rng.uniform(200, 500)  # num_unique_ports disparado
        sample[7] = rng.uniform(100, 400)  # muchos SYN sin ACK
    elif kind == "ddos_flood":
        sample[0] = rng.uniform(5000, 20000)  # num_packets disparado
        sample[5] = rng.uniform(2_000_000, 10_000_000)  # total_bytes disparado
    elif kind == "exfiltration":
        sample[5] = rng.uniform(500_000, 2_000_000)  # total_bytes saliente alto
        sample[2] = rng.uniform(1, 2)  # pero de un único dispositivo
    else:
        raise ValueError(f"Tipo de ataque desconocido: {kind}")
    return sample


def main() -> None:
    rng = random.Random(7)

    train = [make_normal_sample(rng) for _ in range(300)]
    model = AnomalyModel(contamination=0.05)
    model.train(train)

    test_normal = [make_normal_sample(rng) for _ in range(200)]
    attack_kinds = ("port_scan", "ddos_flood", "exfiltration")
    test_attacks = {
        kind: [make_anomalous_sample(rng, kind) for _ in range(50)] for kind in attack_kinds
    }

    print("=== NetGuardian — evaluación del modelo con tráfico sintético ===\n")

    false_positives = sum(1 for v in test_normal if model.score(v).is_anomaly)
    fp_rate = false_positives / len(test_normal)
    print(
        f"Falsos positivos sobre tráfico normal: {false_positives}/{len(test_normal)} "
        f"({fp_rate:.1%})"
    )

    print("\nDetección por tipo de ataque simulado:")
    for kind, samples in test_attacks.items():
        detected = sum(1 for v in samples if model.score(v).is_anomaly)
        rate = detected / len(samples)
        print(f"  {kind:14s} {detected:3d}/{len(samples)} ({rate:.1%})")

    print(
        "\nEsto es tráfico sintético con patrones exagerados a propósito, así que "
        "una tasa de detección alta aquí no garantiza el mismo resultado con tu "
        "tráfico real. Úsalo como humo, no como benchmark definitivo."
    )


if __name__ == "__main__":
    main()
