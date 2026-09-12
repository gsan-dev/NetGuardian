"""Extracción de features numéricas a partir de una ventana de paquetes.

Dos niveles de features, pensados para dos modos de modelo (ver model.py):

- `WindowFeatures`: agregado de toda la red en la ventana (modo "global").
- `IpWindowFeatures`: agregado por IP origen dentro de la ventana (modo
  "per_ip", mejora futura ya integrada: permite un perfil de
  comportamiento normal por dispositivo en vez de uno único global).
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from capture import PacketRecord

SYN_FLAG = "S"


def _is_syn_only(tcp_flags: str | None) -> bool:
    """True si el paquete es un SYN "puro" (sin ACK) — típico de escaneos/floods."""
    return bool(tcp_flags) and SYN_FLAG in tcp_flags and "A" not in tcp_flags


@dataclass
class WindowFeatures:
    window_start: float
    window_end: float
    num_packets: int
    num_connections: int
    num_unique_src_ips: int
    num_unique_dst_ips: int
    num_unique_ports: int
    total_bytes: int
    avg_packet_size: float
    syn_count: int
    tcp_ratio: float
    udp_ratio: float
    icmp_ratio: float

    def to_vector(self) -> list[float]:
        """Vector numérico en orden fijo, listo para alimentar al modelo ML."""
        return [
            float(self.num_packets),
            float(self.num_connections),
            float(self.num_unique_src_ips),
            float(self.num_unique_dst_ips),
            float(self.num_unique_ports),
            float(self.total_bytes),
            self.avg_packet_size,
            float(self.syn_count),
            self.tcp_ratio,
            self.udp_ratio,
            self.icmp_ratio,
        ]

    @staticmethod
    def feature_names() -> list[str]:
        return [
            "num_packets",
            "num_connections",
            "num_unique_src_ips",
            "num_unique_dst_ips",
            "num_unique_ports",
            "total_bytes",
            "avg_packet_size",
            "syn_count",
            "tcp_ratio",
            "udp_ratio",
            "icmp_ratio",
        ]


@dataclass
class IpWindowFeatures:
    """Features de una IP concreta dentro de una ventana (para modelo per_ip)."""

    src_ip: str
    window_start: float
    window_end: float
    num_packets: int
    num_connections: int
    num_unique_dst_ips: int
    num_unique_ports: int
    total_bytes: int
    syn_count: int

    def to_vector(self) -> list[float]:
        return [
            float(self.num_packets),
            float(self.num_connections),
            float(self.num_unique_dst_ips),
            float(self.num_unique_ports),
            float(self.total_bytes),
            float(self.syn_count),
        ]

    @staticmethod
    def feature_names() -> list[str]:
        return [
            "num_packets",
            "num_connections",
            "num_unique_dst_ips",
            "num_unique_ports",
            "total_bytes",
            "syn_count",
        ]


def extract_window_features(
    window_start: float, window_end: float, packets: list[PacketRecord]
) -> WindowFeatures:
    """Calcula las features agregadas de toda la red para una ventana."""
    num_packets = len(packets)
    if num_packets == 0:
        return WindowFeatures(
            window_start=window_start,
            window_end=window_end,
            num_packets=0,
            num_connections=0,
            num_unique_src_ips=0,
            num_unique_dst_ips=0,
            num_unique_ports=0,
            total_bytes=0,
            avg_packet_size=0.0,
            syn_count=0,
            tcp_ratio=0.0,
            udp_ratio=0.0,
            icmp_ratio=0.0,
        )

    connections: set[tuple] = set()
    src_ips: set[str] = set()
    dst_ips: set[str] = set()
    ports: set[int] = set()
    total_bytes = 0
    syn_count = 0
    proto_counter: Counter[str] = Counter()

    for p in packets:
        connections.add((p.src_ip, p.dst_ip, p.src_port, p.dst_port))
        src_ips.add(p.src_ip)
        dst_ips.add(p.dst_ip)
        if p.src_port is not None:
            ports.add(p.src_port)
        if p.dst_port is not None:
            ports.add(p.dst_port)
        total_bytes += p.length
        proto_counter[p.protocol] += 1
        if p.protocol == "tcp" and _is_syn_only(p.tcp_flags):
            syn_count += 1

    return WindowFeatures(
        window_start=window_start,
        window_end=window_end,
        num_packets=num_packets,
        num_connections=len(connections),
        num_unique_src_ips=len(src_ips),
        num_unique_dst_ips=len(dst_ips),
        num_unique_ports=len(ports),
        total_bytes=total_bytes,
        avg_packet_size=total_bytes / num_packets,
        syn_count=syn_count,
        tcp_ratio=proto_counter["tcp"] / num_packets,
        udp_ratio=proto_counter["udp"] / num_packets,
        icmp_ratio=proto_counter["icmp"] / num_packets,
    )


def extract_ip_window_features(
    window_start: float, window_end: float, packets: list[PacketRecord]
) -> list[IpWindowFeatures]:
    """Agrupa los paquetes de la ventana por IP origen y calcula features por IP."""
    by_ip: dict[str, list[PacketRecord]] = defaultdict(list)
    for p in packets:
        by_ip[p.src_ip].append(p)

    results: list[IpWindowFeatures] = []
    for src_ip, ip_packets in by_ip.items():
        connections: set[tuple] = set()
        dst_ips: set[str] = set()
        ports: set[int] = set()
        total_bytes = 0
        syn_count = 0

        for p in ip_packets:
            connections.add((p.dst_ip, p.dst_port))
            dst_ips.add(p.dst_ip)
            if p.dst_port is not None:
                ports.add(p.dst_port)
            total_bytes += p.length
            if p.protocol == "tcp" and _is_syn_only(p.tcp_flags):
                syn_count += 1

        results.append(
            IpWindowFeatures(
                src_ip=src_ip,
                window_start=window_start,
                window_end=window_end,
                num_packets=len(ip_packets),
                num_connections=len(connections),
                num_unique_dst_ips=len(dst_ips),
                num_unique_ports=len(ports),
                total_bytes=total_bytes,
                syn_count=syn_count,
            )
        )
    return results
