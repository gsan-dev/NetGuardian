"""Captura de tráfico de red con Scapy, agrupado en ventanas temporales.

Este módulo separa dos responsabilidades para que sean testeables sin
necesitar una interfaz de red real ni permisos elevados:

- `parse_packet`: convierte un paquete de Scapy en un `PacketRecord` plano.
- `WindowBuffer`: acumula records y decide cuándo cerrar una ventana.

`TrafficCapture` es la clase que efectivamente abre un sniffer en vivo
(requiere permisos de administrador/root y, en Windows, Npcap).
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable

from scapy.all import ICMP, IP, TCP, UDP, AsyncSniffer

try:
    from scapy.all import IPv6
except ImportError:  # pragma: no cover
    IPv6 = None  # type: ignore[assignment]

logger = logging.getLogger("netguardian.capture")


@dataclass(frozen=True)
class PacketRecord:
    """Representación plana y serializable de un paquete capturado."""

    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str  # "tcp" | "udp" | "icmp" | "other"
    length: int
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None  # p.ej. "S", "SA", "PA", "FA"


def parse_packet(pkt) -> PacketRecord | None:
    """Convierte un paquete de Scapy en un PacketRecord, o None si no es IP/IPv6."""
    if IP in pkt:
        ip_layer = pkt[IP]
    elif IPv6 is not None and IPv6 in pkt:
        ip_layer = pkt[IPv6]
    else:
        return None

    length = len(pkt)
    timestamp = float(pkt.time) if hasattr(pkt, "time") and pkt.time else time.time()

    if TCP in pkt:
        layer = pkt[TCP]
        return PacketRecord(
            timestamp=timestamp,
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            protocol="tcp",
            length=length,
            src_port=int(layer.sport),
            dst_port=int(layer.dport),
            tcp_flags=str(layer.flags),
        )
    if UDP in pkt:
        layer = pkt[UDP]
        return PacketRecord(
            timestamp=timestamp,
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            protocol="udp",
            length=length,
            src_port=int(layer.sport),
            dst_port=int(layer.dport),
        )
    if ICMP in pkt:
        return PacketRecord(
            timestamp=timestamp,
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            protocol="icmp",
            length=length,
        )
    return PacketRecord(
        timestamp=timestamp,
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        protocol="other",
        length=length,
    )


class WindowBuffer:
    """Acumula PacketRecord y los agrupa en ventanas de tiempo fijas.

    Thread-safe: `add()` se llama desde el hilo de captura de Scapy y
    `flush()` desde un hilo temporizador independiente.
    """

    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._packets: list[PacketRecord] = []
        self._window_start = time.time()

    def add(self, record: PacketRecord) -> None:
        with self._lock:
            self._packets.append(record)

    def should_flush(self, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        return (now - self._window_start) >= self.window_seconds

    def flush(self, now: float | None = None) -> tuple[float, float, list[PacketRecord]]:
        """Devuelve (window_start, window_end, packets) y reinicia el buffer."""
        now = now if now is not None else time.time()
        with self._lock:
            packets = self._packets
            window_start = self._window_start
            self._packets = []
            self._window_start = now
        return window_start, now, packets

    def __len__(self) -> int:
        with self._lock:
            return len(self._packets)


WindowCallback = Callable[[float, float, list[PacketRecord]], None]


class TrafficCapture:
    """Captura paquetes en vivo con Scapy y entrega ventanas completas vía callback."""

    def __init__(
        self,
        interface: str,
        window_seconds: int,
        on_window: WindowCallback,
        bpf_filter: str = "ip or ip6",
    ):
        self.interface = interface
        self.on_window = on_window
        self.buffer = WindowBuffer(window_seconds)
        self.bpf_filter = bpf_filter
        self._sniffer: AsyncSniffer | None = None
        self._timer_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def _handle_packet(self, pkt) -> None:
        record = parse_packet(pkt)
        if record is not None:
            self.buffer.add(record)

    def _timer_loop(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(1)
            if self.buffer.should_flush():
                window_start, window_end, packets = self.buffer.flush()
                try:
                    self.on_window(window_start, window_end, packets)
                except Exception:
                    logger.exception("Error procesando ventana de tráfico")

    def start(self) -> None:
        logger.info(
            "Iniciando captura en interfaz '%s' (ventana=%ss)",
            self.interface,
            self.buffer.window_seconds,
        )
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self._handle_packet,
            store=False,
        )
        self._sniffer.start()
        self._stop_event.clear()
        self._timer_thread = threading.Thread(target=self._timer_loop, daemon=True)
        self._timer_thread.start()

    def stop(self) -> None:
        logger.info("Deteniendo captura de tráfico")
        self._stop_event.set()
        if self._sniffer is not None:
            self._sniffer.stop()
        if self._timer_thread is not None:
            self._timer_thread.join(timeout=2)
