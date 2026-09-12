"""Pruebas del parseo de paquetes y la agrupación en ventanas temporales."""
import time

from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw

from capture import PacketRecord, TrafficCapture, WindowBuffer, parse_packet


def test_parse_packet_tcp():
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=443, dport=51000, flags="SA") / Raw(b"x" * 20)
    record = parse_packet(pkt)

    assert record is not None
    assert record.protocol == "tcp"
    assert record.src_ip == "10.0.0.5"
    assert record.dst_ip == "10.0.0.1"
    assert record.src_port == 443
    assert record.dst_port == 51000
    assert record.tcp_flags == "SA"
    assert record.length > 20


def test_parse_packet_udp():
    pkt = Ether() / IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=53, dport=12345)
    record = parse_packet(pkt)

    assert record is not None
    assert record.protocol == "udp"
    assert record.src_port == 53
    assert record.dst_port == 12345


def test_parse_packet_icmp():
    pkt = Ether() / IP(src="192.168.1.10", dst="192.168.1.1") / ICMP()
    record = parse_packet(pkt)

    assert record is not None
    assert record.protocol == "icmp"
    assert record.src_port is None


def test_parse_packet_non_ip_returns_none():
    pkt = Ether()
    assert parse_packet(pkt) is None


def test_window_buffer_accumulates_and_flushes():
    buffer = WindowBuffer(window_seconds=10)
    record = PacketRecord(
        timestamp=time.time(), src_ip="1.2.3.4", dst_ip="5.6.7.8", protocol="tcp", length=100
    )

    buffer.add(record)
    buffer.add(record)

    assert len(buffer) == 2
    assert buffer.should_flush(now=buffer._window_start + 5) is False
    assert buffer.should_flush(now=buffer._window_start + 11) is True

    start, end, packets = buffer.flush(now=buffer._window_start + 11)
    assert len(packets) == 2
    assert len(buffer) == 0  # el buffer se reinicia tras el flush


def test_traffic_capture_handle_packet_feeds_buffer():
    windows_received = []

    def on_window(start, end, packets):
        windows_received.append(packets)

    capture = TrafficCapture(interface="lo", window_seconds=10, on_window=on_window)
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=443, dport=51000)

    capture._handle_packet(pkt)
    capture._handle_packet(pkt)

    assert len(capture.buffer) == 2
