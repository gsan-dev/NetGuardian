"""Pruebas del pipeline de extracción de features."""
from capture import PacketRecord
from features import extract_ip_window_features, extract_window_features


def _packet(src_ip="10.0.0.5", dst_ip="10.0.0.1", protocol="tcp", src_port=51000,
            dst_port=443, length=100, tcp_flags=None):
    return PacketRecord(
        timestamp=0.0,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        length=length,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
    )


def test_extract_window_features_empty_window():
    features = extract_window_features(0.0, 30.0, [])

    assert features.num_packets == 0
    assert features.num_connections == 0
    assert features.avg_packet_size == 0.0
    assert features.tcp_ratio == 0.0


def test_extract_window_features_basic_counts():
    packets = [
        _packet(src_ip="10.0.0.5", dst_port=443, length=100),
        _packet(src_ip="10.0.0.5", dst_port=443, length=200),
        _packet(src_ip="10.0.0.6", dst_ip="10.0.0.2", protocol="udp", dst_port=53, length=50),
    ]
    features = extract_window_features(0.0, 30.0, packets)

    assert features.num_packets == 3
    assert features.num_unique_src_ips == 2
    assert features.num_unique_dst_ips == 2
    assert features.total_bytes == 350
    assert features.avg_packet_size == 350 / 3
    assert round(features.tcp_ratio, 2) == round(2 / 3, 2)
    assert round(features.udp_ratio, 2) == round(1 / 3, 2)


def test_extract_window_features_counts_syn_only_packets():
    packets = [
        _packet(tcp_flags="S"),  # SYN puro -> cuenta
        _packet(tcp_flags="SA"),  # SYN-ACK -> no cuenta como intento de conexión nueva
        _packet(tcp_flags="A"),
    ]
    features = extract_window_features(0.0, 30.0, packets)

    assert features.syn_count == 1


def test_window_features_to_vector_matches_feature_names_length():
    features = extract_window_features(0.0, 30.0, [_packet()])
    assert len(features.to_vector()) == len(features.feature_names())


def test_extract_ip_window_features_groups_by_source():
    packets = [
        _packet(src_ip="10.0.0.5", dst_ip="10.0.0.1", dst_port=443),
        _packet(src_ip="10.0.0.5", dst_ip="10.0.0.2", dst_port=80),
        _packet(src_ip="10.0.0.6", dst_ip="10.0.0.1", dst_port=443),
    ]
    ip_features = extract_ip_window_features(0.0, 30.0, packets)
    by_ip = {f.src_ip: f for f in ip_features}

    assert set(by_ip.keys()) == {"10.0.0.5", "10.0.0.6"}
    assert by_ip["10.0.0.5"].num_packets == 2
    assert by_ip["10.0.0.5"].num_unique_dst_ips == 2
    assert by_ip["10.0.0.6"].num_packets == 1


def test_ip_window_features_to_vector_matches_feature_names_length():
    ip_features = extract_ip_window_features(0.0, 30.0, [_packet()])[0]
    assert len(ip_features.to_vector()) == len(ip_features.feature_names())
