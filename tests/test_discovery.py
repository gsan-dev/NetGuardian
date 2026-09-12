"""Pruebas unitarias del módulo de descubrimiento de servicios."""
from unittest.mock import MagicMock, patch

import discovery


def _fake_conn(port, pid, status="LISTEN", sock_type=1):
    conn = MagicMock()
    conn.laddr = MagicMock(port=port)
    conn.type = sock_type  # socket.SOCK_STREAM == 1
    conn.status = status
    conn.pid = pid
    return conn


def test_discover_processes_returns_listening_services():
    fake_conns = [_fake_conn(port=8080, pid=1234, status="LISTEN")]

    with patch("discovery.psutil.net_connections", return_value=fake_conns), patch(
        "discovery.psutil.Process"
    ) as mock_process:
        mock_process.return_value.name.return_value = "python3"
        services = discovery.discover_processes()

    assert len(services) == 1
    service = services[0]
    assert service.port == 8080
    assert service.protocol == "tcp"
    assert service.status == "LISTEN"
    assert service.process_name == "python3"
    assert service.is_docker is False


def test_discover_processes_deduplicates_by_pid_port_protocol():
    fake_conns = [
        _fake_conn(port=8080, pid=1234, status="ESTABLISHED"),
        _fake_conn(port=8080, pid=1234, status="LISTEN"),
    ]

    with patch("discovery.psutil.net_connections", return_value=fake_conns), patch(
        "discovery.psutil.Process"
    ) as mock_process:
        mock_process.return_value.name.return_value = "nginx"
        services = discovery.discover_processes()

    assert len(services) == 1
    assert services[0].status == "LISTEN"


def test_discover_processes_handles_access_denied():
    with patch(
        "discovery.psutil.net_connections",
        side_effect=discovery.psutil.AccessDenied(),
    ):
        services = discovery.discover_processes()

    assert services == []


def test_discover_docker_containers_returns_empty_when_sdk_unavailable():
    with patch.object(discovery, "_DOCKER_SDK_AVAILABLE", False):
        assert discovery.discover_docker_containers() == []


def test_discover_docker_containers_parses_published_ports():
    fake_container = MagicMock()
    fake_container.attrs = {
        "NetworkSettings": {
            "Ports": {"80/tcp": [{"HostPort": "8080"}]}
        }
    }
    fake_container.image.tags = ["nginx:latest"]
    fake_container.short_id = "abc123"
    fake_container.name = "web"

    fake_client = MagicMock()
    fake_client.containers.list.return_value = [fake_container]

    with patch.object(discovery, "_DOCKER_SDK_AVAILABLE", True), patch.object(
        discovery, "docker"
    ) as mock_docker:
        mock_docker.from_env.return_value = fake_client
        services = discovery.discover_docker_containers()

    assert len(services) == 1
    service = services[0]
    assert service.port == 8080
    assert service.protocol == "tcp"
    assert service.is_docker is True
    assert service.container_name == "web"
    assert service.container_image == "nginx:latest"


def test_discover_services_prioritizes_docker_over_process_on_same_port():
    docker_service = discovery.Service(
        port=8080,
        protocol="tcp",
        status="LISTEN",
        is_docker=True,
        container_name="web",
    )
    process_service = discovery.Service(
        port=8080, protocol="tcp", status="LISTEN", pid=99, process_name="docker-proxy"
    )
    other_service = discovery.Service(
        port=22, protocol="tcp", status="LISTEN", pid=1, process_name="sshd"
    )

    with patch.object(
        discovery, "discover_docker_containers", return_value=[docker_service]
    ), patch.object(
        discovery, "discover_processes", return_value=[process_service, other_service]
    ):
        services = discovery.discover_services()

    assert docker_service in services
    assert process_service not in services
    assert other_service in services
