"""Descubrimiento de servicios activos en la máquina.

Combina dos fuentes:
- Procesos del sistema operativo con puertos abiertos (vía psutil).
- Contenedores Docker en ejecución y sus puertos publicados (vía Docker SDK).

El resultado es una lista de `Service`, independiente de cómo se
persista o se muestre después.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import psutil

logger = logging.getLogger("netguardian.discovery")

try:
    import docker
    from docker.errors import DockerException

    _DOCKER_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover - docker es opcional en el sistema
    _DOCKER_SDK_AVAILABLE = False


@dataclass(frozen=True)
class Service:
    """Un servicio/proceso detectado escuchando o con conexiones activas."""

    port: int
    protocol: str  # "tcp" | "udp"
    status: str  # "LISTEN", "ESTABLISHED", ...
    pid: int | None = None
    process_name: str | None = None
    is_docker: bool = False
    container_id: str | None = None
    container_name: str | None = None
    container_image: str | None = None

    @property
    def key(self) -> tuple:
        """Clave de deduplicación: mismo puerto+protocolo+pid es el mismo servicio."""
        return (self.port, self.protocol, self.pid)

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "status": self.status,
            "pid": self.pid,
            "process_name": self.process_name,
            "is_docker": self.is_docker,
            "container_id": self.container_id,
            "container_name": self.container_name,
            "container_image": self.container_image,
        }


def _proto_name(kind: int) -> str:
    import socket

    if kind == socket.SOCK_STREAM:
        return "tcp"
    if kind == socket.SOCK_DGRAM:
        return "udp"
    return "unknown"


def discover_processes() -> list[Service]:
    """Lista procesos del SO con sockets abiertos (escuchando o con conexión activa)."""
    services: dict[tuple, Service] = {}

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        logger.warning(
            "Permisos insuficientes para listar conexiones de red. "
            "Ejecuta el sensor como administrador/root para ver todos los procesos."
        )
        return []

    for conn in connections:
        if not conn.laddr:
            continue
        port = conn.laddr.port
        protocol = _proto_name(conn.type)
        status = conn.status if conn.status else "NONE"
        process_name = None

        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = None

        service = Service(
            port=port,
            protocol=protocol,
            status=status,
            pid=conn.pid,
            process_name=process_name,
        )
        # Si ya vimos este pid+puerto+protocolo, nos quedamos con el estado LISTEN
        # (más informativo que una conexión efímera ESTABLISHED repetida).
        existing = services.get(service.key)
        if existing is None or (status == "LISTEN" and existing.status != "LISTEN"):
            services[service.key] = service

    return list(services.values())


def discover_docker_containers() -> list[Service]:
    """Lista contenedores Docker en ejecución y sus puertos publicados al host."""
    if not _DOCKER_SDK_AVAILABLE:
        logger.debug("docker SDK no instalado; se omite descubrimiento de contenedores.")
        return []

    services: list[Service] = []
    try:
        client = docker.from_env()
        client.ping()
    except DockerException as exc:
        logger.debug("Docker no disponible (¿daemon apagado?): %s", exc)
        return []

    try:
        containers = client.containers.list()
        for container in containers:
            ports = container.attrs.get("NetworkSettings", {}).get("Ports", {}) or {}
            image_tags = container.image.tags
            image_name = image_tags[0] if image_tags else container.image.short_id

            if not ports:
                # Contenedor sin puertos publicados: lo registramos igualmente
                # con puerto 0 para que aparezca como "servicio interno".
                services.append(
                    Service(
                        port=0,
                        protocol="n/a",
                        status="RUNNING",
                        is_docker=True,
                        container_id=container.short_id,
                        container_name=container.name,
                        container_image=image_name,
                    )
                )
                continue

            for container_port, bindings in ports.items():
                if not bindings:
                    continue
                port_num, proto = (
                    container_port.split("/") if "/" in container_port else (container_port, "tcp")
                )
                for binding in bindings:
                    host_port = binding.get("HostPort")
                    if not host_port:
                        continue
                    services.append(
                        Service(
                            port=int(host_port),
                            protocol=proto,
                            status="LISTEN",
                            is_docker=True,
                            container_id=container.short_id,
                            container_name=container.name,
                            container_image=image_name,
                        )
                    )
    except DockerException as exc:
        logger.warning("Error consultando contenedores Docker: %s", exc)

    return services


def discover_services() -> list[Service]:
    """Combina procesos del SO y contenedores Docker en una sola lista de servicios.

    Cuando un puerto está publicado por Docker, se prioriza la información
    del contenedor (más útil) sobre la del proceso genérico que Docker usa
    para hacer el port-forwarding (p. ej. docker-proxy).
    """
    docker_services = discover_docker_containers()
    docker_ports = {s.port for s in docker_services if s.protocol in {"tcp", "udp"}}

    process_services = [
        s for s in discover_processes() if s.port not in docker_ports
    ]

    return docker_services + process_services
