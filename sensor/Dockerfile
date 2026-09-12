# Build context: raíz del repo (necesita common/ además de sensor/)
#
# El sensor necesita ejecutarse con permisos elevados para capturar
# tráfico (Scapy) y, si AUTO_BLOCK_ENABLED=true, para invocar iptables.
# En docker-compose.yml se le da network_mode: host y
# cap_add: NET_ADMIN, NET_RAW (ver comentarios allí).
FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY common/ common/
COPY sensor/ sensor/

RUN pip install --no-cache-dir -r sensor/requirements.txt

WORKDIR /app/sensor

CMD ["python", "main.py"]
