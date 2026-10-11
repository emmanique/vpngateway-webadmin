FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 wireguard-tools nftables && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY health.py /app/health.py
USER 65532:65532
CMD ["python", "/app/health.py"]
