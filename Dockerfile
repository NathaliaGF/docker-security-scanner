FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/NathaliaGF/docker-security-scanner" \
      org.opencontainers.image.description="Static security scanner for Dockerfiles and docker-compose files" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY dockerscan ./dockerscan
RUN pip install --no-cache-dir . && useradd --system --no-create-home scanner

USER scanner
WORKDIR /scan
ENTRYPOINT ["dockerscan"]
CMD ["--dir", "."]
