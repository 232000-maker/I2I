FROM python:3.10-slim-bookworm

ARG PUID=1000
ARG PGID=1000

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb fluxbox x11vnc novnc websockify tini python3-tk libtk8.6 \
    gosu \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g ${PGID} i2igroup && \
    useradd -u ${PUID} -g i2igroup -m -s /bin/bash i2iuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application directories
COPY src/ ./src/
COPY gui/ ./gui/
COPY tests/ ./tests/

# Copy individual files
COPY main.py .
COPY security_test.py .
COPY entrypoint.sh .

RUN chmod +x /app/entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
