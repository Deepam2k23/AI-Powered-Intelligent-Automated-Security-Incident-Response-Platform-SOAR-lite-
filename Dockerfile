FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1

WORKDIR /app

# iptables is needed by response.py.
# ca-certificates is needed for HTTPS API calls.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iptables \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN python3 -m pip install \
    --no-cache-dir \
    -r requirements.txt

COPY ai_report.py .
COPY config.py .
COPY decision.py .
COPY enrichment.py .
COPY notifier.py .
COPY response.py .
COPY soar.py .
COPY storage.py .
COPY wazuh_client.py .

RUN mkdir -p /app/reports /data

CMD ["python3", "-u", "soar.py"]
