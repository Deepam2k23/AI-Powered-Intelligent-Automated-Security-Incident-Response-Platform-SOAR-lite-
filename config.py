"""Central configuration for the SOAR-lite playbook."""

import os


# ==========================================================
# Safety configuration
# ==========================================================

# These IPs must never be blocked automatically.
PROTECTED_IPS = {
    "127.0.0.1",
    "::1",
    "192.168.80.130",  # Debian server
    "192.168.80.1",    # Gateway/host
}

# Only these IPs may be automatically blocked.
AUTO_BLOCK_ALLOWED_IPS = {
    "192.168.80.129",  # Kali lab machine
}


# ==========================================================
# Wazuh Indexer connection
# ==========================================================

# When running normally on Debian, the default values work.
# When running in Docker, values will come from
# /etc/soar-lite.env.

WAZUH_INDEXER_URL = os.getenv(
    "WAZUH_INDEXER_URL",
    "https://127.0.0.1:9200",
)

WAZUH_INDEXER_USER = os.getenv(
    "WAZUH_INDEXER_USER",
    "",
)

WAZUH_INDEXER_PASS = os.getenv(
    "WAZUH_INDEXER_PASS",
    "",
)


# ==========================================================
# Wazuh rules/groups to monitor
# ==========================================================

# 5710/5712 = SSH authentication failures.
MONITORED_RULE_IDS = [
    "5710",
    "5712",
]

MONITORED_RULE_GROUPS = [
    "authentication_failed",
    "suricata",
]


# ==========================================================
# Polling configuration
# ==========================================================

POLL_INTERVAL_SECONDS = int(
    os.getenv(
        "POLL_INTERVAL_SECONDS",
        "15",
    )
)

LOOKBACK_MINUTES = int(
    os.getenv(
        "LOOKBACK_MINUTES",
        "2",
    )
)


# ==========================================================
# Threat-intelligence APIs
# ==========================================================

ABUSEIPDB_KEY = os.getenv(
    "ABUSEIPDB_KEY",
    "",
)

VT_KEY = os.getenv(
    "VT_KEY",
    "",
)


# ==========================================================
# Decision engine
# ==========================================================

BLOCK_SCORE_THRESHOLD = int(
    os.getenv(
        "BLOCK_SCORE_THRESHOLD",
        "50",
    )
)


# ==========================================================
# Slack notification
# ==========================================================

SLACK_WEBHOOK = os.getenv(
    "SLACK_WEBHOOK",
    "",
)


# ==========================================================
# Email notification
# ==========================================================

SMTP_HOST = os.getenv(
    "SMTP_HOST",
    "smtp.gmail.com",
)

SMTP_PORT = int(
    os.getenv(
        "SMTP_PORT",
        "587",
    )
)

SMTP_USER = os.getenv(
    "SMTP_USER",
    "",
)

SMTP_PASS = os.getenv(
    "SMTP_PASS",
    "",
)

EMAIL_FROM = os.getenv(
    "EMAIL_FROM",
    SMTP_USER,
)

EMAIL_TO = os.getenv(
    "EMAIL_TO",
    "",
)


# ==========================================================
# Storage configuration
# ==========================================================

# Normal Debian execution:
#   /home/shuhari/soar-lite
#
# Docker execution:
#   SOAR_BASE_DIR=/data
#
BASE_DIR = os.getenv(
    "SOAR_BASE_DIR",
    os.path.expanduser("~/soar-lite"),
)

BLOCKED_IPS_FILE = os.path.join(
    BASE_DIR,
    "blocked_ips.txt",
)

INCIDENT_LOG = os.path.join(
    BASE_DIR,
    "incidents.log",
)

SEEN_ALERTS_FILE = os.path.join(
    BASE_DIR,
    "seen_alert_ids.txt",
)


# ==========================================================
# Gemini AI configuration
# ==========================================================

# Never place the real API key directly inside config.py.
GEMINI_API_KEY = os.getenv(
    "GEMINI_API_KEY",
    "",
)

GEMINI_MODEL = os.getenv(
    "GEMINI_MODEL",
    "gemini-3.5-flash",
)


# ==========================================================
# Suricata configuration
# ==========================================================

SURICATA_LOG_PATH = os.getenv(
    "SURICATA_LOG_PATH",
    "/var/log/suricata/eve.json",
)


# ==========================================================
# AI incident-report configuration
# ==========================================================

# Only these IPs may trigger Gemini report generation.
AI_REPORT_ALLOWED_IPS = {
    "192.168.80.129",  # Kali lab machine
}

# Gemini will analyze Suricata alerts from the last 30 minutes.
AI_REPORT_LOOKBACK_MINUTES = int(
    os.getenv(
        "AI_REPORT_LOOKBACK_MINUTES",
        "30",
    )
)

# One Gemini request per IP every 15 minutes.
# This also applies after 429/503 errors.
AI_REPORT_COOLDOWN_SECONDS = int(
    os.getenv(
        "AI_REPORT_COOLDOWN_SECONDS",
        "900",
    )
)
