"""Incident logging and local state management."""

import json
import os
from datetime import datetime

import config


blocked = set()
seen_alert_ids = set()


def _ensure_parent_directory(file_path):
    directory = os.path.dirname(file_path)

    if directory:
        os.makedirs(directory, exist_ok=True)


def load_state():
    """Load blocked IPs and processed alert IDs from files."""

    blocked.clear()
    seen_alert_ids.clear()

    if os.path.exists(config.BLOCKED_IPS_FILE):
        with open(
            config.BLOCKED_IPS_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            blocked.update(
                line.strip()
                for line in file
                if line.strip()
            )

    if os.path.exists(config.SEEN_ALERTS_FILE):
        with open(
            config.SEEN_ALERTS_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            seen_alert_ids.update(
                line.strip()
                for line in file
                if line.strip()
            )


def is_blocked(ip):
    """Check whether an IP is stored as blocked."""

    return bool(ip) and ip in blocked


def is_seen(alert_id):
    """Check whether an alert has already been processed."""

    return bool(alert_id) and alert_id in seen_alert_ids


def mark_blocked(ip):
    """Add an IP to memory and blocked_ips.txt."""

    if not ip:
        return False

    if ip in blocked:
        return True

    _ensure_parent_directory(config.BLOCKED_IPS_FILE)

    blocked.add(ip)

    with open(
        config.BLOCKED_IPS_FILE,
        "a",
        encoding="utf-8",
    ) as file:
        file.write(ip + "\n")

    return True


def unmark_blocked(ip):
    """Remove an IP from memory and blocked_ips.txt."""

    if not ip:
        return False

    blocked.discard(ip)

    if not os.path.exists(config.BLOCKED_IPS_FILE):
        return True

    with open(
        config.BLOCKED_IPS_FILE,
        "r",
        encoding="utf-8",
    ) as source:
        remaining_ips = {
            line.strip()
            for line in source
            if line.strip() and line.strip() != ip
        }

    temporary_file = config.BLOCKED_IPS_FILE + ".tmp"

    with open(
        temporary_file,
        "w",
        encoding="utf-8",
    ) as destination:
        for blocked_ip in sorted(remaining_ips):
            destination.write(blocked_ip + "\n")

    os.replace(
        temporary_file,
        config.BLOCKED_IPS_FILE,
    )

    return True


def mark_seen(alert_id):
    """Store an alert ID so it is not processed twice."""

    if not alert_id:
        return False

    if alert_id in seen_alert_ids:
        return True

    _ensure_parent_directory(config.SEEN_ALERTS_FILE)

    seen_alert_ids.add(alert_id)

    with open(
        config.SEEN_ALERTS_FILE,
        "a",
        encoding="utf-8",
    ) as file:
        file.write(alert_id + "\n")

    return True


def log_incident(
    ioc,
    abuse_info,
    vt_info,
    action_taken,
):
    """Append an incident record to incidents.log."""

    _ensure_parent_directory(config.INCIDENT_LOG)

    record = {
        "time": datetime.now().isoformat(),
        "alert_id": ioc.get("alert_id", ""),
        "source_ip": ioc.get("ip", ""),
        "host": ioc.get("host", ""),
        "rule_id": ioc.get("rule_id", ""),
        "rule_desc": ioc.get("rule_desc", ""),
        "mitre": ioc.get("mitre", []),
        "abuse_score": abuse_info.get("abuse_score"),
        "vt_stats": vt_info,
        "action_taken": action_taken,
        "ai_report_path": ioc.get("ai_report_path"),
        "ai_alerts_analyzed": ioc.get(
            "ai_alerts_analyzed"
        ),
        "status": "Success",
    }

    with open(
        config.INCIDENT_LOG,
        "a",
        encoding="utf-8",
    ) as file:
        file.write(json.dumps(record) + "\n")
