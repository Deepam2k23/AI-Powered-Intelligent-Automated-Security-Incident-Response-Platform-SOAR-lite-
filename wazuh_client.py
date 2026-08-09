"""Step 1 & 2: Read alerts from Wazuh Indexer and extract IoCs."""

from datetime import datetime, timedelta

import requests
import urllib3

import config

urllib3.disable_warnings()


def fetch_wazuh_alerts():
    """Query the Wazuh Indexer for recent alerts matching monitored rules/groups."""
    since = (datetime.utcnow() - timedelta(minutes=config.LOOKBACK_MINUTES)).isoformat() + "Z"
    query = {
        "size": 100,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [{"range": {"timestamp": {"gte": since}}}],
                "should": [
                    {"terms": {"rule.id": config.MONITORED_RULE_IDS}},
                    {"terms": {"rule.groups": config.MONITORED_RULE_GROUPS}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    try:
        r = requests.get(
            f"{config.WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
            auth=(config.WAZUH_INDEXER_USER, config.WAZUH_INDEXER_PASS),
            json=query,
            verify=False,
            timeout=15,
        )
        r.raise_for_status()
        return r.json().get("hits", {}).get("hits", [])
    except Exception as e:
        print(f"[ERROR] Wazuh indexer query failed: {e}")
        return []


def extract_ioc(hit):
    """Pull out source IP, host, rule info, and MITRE technique from a Wazuh alert doc."""
    src = hit.get("_source", {})
    rule = src.get("rule", {})
    ip = (
        src.get("data", {}).get("srcip")
        or src.get("data", {}).get("src_ip")
        or src.get("GeoLocation", {}).get("ip")
    )
    host = src.get("agent", {}).get("name", "unknown")
    return {
        "alert_id": hit.get("_id"),
        "ip": ip,
        "host": host,
        "rule_id": rule.get("id"),
        "rule_desc": rule.get("description"),
        "mitre": rule.get("mitre", {}).get("technique", []),
        "timestamp": src.get("timestamp"),
    }
