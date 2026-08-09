"""Step 3: Threat intelligence lookups (AbuseIPDB, VirusTotal)."""

import requests

import config


def enrich_abuseipdb(ip):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": config.ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        d = r.json().get("data", {})
        return {
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "total_reports": d.get("totalReports"),
        }
    except Exception as e:
        return {"abuse_score": 0, "error": str(e)}


def enrich_virustotal(ip):
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": config.VT_KEY},
            timeout=10,
        )
        return r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    except Exception as e:
        return {"error": str(e)}
