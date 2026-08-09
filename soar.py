#!/usr/bin/env python3
"""
SOAR-lite: Automated Incident Response Playbook

Trigger source : Wazuh Indexer
Enrichment     : AbuseIPDB, VirusTotal
Response       : iptables DROP
AI Analysis    : Gemini REST API
Notification   : Slack webhook
Storage        : JSON incident log
"""

import os
import subprocess
import time

import ai_report
import config
import decision
import enrichment
import notifier
import response
import storage
import wazuh_client


# ==========================================================
# Project configuration
# ==========================================================

PROJECT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

AI_REPORT_DIRECTORY = os.path.join(
    PROJECT_DIR,
    "reports",
)

# Default cooldown: 15 minutes.
AI_REPORT_COOLDOWN_SECONDS = getattr(
    config,
    "AI_REPORT_COOLDOWN_SECONDS",
    900,
)

# Stores the latest successful or failed Gemini attempt time.
# Format:
#
# {
#     "192.168.80.129": 1785920000.25
# }
#
last_ai_report_time = {}


# ==========================================================
# AI cooldown
# ==========================================================

def should_generate_ai_report(ip_address):
    """
    Return True when the AI cooldown for this IP has expired.
    """

    current_time = time.time()

    previous_time = last_ai_report_time.get(
        ip_address,
        0,
    )

    return (
        current_time - previous_time
        >= AI_REPORT_COOLDOWN_SECONDS
    )


# ==========================================================
# Gemini AI report
# ==========================================================

def generate_ai_incident_report(
    ioc,
    abuse_info,
    vt_info,
    action_taken,
):
    """
    Generate a Gemini incident report.

    Gemini failures must not stop the complete SOAR program.

    AI_REPORT_ALLOWED_IPS is used when defined in config.py.
    Otherwise, AUTO_BLOCK_ALLOWED_IPS is used as fallback.
    """

    ip_address = ioc.get("ip")

    if not ip_address:
        return None

    # Only approved IPs can trigger Gemini requests.
    # This prevents wasting Gemini quota on gateway,
    # server and unrelated public IP alerts.
    ai_allowed_ips = set(
        getattr(
            config,
            "AI_REPORT_ALLOWED_IPS",
            getattr(
                config,
                "AUTO_BLOCK_ALLOWED_IPS",
                set(),
            ),
        )
    )

    if ip_address not in ai_allowed_ips:
        print(
            f"[AI SKIP] {ip_address} is not approved "
            "for automatic AI reporting."
        )

        return None

    # Prevent repeated Gemini calls for the same IP.
    if not should_generate_ai_report(ip_address):
        print(
            f"[AI SKIP] AI request for {ip_address} "
            "is currently in cooldown."
        )

        return None

    extra_context = {
        "wazuh_alert_id": ioc.get("alert_id"),
        "wazuh_rule_description": ioc.get(
            "rule_desc"
        ),
        "monitored_host": ioc.get("host"),
        "response_action": action_taken,
        "abuseipdb": abuse_info,
        "virustotal": vt_info,
    }

    try:
        report_path, _report_text, report_summary = (
            ai_report.generate_ip_report(
                ip_address=ip_address,

                lookback_minutes=getattr(
                    config,
                    "AI_REPORT_LOOKBACK_MINUTES",
                    30,
                ),

                extra_context=extra_context,

                log_file=getattr(
                    config,
                    "SURICATA_LOG_PATH",
                    "/var/log/suricata/eve.json",
                ),

                output_directory=(
                    AI_REPORT_DIRECTORY
                ),
            )
        )

        # Successful request starts the cooldown.
        last_ai_report_time[ip_address] = (
            time.time()
        )

        ioc["ai_report_path"] = str(
            report_path
        )

        ioc["ai_alerts_analyzed"] = (
            report_summary.get(
                "total_alerts",
                0,
            )
        )

        print(
            f"[AI] Report generated for "
            f"{ip_address}"
        )

        print(
            f"[AI] Alerts analyzed: "
            f"{ioc['ai_alerts_analyzed']}"
        )

        print(
            f"[AI] Report saved: "
            f"{report_path}"
        )

        return str(report_path)

    except ai_report.AIReportError as error:
        # Start cooldown even when Gemini fails.
        # This prevents every repeated alert from
        # calling Gemini again.
        last_ai_report_time[ip_address] = (
            time.time()
        )

        print(
            f"[AI ERROR] Gemini report failed: "
            f"{error}"
        )

        print(
            f"[AI COOLDOWN] Further AI requests "
            f"for {ip_address} are temporarily "
            "paused."
        )

    except FileNotFoundError as error:
        last_ai_report_time[ip_address] = (
            time.time()
        )

        print(
            f"[AI ERROR] Suricata log not found: "
            f"{error}"
        )

        print(
            f"[AI COOLDOWN] Further AI requests "
            f"for {ip_address} are temporarily "
            "paused."
        )

    except PermissionError:
        last_ai_report_time[ip_address] = (
            time.time()
        )

        print(
            "[AI ERROR] Permission denied while "
            "reading /var/log/suricata/eve.json"
        )

        print(
            f"[AI COOLDOWN] Further AI requests "
            f"for {ip_address} are temporarily "
            "paused."
        )

    except ValueError as error:
        last_ai_report_time[ip_address] = (
            time.time()
        )

        print(
            f"[AI ERROR] Invalid alert information: "
            f"{error}"
        )

        print(
            f"[AI COOLDOWN] Further AI requests "
            f"for {ip_address} are temporarily "
            "paused."
        )

    except Exception as error:
        # An unexpected AI error must not stop SOAR.
        last_ai_report_time[ip_address] = (
            time.time()
        )

        print(
            f"[AI ERROR] Unexpected error: "
            f"{error}"
        )

        print(
            f"[AI COOLDOWN] Further AI requests "
            f"for {ip_address} are temporarily "
            "paused."
        )

    return None


# ==========================================================
# Firewall checking
# ==========================================================

def is_firewall_blocked(ip_address):
    """
    Check whether an iptables INPUT DROP rule exists.
    """

    result = subprocess.run(
        [
            "iptables",
            "-C",
            "INPUT",
            "-s",
            ip_address,
            "-j",
            "DROP",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    return result.returncode == 0


# ==========================================================
# Alert processing
# ==========================================================

def handle_alert(hit):
    """
    Process one Wazuh alert through the SOAR workflow.
    """

    ioc = wazuh_client.extract_ioc(hit)

    ip_address = ioc.get("ip")
    alert_id = ioc.get("alert_id")

    # Ignore incomplete alerts.
    if not ip_address or not alert_id:
        return

    # Ignore alert IDs that were already processed.
    if storage.is_seen(alert_id):
        return

    storage.mark_seen(alert_id)

    # IPs approved for automatic blocking.
    allowed_ips = set(
        getattr(
            config,
            "AUTO_BLOCK_ALLOWED_IPS",
            set(),
        )
    )

    # IPs that must never be automatically blocked.
    protected_ips = set(
        getattr(
            config,
            "PROTECTED_IPS",
            set(),
        )
    )

    # Compare SOAR state with actual firewall state.
    stored_as_blocked = storage.is_blocked(
        ip_address
    )

    actually_blocked = is_firewall_blocked(
        ip_address
    )

    # Remove stale state when blocked_ips.txt says blocked,
    # but the iptables rule no longer exists.
    if stored_as_blocked and not actually_blocked:
        print(
            f"[STATE FIX] {ip_address} was stored "
            "as blocked but no iptables rule exists. "
            "Removing stale state."
        )

        storage.unmark_blocked(ip_address)

        stored_as_blocked = False

    rule_description = ioc.get(
        "rule_desc",
        "Unknown Wazuh alert",
    )

    monitored_host = ioc.get(
        "host",
        "Unknown host",
    )

    print(
        f"[ALERT] {rule_description} "
        f"from {ip_address} "
        f"on {monitored_host} — enriching..."
    )

    # ======================================================
    # Threat-intelligence enrichment
    # ======================================================

    abuse_info = (
        enrichment.enrich_abuseipdb(
            ip_address
        )
        if getattr(
            config,
            "ABUSEIPDB_KEY",
            "",
        )
        else {}
    )

    vt_info = (
        enrichment.enrich_virustotal(
            ip_address
        )
        if getattr(
            config,
            "VT_KEY",
            "",
        )
        else {}
    )

    # ======================================================
    # Response decision
    # ======================================================

    # Never block protected server/gateway addresses.
    if ip_address in protected_ips:
        action_taken = (
            "Logged only (protected IP)"
        )

        print(
            f"[SAFE MODE] Protected IP not blocked: "
            f"{ip_address}"
        )

    # Do not create duplicate firewall rules.
    elif actually_blocked:
        action_taken = (
            "IP already blocked by iptables"
        )

        # Firewall contains the rule but storage does not.
        # Synchronize the local state.
        if not stored_as_blocked:
            storage.mark_blocked(
                ip_address
            )

        print(
            f"[ACTION] {ip_address} is already "
            "blocked in iptables. Alert will still "
            "be analyzed."
        )

    # Only explicitly approved lab IPs may be blocked.
    elif (
        ip_address in allowed_ips
        and decision.should_block(
            ioc,
            abuse_info,
        )
    ):
        block_success = response.block_ip(
            ip_address
        )

        # Confirm that response.py really created the rule.
        firewall_confirmed = is_firewall_blocked(
            ip_address
        )

        if block_success and firewall_confirmed:
            if not storage.is_blocked(
                ip_address
            ):
                storage.mark_blocked(
                    ip_address
                )

            action_taken = (
                "IP Blocked (iptables DROP)"
            )

            print(
                f"[ACTION] Blocked {ip_address}"
            )

        else:
            action_taken = (
                "Block attempted but failed"
            )

            print(
                f"[ACTION ERROR] Could not block "
                f"{ip_address}. Check response.py."
            )

    else:
        action_taken = (
            "Logged only (automatic blocking not "
            "allowed or below threshold)"
        )

        print(
            f"[SAFE MODE] Logged but not blocked: "
            f"{ip_address}"
        )

    # ======================================================
    # Gemini AI report
    # ======================================================

    report_path = generate_ai_incident_report(
        ioc=ioc,
        abuse_info=abuse_info,
        vt_info=vt_info,
        action_taken=action_taken,
    )

    if report_path:
        action_taken = (
            f"{action_taken} | "
            f"AI report: {report_path}"
        )

    # ======================================================
    # Notification
    # ======================================================

    notifier.notify_all(
        ioc,
        abuse_info,
        vt_info,
        action_taken,
    )

    # ======================================================
    # Incident storage
    # ======================================================

    storage.log_incident(
        ioc,
        abuse_info,
        vt_info,
        action_taken,
    )


# ==========================================================
# Main loop
# ==========================================================

def main():
    """
    Start continuous Wazuh polling.
    """

    os.makedirs(
        config.BASE_DIR,
        exist_ok=True,
    )

    os.makedirs(
        AI_REPORT_DIRECTORY,
        exist_ok=True,
    )

    storage.load_state()

    print(
        "SOAR-lite playbook started. Polling "
        "Wazuh Indexer every "
        f"{config.POLL_INTERVAL_SECONDS}s "
        f"(lookback {config.LOOKBACK_MINUTES}m)..."
    )

    print(
        f"AI reports directory: "
        f"{AI_REPORT_DIRECTORY}"
    )

    try:
        while True:
            try:
                hits = (
                    wazuh_client.fetch_wazuh_alerts()
                )

                for hit in hits:
                    handle_alert(hit)

            except Exception as error:
                # One alert-processing error must not
                # terminate the complete SOAR service.
                print(
                    f"[ERROR] SOAR processing error: "
                    f"{error}"
                )

            time.sleep(
                config.POLL_INTERVAL_SECONDS
            )

    except KeyboardInterrupt:
        print(
            "\n[STOP] SOAR-lite stopped by user."
        )


if __name__ == "__main__":
    main()
