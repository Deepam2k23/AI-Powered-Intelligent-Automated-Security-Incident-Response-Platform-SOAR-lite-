"""Notifications: Slack webhook and formatted SMTP email."""

import html
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests

import config


# ==========================================================
# Common formatting helpers
# ==========================================================

def _safe_text(value, default="Not available"):
    """
    Convert a value into safe readable text.
    """

    if value is None:
        return default

    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned if cleaned else default

    if isinstance(value, (list, tuple, set)):
        if not value:
            return default

        return ", ".join(
            str(item)
            for item in value
        )

    if isinstance(value, dict):
        if not value:
            return default

        return ", ".join(
            f"{key}: {item}"
            for key, item in value.items()
        )

    return str(value)


def _current_time():
    """
    Return local server time with timezone.
    """

    return datetime.now().astimezone().strftime(
        "%d %B %Y, %I:%M:%S %p %Z"
    )


def _extract_virustotal_stats(vt_info):
    """
    Extract VirusTotal statistics from different possible
    response formats.
    """

    if not isinstance(vt_info, dict):
        return {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
        }

    # Format 1:
    # {
    #     "malicious": 2,
    #     "suspicious": 1,
    #     ...
    # }
    if any(
        key in vt_info
        for key in (
            "malicious",
            "suspicious",
            "harmless",
            "undetected",
        )
    ):
        return {
            "malicious": vt_info.get(
                "malicious",
                0,
            ),
            "suspicious": vt_info.get(
                "suspicious",
                0,
            ),
            "harmless": vt_info.get(
                "harmless",
                0,
            ),
            "undetected": vt_info.get(
                "undetected",
                0,
            ),
        }

    # Format 2:
    # {
    #     "last_analysis_stats": {...}
    # }
    direct_stats = vt_info.get(
        "last_analysis_stats",
        {},
    )

    if isinstance(direct_stats, dict):
        if direct_stats:
            return {
                "malicious": direct_stats.get(
                    "malicious",
                    0,
                ),
                "suspicious": direct_stats.get(
                    "suspicious",
                    0,
                ),
                "harmless": direct_stats.get(
                    "harmless",
                    0,
                ),
                "undetected": direct_stats.get(
                    "undetected",
                    0,
                ),
            }

    # Format 3:
    # {
    #     "data": {
    #         "attributes": {
    #             "last_analysis_stats": {...}
    #         }
    #     }
    nested_stats = (
        vt_info
        .get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )

    return {
        "malicious": nested_stats.get(
            "malicious",
            0,
        ),
        "suspicious": nested_stats.get(
            "suspicious",
            0,
        ),
        "harmless": nested_stats.get(
            "harmless",
            0,
        ),
        "undetected": nested_stats.get(
            "undetected",
            0,
        ),
    }


def _determine_severity(
    ioc,
    abuse_info,
    vt_info,
    action_taken,
):
    """
    Assign an easy-to-understand incident severity.
    """

    description = str(
        ioc.get("rule_desc", "")
    ).lower()

    action = str(
        action_taken or ""
    ).lower()

    try:
        abuse_score = int(
            abuse_info.get(
                "abuse_score",
                0,
            )
            or 0
        )
    except (TypeError, ValueError):
        abuse_score = 0

    vt_stats = _extract_virustotal_stats(
        vt_info
    )

    try:
        vt_malicious = int(
            vt_stats.get(
                "malicious",
                0,
            )
            or 0
        )
    except (TypeError, ValueError):
        vt_malicious = 0

    if (
        "blocked" in action
        or abuse_score >= 75
        or vt_malicious >= 5
    ):
        return "CRITICAL"

    if (
        abuse_score >= 50
        or vt_malicious >= 1
        or "authentication failed" in description
        or "maximum authentication" in description
        or "nmap" in description
        or "scan" in description
    ):
        return "HIGH"

    if abuse_score >= 20:
        return "MEDIUM"

    return "LOW"


def _action_status(action_taken):
    """
    Return a short response status.
    """

    action = str(
        action_taken or ""
    ).lower()

    if "already blocked" in action:
        return "ALREADY BLOCKED"

    if "blocked" in action:
        return "IP BLOCKED"

    if "failed" in action:
        return "RESPONSE FAILED"

    if "protected" in action:
        return "PROTECTED IP — LOGGED ONLY"

    return "LOGGED AND MONITORED"


def _recommended_actions(
    severity,
    action_taken,
):
    """
    Build simple analyst recommendations.
    """

    action = str(
        action_taken or ""
    ).lower()

    recommendations = [
        "Verify whether the source IP belongs to an authorized user or system.",
        "Review Wazuh, Suricata and authentication logs for related activity.",
        "Check whether other systems received similar traffic from this IP.",
    ]

    if "blocked" in action:
        recommendations.append(
            "Keep the IP blocked until the investigation is complete."
        )
    else:
        recommendations.append(
            "Consider temporary blocking if malicious activity is confirmed."
        )

    if severity in {
        "CRITICAL",
        "HIGH",
    }:
        recommendations.append(
            "Escalate the incident to the security administrator."
        )

    return recommendations


# ==========================================================
# Plain-text email
# ==========================================================

def _build_plain_text(
    ioc,
    abuse_info,
    vt_info,
    action_taken,
):
    severity = _determine_severity(
        ioc,
        abuse_info,
        vt_info,
        action_taken,
    )

    status = _action_status(
        action_taken
    )

    vt_stats = _extract_virustotal_stats(
        vt_info
    )

    recommendations = _recommended_actions(
        severity,
        action_taken,
    )

    recommendation_text = "\n".join(
        f"{index}. {recommendation}"
        for index, recommendation in enumerate(
            recommendations,
            start=1,
        )
    )

    ai_report_path = ioc.get(
        "ai_report_path"
    )

    ai_alerts_analyzed = ioc.get(
        "ai_alerts_analyzed"
    )

    ai_section = ""

    if ai_report_path:
        ai_section = (
            "\n\nAI INCIDENT REPORT\n"
            "------------------------------\n"
            f"Report Path      : {ai_report_path}\n"
            f"Alerts Analyzed  : "
            f"{_safe_text(ai_alerts_analyzed, '0')}"
        )

    return f"""
SOAR-LITE SECURITY INCIDENT ALERT
==================================

INCIDENT SUMMARY
------------------------------
Severity         : {severity}
Status           : {status}
Detection Time   : {_current_time()}

INCIDENT DETAILS
------------------------------
Alert            : {_safe_text(ioc.get("rule_desc"))}
Source IP        : {_safe_text(ioc.get("ip"))}
Target Host      : {_safe_text(ioc.get("host"))}
Wazuh Rule ID    : {_safe_text(ioc.get("rule_id"))}
Alert ID         : {_safe_text(ioc.get("alert_id"))}
MITRE Technique  : {_safe_text(ioc.get("mitre"))}

THREAT INTELLIGENCE
------------------------------
AbuseIPDB Score  : {_safe_text(abuse_info.get("abuse_score"), "0")}
Total Reports    : {_safe_text(abuse_info.get("total_reports"), "0")}
Country          : {_safe_text(abuse_info.get("country"))}

VirusTotal:
  Malicious      : {vt_stats["malicious"]}
  Suspicious     : {vt_stats["suspicious"]}
  Harmless       : {vt_stats["harmless"]}
  Undetected     : {vt_stats["undetected"]}

AUTOMATED RESPONSE
------------------------------
{_safe_text(action_taken)}
{ai_section}

RECOMMENDED ACTIONS
------------------------------
{recommendation_text}

IMPORTANT
------------------------------
This is an automated SOAR notification.
Validate the alert and AI-generated findings before taking
additional operational action.
""".strip()


# ==========================================================
# HTML email
# ==========================================================

def _build_html(
    ioc,
    abuse_info,
    vt_info,
    action_taken,
):
    severity = _determine_severity(
        ioc,
        abuse_info,
        vt_info,
        action_taken,
    )

    status = _action_status(
        action_taken
    )

    vt_stats = _extract_virustotal_stats(
        vt_info
    )

    recommendations = _recommended_actions(
        severity,
        action_taken,
    )

    severity_colors = {
        "CRITICAL": "#b91c1c",
        "HIGH": "#dc2626",
        "MEDIUM": "#d97706",
        "LOW": "#2563eb",
    }

    severity_color = severity_colors.get(
        severity,
        "#4b5563",
    )

    recommendation_html = "".join(
        f"<li>{html.escape(item)}</li>"
        for item in recommendations
    )

    ai_report_path = ioc.get(
        "ai_report_path"
    )

    ai_alerts_analyzed = ioc.get(
        "ai_alerts_analyzed"
    )

    ai_section = ""

    if ai_report_path:
        ai_section = f"""
        <div class="section">
            <h2>AI Incident Report</h2>

            <div class="row">
                <span class="label">Report location</span>
                <span class="value">
                    {html.escape(str(ai_report_path))}
                </span>
            </div>

            <div class="row">
                <span class="label">Alerts analyzed</span>
                <span class="value">
                    {html.escape(
                        _safe_text(
                            ai_alerts_analyzed,
                            "0",
                        )
                    )}
                </span>
            </div>
        </div>
        """

    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">

    <style>
        body {{
            margin: 0;
            padding: 20px;
            background: #f3f4f6;
            font-family:
                Arial,
                Helvetica,
                sans-serif;
            color: #1f2937;
        }}

        .container {{
            max-width: 760px;
            margin: auto;
            background: #ffffff;
            border-radius: 10px;
            overflow: hidden;
            border: 1px solid #d1d5db;
        }}

        .header {{
            background: #111827;
            color: #ffffff;
            padding: 24px;
        }}

        .header h1 {{
            margin: 0 0 8px;
            font-size: 24px;
        }}

        .header p {{
            margin: 0;
            color: #d1d5db;
        }}

        .severity {{
            display: inline-block;
            margin-top: 16px;
            padding: 8px 14px;
            border-radius: 20px;
            background: {severity_color};
            color: #ffffff;
            font-weight: bold;
        }}

        .content {{
            padding: 24px;
        }}

        .section {{
            margin-bottom: 24px;
            padding: 18px;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
        }}

        .section h2 {{
            margin: 0 0 15px;
            font-size: 18px;
            color: #111827;
            border-bottom: 1px solid #e5e7eb;
            padding-bottom: 10px;
        }}

        .row {{
            display: table;
            width: 100%;
            margin: 9px 0;
        }}

        .label {{
            display: table-cell;
            width: 190px;
            font-weight: bold;
            color: #4b5563;
        }}

        .value {{
            display: table-cell;
            word-break: break-word;
        }}

        .status-box {{
            background: #f9fafb;
            border-left: 5px solid {severity_color};
            padding: 14px;
            font-weight: bold;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th,
        td {{
            padding: 10px;
            border: 1px solid #e5e7eb;
            text-align: left;
        }}

        th {{
            background: #f9fafb;
        }}

        li {{
            margin: 8px 0;
        }}

        .notice {{
            background: #fff7ed;
            border: 1px solid #fed7aa;
            padding: 14px;
            border-radius: 8px;
        }}

        .footer {{
            background: #f9fafb;
            padding: 18px 24px;
            color: #6b7280;
            font-size: 12px;
        }}
    </style>
</head>

<body>
    <div class="container">
        <div class="header">
            <h1>SOAR-lite Security Incident Alert</h1>

            <p>
                Automated security detection and response
                notification
            </p>

            <div class="severity">
                {html.escape(severity)} SEVERITY
            </div>
        </div>

        <div class="content">
            <div class="section">
                <h2>Incident Summary</h2>

                <div class="status-box">
                    Status: {html.escape(status)}
                </div>

                <div class="row">
                    <span class="label">Detection time</span>
                    <span class="value">
                        {html.escape(_current_time())}
                    </span>
                </div>
            </div>

            <div class="section">
                <h2>Incident Details</h2>

                <div class="row">
                    <span class="label">Alert</span>
                    <span class="value">
                        {html.escape(
                            _safe_text(
                                ioc.get("rule_desc")
                            )
                        )}
                    </span>
                </div>

                <div class="row">
                    <span class="label">Source IP</span>
                    <span class="value">
                        {html.escape(
                            _safe_text(
                                ioc.get("ip")
                            )
                        )}
                    </span>
                </div>

                <div class="row">
                    <span class="label">Target host</span>
                    <span class="value">
                        {html.escape(
                            _safe_text(
                                ioc.get("host")
                            )
                        )}
                    </span>
                </div>

                <div class="row">
                    <span class="label">Wazuh rule ID</span>
                    <span class="value">
                        {html.escape(
                            _safe_text(
                                ioc.get("rule_id")
                            )
                        )}
                    </span>
                </div>

                <div class="row">
                    <span class="label">Alert ID</span>
                    <span class="value">
                        {html.escape(
                            _safe_text(
                                ioc.get("alert_id")
                            )
                        )}
                    </span>
                </div>

                <div class="row">
                    <span class="label">MITRE technique</span>
                    <span class="value">
                        {html.escape(
                            _safe_text(
                                ioc.get("mitre")
                            )
                        )}
                    </span>
                </div>
            </div>

            <div class="section">
                <h2>Threat Intelligence</h2>

                <div class="row">
                    <span class="label">AbuseIPDB score</span>
                    <span class="value">
                        {html.escape(
                            _safe_text(
                                abuse_info.get(
                                    "abuse_score"
                                ),
                                "0",
                            )
                        )}
                    </span>
                </div>

                <div class="row">
                    <span class="label">Total reports</span>
                    <span class="value">
                        {html.escape(
                            _safe_text(
                                abuse_info.get(
                                    "total_reports"
                                ),
                                "0",
                            )
                        )}
                    </span>
                </div>

                <div class="row">
                    <span class="label">Country</span>
                    <span class="value">
                        {html.escape(
                            _safe_text(
                                abuse_info.get(
                                    "country"
                                )
                            )
                        )}
                    </span>
                </div>

                <br>

                <table>
                    <tr>
                        <th>VirusTotal result</th>
                        <th>Count</th>
                    </tr>

                    <tr>
                        <td>Malicious</td>
                        <td>
                            {vt_stats["malicious"]}
                        </td>
                    </tr>

                    <tr>
                        <td>Suspicious</td>
                        <td>
                            {vt_stats["suspicious"]}
                        </td>
                    </tr>

                    <tr>
                        <td>Harmless</td>
                        <td>
                            {vt_stats["harmless"]}
                        </td>
                    </tr>

                    <tr>
                        <td>Undetected</td>
                        <td>
                            {vt_stats["undetected"]}
                        </td>
                    </tr>
                </table>
            </div>

            <div class="section">
                <h2>Automated Response</h2>

                <div class="status-box">
                    {html.escape(
                        _safe_text(action_taken)
                    )}
                </div>
            </div>

            {ai_section}

            <div class="section">
                <h2>Recommended Actions</h2>

                <ol>
                    {recommendation_html}
                </ol>
            </div>

            <div class="notice">
                <strong>Important:</strong>
                This email was generated automatically.
                Validate the alert and any AI-generated
                conclusions before taking additional action.
            </div>
        </div>

        <div class="footer">
            SOAR-lite Automated Incident Response System
        </div>
    </div>
</body>
</html>
"""


# ==========================================================
# Slack notification
# ==========================================================

def notify_slack(
    ioc,
    abuse_info,
    vt_info,
    action_taken,
):
    """
    Send a short formatted Slack notification.
    """

    if not getattr(
        config,
        "SLACK_WEBHOOK",
        "",
    ):
        print(
            "[SKIP] Slack not configured."
        )
        return

    severity = _determine_severity(
        ioc,
        abuse_info,
        vt_info,
        action_taken,
    )

    text = (
        f":rotating_light: *SOAR Security Alert*\n"
        f"*Severity:* {severity}\n"
        f"*Alert:* {_safe_text(ioc.get('rule_desc'))}\n"
        f"*Source IP:* {_safe_text(ioc.get('ip'))}\n"
        f"*Host:* {_safe_text(ioc.get('host'))}\n"
        f"*Action:* {_safe_text(action_taken)}\n"
        f"*Time:* {_current_time()}"
    )

    try:
        response = requests.post(
            config.SLACK_WEBHOOK,
            json={
                "text": text,
            },
            timeout=10,
        )

        response.raise_for_status()

        print(
            "[SLACK] Alert notification sent."
        )

    except requests.RequestException as error:
        print(
            f"[ERROR] Slack notification failed: "
            f"{error}"
        )


# ==========================================================
# Email notification
# ==========================================================

def notify_email(
    ioc,
    abuse_info,
    vt_info,
    action_taken,
):
    """
    Send a readable HTML email with plain-text fallback.
    """

    smtp_user = getattr(
        config,
        "SMTP_USER",
        "",
    )

    smtp_password = getattr(
        config,
        "SMTP_PASS",
        "",
    )

    email_to = getattr(
        config,
        "EMAIL_TO",
        "",
    )

    if not (
        smtp_user
        and smtp_password
        and email_to
    ):
        print(
            "[SKIP] Email not configured "
            "(missing SMTP_USER, SMTP_PASS "
            "or EMAIL_TO)."
        )

        return

    recipients = [
        address.strip()
        for address in email_to.split(",")
        if address.strip()
    ]

    if not recipients:
        print(
            "[SKIP] Email recipient list is empty."
        )
        return

    sender = (
        getattr(
            config,
            "EMAIL_FROM",
            "",
        )
        or smtp_user
    )

    severity = _determine_severity(
        ioc,
        abuse_info,
        vt_info,
        action_taken,
    )

    status = _action_status(
        action_taken
    )

    source_ip = _safe_text(
        ioc.get("ip"),
        "Unknown IP",
    )

    alert_description = _safe_text(
        ioc.get("rule_desc"),
        "Security Alert",
    )

    message = MIMEMultipart(
        "alternative"
    )

    message["Subject"] = (
        f"[{severity}] [SOAR-lite] "
        f"{status} - {source_ip}"
    )

    message["From"] = sender
    message["To"] = ", ".join(recipients)

    plain_body = _build_plain_text(
        ioc,
        abuse_info,
        vt_info,
        action_taken,
    )

    html_body = _build_html(
        ioc,
        abuse_info,
        vt_info,
        action_taken,
    )

    message.attach(
        MIMEText(
            plain_body,
            "plain",
            "utf-8",
        )
    )

    message.attach(
        MIMEText(
            html_body,
            "html",
            "utf-8",
        )
    )

    try:
        with smtplib.SMTP(
            config.SMTP_HOST,
            config.SMTP_PORT,
            timeout=20,
        ) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()

            server.login(
                smtp_user,
                smtp_password,
            )

            server.sendmail(
                sender,
                recipients,
                message.as_string(),
            )

        print(
            f"[EMAIL] {severity} alert sent to "
            f"{', '.join(recipients)}: "
            f"{alert_description}"
        )

    except smtplib.SMTPAuthenticationError:
        print(
            "[ERROR] Email authentication failed. "
            "For Gmail, use a Google App Password."
        )

    except smtplib.SMTPException as error:
        print(
            f"[ERROR] SMTP notification failed: "
            f"{error}"
        )

    except OSError as error:
        print(
            f"[ERROR] Email connection failed: "
            f"{error}"
        )


# ==========================================================
# Send all notifications
# ==========================================================

def notify_all(
    ioc,
    abuse_info,
    vt_info,
    action_taken,
):
    """
    Send all configured notification channels.

    Failure in one channel must not stop another channel.
    """

    notify_slack(
        ioc,
        abuse_info,
        vt_info,
        action_taken,
    )

    notify_email(
        ioc,
        abuse_info,
        vt_info,
        action_taken,
    )
