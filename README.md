# 🛡️ AI-Powered Intelligent Automated Security Incident Response Platform (SOAR-lite)

An end-to-end **Security Orchestration, Automation and Response (SOAR)** mini-platform that detects, enriches, scores, and automatically responds to security incidents in real time — with AI-generated incident reports powered by **Gemini 2.5 Flash**.

Built as a hands-on SOC engineering project combining **SIEM, IDS, log analytics, threat intelligence, automated response, and DevSecOps** practices into a single working pipeline.

---

## 📌 Overview

This project simulates a realistic SOC (Security Operations Center) environment where an attacker (Kali Linux) performs an SSH brute-force attack against a target Debian 12 server. The attack is detected by **Wazuh SIEM**, correlated and cross-checked with **Suricata IDS** alerts, enriched using threat intelligence APIs, scored by a decision engine, and automatically remediated — all while pushing logs into an **ELK Stack** for visibility and notifications to **Slack/Email**. An AI-generated summary of the incident is created using the **Gemini 2.5 Flash** model for human-readable reporting.

> ⚠️ Note: No LLM is used for detection, correlation, or decision-making logic — those are fully rule/score based. Gemini 2.5 Flash is used **only** for generating natural-language incident summary reports after the fact.

---

## 🏗️ Architecture

![SOAR-lite Architecture Diagram](./architecture-diagram.png)

### Flow Summary

1. **Threat Actor** — Kali Linux attacker performs reconnaissance (Nmap port/service scans) followed by an SSH brute-force attack (Hydra / Ncrack / Medusa) against the target.
2. **Target Server** — Debian 12 victim server running OpenSSH, Wazuh Agent, and iptables/UFW, generating `auth.log` events. Suricata IDS also inspects network traffic on this host and flags Nmap scan signatures (SYN/Connect/UDP scans, OS fingerprinting).
3. **Monitoring & Log Collection** — Wazuh Agent collects logs, performs file integrity monitoring, and forwards events over a secure channel (TCP 1514) to the Wazuh Manager.
4. **SIEM (Wazuh Manager)** — Performs log analysis, rule correlation, and MITRE ATT&CK mapping, generating **Detected Alerts** for both reconnaissance and brute force activity (e.g., Suricata Nmap scan alert mapped to T1046, and Rule ID 5710 — Multiple SSH Failed Logins mapped to T1110).
5. **Automation Playbook (SOAR-lite, Python)**:
   1. Read alert from Wazuh (API / Alerts JSON)
   2. Extract IoC (Source IP, Host, Rule)
   3. Threat Intelligence lookup / enrichment
   4. Decision engine (score ≥ threshold?)
   5. Response actions (block IP via iptables)
   6. Notifications (Slack / Email)
   7. Incident logging (store & update in SQLite)
6. **Integrations**:
   - **Threat Intelligence APIs** — AbuseIPDB (reputation score), VirusTotal (malicious reports)
   - **Firewall / Response Action** — iptables/UFW auto-blocks the malicious IP
   - **Notification Channels** — Slack Webhook, Email (SMTP)
7. **Incident Storage & Logging** — All incident data (time, source IP, host, attack type, MITRE technique, score, action taken, status) stored in SQLite/JSON.
8. **Visibility / Dashboard** — Wazuh Dashboard + custom ELK (Elasticsearch, Logstash, Kibana) dashboards for incident summaries, attack trends, and response actions.
9. **AI Reporting Layer** — Gemini 2.5 Flash converts structured incident data into a clear, human-readable incident report for analysts/management.

---

## ⚙️ Tech Stack

| Category | Technology |
|---|---|
| Automation / Playbook | Python |
| SIEM | Wazuh SIEM |
| IDS | Suricata IDS |
| Log Analytics | Elasticsearch, Logstash, Kibana (ELK Stack) |
| Threat Intelligence | VirusTotal API, AbuseIPDB API |
| Response / Firewall | iptables |
| Storage | SQLite |
| Notifications | Slack API, SMTP (Email) |
| AI Reporting | Gemini 2.5 Flash |
| CI/CD & Version Control | Jenkins, Git, GitHub |
| Attack Simulation | Kali Linux (Nmap, Hydra / Ncrack / Medusa) |
| OS / Infra | Debian 12 (x2 servers), VMware Workstation |

---

## 🖥️ Lab Environment

| Machine | Role | OS |
|---|---|---|
| Server 1 | Target host — OpenSSH, Wazuh Agent, iptables, Suricata | Debian 12 |
| Server 2 | ELK Stack (Elasticsearch, Logstash, Kibana) | Debian 12 |
| Attacker | Attack simulation (SSH brute force) | Kali Linux |

All machines were provisioned as separate VMs on **VMware Workstation**, networked together to simulate a realistic segmented SOC lab.

---

## 🚀 Key Features

- ✅ Real-time log collection & correlation via Wazuh SIEM
- ✅ Network-based threat detection via Suricata IDS, including **Nmap scan detection** (SYN scan, Connect scan, service/OS fingerprinting attempts) via custom IDS signatures
- ✅ Instant Slack + Email alerting for reconnaissance activity (Nmap scans) as well as brute-force incidents
- ✅ MITRE ATT&CK technique mapping for detected alerts (e.g., T1046 — Network Service Discovery, T1110 — Brute Force)
- ✅ Automated IoC extraction from raw alerts
- ✅ Threat intelligence enrichment (AbuseIPDB reputation score, VirusTotal reports)
- ✅ Configurable scoring/decision engine for auto-response threshold
- ✅ Automated malicious IP blocking via iptables
- ✅ Real-time Slack and Email notifications
- ✅ Centralized incident logging (SQLite/JSON) with full audit trail
- ✅ ELK-based dashboards for attack trend visibility
- ✅ AI-generated (Gemini 2.5 Flash) human-readable incident summary reports
- ✅ Jenkins-driven DevSecOps pipeline for playbook testing/deployment

---

## 📂 Project Structure

```
soar-lite/
├── playbook/
│   ├── read_alert.py           # Fetch alerts from Wazuh API
│   ├── extract_ioc.py          # Extract Source IP / Host / Rule from alert
│   ├── threat_intel.py         # AbuseIPDB + VirusTotal enrichment
│   ├── decision_engine.py      # Scoring & threshold-based decision logic
│   ├── response_action.py      # iptables auto-block execution
│   ├── notify.py               # Slack + SMTP email notifications
│   └── incident_logger.py      # SQLite incident storage & updates
│   └── soar.py                 # orchestrating all the files
├── Dockerfile            # for Generating Docker Image   
├── ai_report/
│   └── ai_report.py      # Gemini 2.5 Flash incident report generation
├── suricata/
│   ├── suricata.yaml            # IDS rules & config
│   └── nmap-detection.rules     # Custom rules for Nmap scan detection
├── wazuh/
│   └── custom_rules.xml        # Custom Wazuh detection rules
├── elk/
│   ├── logstash.conf
│   └── kibana_dashboards/
├── jenkins/
│   └── Jenkinsfile             # CI/CD pipeline for the playbook
├── db/
│   └── incidents.db            # SQLite incident database
├── requirements.txt
└── README.md
```

---

## 🔧 Setup & Installation

### Prerequisites
- 2x Debian 12 servers (target + ELK stack)
- 1x Kali Linux VM (attack simulation)
- Python 3.10+
- Wazuh Manager & Agent installed
- Suricata IDS installed on target
- ELK Stack (Elasticsearch, Logstash, Kibana) on the second server
- API keys: AbuseIPDB, VirusTotal, Gemini API, Slack Webhook, SMTP credentials

### Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/AI-Powered-Intelligent-Automated-Security-Incident-Response-Platform-SOAR-lite.git
cd AI-Powered-Intelligent-Automated-Security-Incident-Response-Platform-SOAR-lite

# Install Python dependencies
pip install -r requirements.txt

# Configure environment variables / secrets
cp .env.example .env
# Fill in: ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, GEMINI_API_KEY,
#          SLACK_WEBHOOK_URL, SMTP_HOST, SMTP_USER, SMTP_PASS,
#          WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASS

# Run the playbook (triggered manually or via Wazuh active response)
python3 playbook/main.py
```

### Attack Simulation (from Kali Linux)

```bash
# Reconnaissance — Nmap scan (triggers Suricata Nmap-detection rules)
nmap -sS -sV -O <target-ip>

# SSH brute force (triggers Wazuh Rule 5710)
hydra -l root -P rockyou.txt ssh://<target-ip>
```

The Nmap scan is picked up by Suricata's port-scan/service-discovery signatures and forwarded to Wazuh, which raises an alert and pushes a Slack/Email notification for the reconnaissance attempt. The subsequent SSH brute-force attempt generates multiple failed SSH login attempts on the target, which Wazuh correlates into a single alert (Rule ID 5710) that triggers the full SOAR-lite playbook (enrichment → scoring → auto-block → notification → logging).

---

## 🧠 MITRE ATT&CK Mapping

| Technique ID | Name | Detection Source |
|---|---|---|
| T1046 | Network Service Discovery (Nmap scan) | Suricata IDS |
| T1110 | Brute Force | Wazuh (SSH failed logins) + Suricata |

The playbook tags every stored incident with its mapped MITRE technique for traceability and reporting.

---

## 📊 Sample Incident Record

| Time | Source IP | Host | Attack Type | MITRE Technique | Score | Action Taken | Status |
|---|---|---|---|---|---|---|---|
| 2025-05-27 10:28:02 | 192.168.1.105 | debian-target | Nmap Port/Service Scan | T1046 (Network Service Discovery) | 40 | Slack + Email Alert Sent | Logged |
| 2025-05-27 10:30:15 | 192.168.1.105 | debian-target | SSH Brute Force | T1110 (Brute Force) | 95 | IP Blocked | Success |

---

## 🤖 AI-Powered Incident Reporting

Once an incident is logged, the platform sends the structured incident record (source IP, host, MITRE technique, score, action taken, timestamps, TI enrichment results) to **Gemini 2.5 Flash**, which generates a concise, analyst-friendly narrative summary of the incident — used for daily SOC reports and management updates. The AI is used strictly for **report generation/summarization**, not for detection or response decisions.

---

## 🔄 DevSecOps / CI-CD

A **Jenkins** pipeline automates linting, testing, and deployment of the playbook code on every push to GitHub, ensuring the automation logic stays reliable as new detection rules and integrations are added.

---

## 📈 Future Enhancements

- Auto-unblock IPs after a cooldown period
- Multi-host / multi-agent correlation for distributed attacks
- Integration with SOAR platforms like TheHive/Cortex
- Expanded MITRE ATT&CK technique coverage (beyond brute force)
- Web-based dashboard for playbook management

---

## 👤 Author

Built as a hands-on SOC Analyst / Blue Team portfolio project demonstrating end-to-end detection-to-response automation, threat intelligence integration, and DevSecOps practices.

---

## 📜 License

This project is intended for educational and portfolio purposes. Use responsibly in isolated lab environments only.
