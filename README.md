# AI-Powered Intelligent Automated Security Incident Response Platform (SOAR-lite)

An AI-powered Security Operations Center (SOC) automation platform that combines **Wazuh SIEM, Suricata IDS, Elastic Stack, Threat Intelligence APIs, Python-based incident response automation, and AI-assisted reporting** to detect, analyze, enrich, prioritize, contain, and report security incidents.

The project is designed as a practical SOC lab environment using **VMware Workstation and Debian 12**, with **Kali Linux** used to simulate real-world cyberattacks.

---

## 📌 Project Overview

The platform automates the security incident lifecycle from **attack detection to incident reporting and response**.

A typical workflow is:

```text
Kali Linux
    │
    │ Simulated Attack
    ▼
Target / Monitored Host
    │
    │ Logs
    ▼
Wazuh Agent + Suricata IDS
    │
    │ Alerts / Events
    ▼
Wazuh Manager
    │
    │ Alert JSON / API
    ▼
Python SOAR Automation Engine
    │
    ├── Alert Processing
    ├── IOC Extraction
    ├── Threat Intelligence Enrichment
    │      ├── VirusTotal API
    │      └── AbuseIPDB API
    │
    ├── AI-based Analysis / Risk Scoring
    ├── Decision Engine
    │
    ├── Automated Response
    │      └── iptables / UFW
    │
    ├── Incident Logging
    │      └── SQLite
    │
    ├── AI Incident Report Generation
    │
    └── Notifications
           ├── Slack
           └── SMTP Email

                │
                ▼
        Elasticsearch
                │
             Logstash
                │
             Kibana
                │
                ▼
       Security Dashboards
       Threat Hunting / Analytics
```

---

## 🏗️ Architecture

The core platform is deployed using **three Debian 12 virtual machines on VMware Workstation**.

### VM-1 — ELK Server

**Operating System:** Debian 12

Dedicated to centralized security log management and visualization.

Components:

- Elasticsearch
- Logstash
- Kibana

Responsibilities:

- Receive and process security logs
- Store centralized security events
- Index security data
- Provide dashboards and visualization
- Support threat hunting and log analysis

---

### VM-2 — Wazuh + Suricata Server

**Operating System:** Debian 12

This VM provides the primary security monitoring and detection layer.

Components:

- Wazuh Manager
- Wazuh Agent
- Suricata IDS

Responsibilities:

- Collect security logs
- Monitor authentication and system events
- Detect network-based attacks
- Generate IDS alerts
- Correlate security events
- Map events to MITRE ATT&CK techniques
- Forward alerts to the SOAR automation engine

---

### VM-3 — SOAR + AI Automation Server

**Operating System:** Debian 12

This VM hosts the Python-based automated incident response platform.

Components:

- Python SOAR automation engine
- Decision engine
- IOC extraction
- Threat intelligence enrichment
- AI-based analysis and reporting
- SQLite incident database
- Slack notification integration
- SMTP email integration
- Automated response actions

Responsibilities:

- Read Wazuh alerts
- Extract Indicators of Compromise (IOCs)
- Query external threat intelligence services
- Calculate incident risk
- Make response decisions
- Block malicious IP addresses
- Store incident information
- Generate AI-assisted incident reports
- Notify SOC/security personnel

---

### Attack Simulation — Kali Linux

**Operating System:** Kali Linux

Kali Linux is used to simulate real-world attacks against the monitored environment.

Example tools include:

- Hydra
- Ncrack
- Medusa
- Nmap
- Other penetration-testing/security tools

Example attack:

```text
Kali Linux
     │
     │ SSH Brute Force
     ▼
Debian Target Server
     │
     ▼
Wazuh + Suricata
     │
     ▼
SOAR Automation
     │
     ▼
Threat Intelligence
     │
     ▼
Risk Decision
     │
     ▼
iptables / UFW
     │
     ▼
Malicious IP Blocked
```

---

## 🔄 Incident Response Workflow

### 1. Attack Simulation

Kali Linux generates a controlled security event against the monitored target.

For example:

```text
SSH Brute Force Attack
```

### 2. Detection

Suricata detects network activity while Wazuh monitors system and authentication logs.

Example event:

```text
Rule ID: 5710
Description: Multiple SSH Failed Logins
Source IP: 192.168.1.105
Host: debian-target
```

### 3. Alert Collection

The Wazuh Manager processes and correlates the event and generates an alert.

The Python SOAR platform retrieves the alert through the Wazuh API / alert JSON.

### 4. IOC Extraction

The automation engine extracts relevant Indicators of Compromise such as:

- Source IP
- Destination IP
- Host
- Port
- Rule ID
- Attack type
- File/hash indicators where applicable

### 5. Threat Intelligence Enrichment

The extracted indicators are submitted to external threat intelligence services.

#### VirusTotal

Used to obtain malicious/benign reputation and security intelligence for indicators.

#### AbuseIPDB

Used to evaluate IP reputation and abuse confidence information.

The enrichment results are incorporated into the incident risk evaluation.

### 6. AI-Based Analysis and Risk Scoring

The platform performs AI-assisted analysis to:

- Summarize the incident
- Identify suspicious behavior
- Analyze contextual information
- Assist with risk prioritization
- Generate actionable security insights
- Reduce manual SOC analysis effort

### 7. Decision Engine

The decision engine evaluates the collected evidence and determines whether automated containment should be performed.

Conceptually:

```text
Threat Intelligence
        +
Wazuh Severity
        +
Attack Context
        +
AI Analysis
        │
        ▼
   Risk Score
        │
        ▼
  Decision Engine
        │
   ┌────┴────┐
   │         │
 Low Risk   High Risk
   │         │
 Monitor    Respond
             │
             ▼
        Block Malicious IP
```

### 8. Automated Response

For high-confidence malicious activity, the platform can automatically block the source IP using Linux firewall controls such as:

```bash
iptables -A INPUT -s <MALICIOUS_IP> -j DROP
```

UFW can also be used depending on the host configuration.

### 9. Incident Logging

Incident details are stored in SQLite.

Example information:

| Field | Example |
|---|---|
| Time | 2025-05-27 10:30:15 |
| Source IP | 192.168.1.105 |
| Host | debian-target |
| Attack Type | SSH Brute Force |
| MITRE Technique | T1110 |
| Risk Score | 95 |
| Action | IP Blocked |
| Status | Success |

### 10. AI Incident Report

The platform generates an AI-assisted incident report containing information such as:

- Incident summary
- Detection source
- Source IP / IOC
- Attack type
- Threat intelligence findings
- Risk assessment
- MITRE ATT&CK mapping
- Response action
- Recommended remediation
- Incident status

### 11. Notifications

Security personnel can receive automated notifications through:

- Slack API / Webhook
- SMTP Email

This allows incidents to be reported without requiring continuous manual monitoring.

### 12. Centralized Logging and Visualization

Security logs are forwarded to the Elastic Stack:

```text
Security Logs
     │
     ▼
 Logstash
     │
     ▼
Elasticsearch
     │
     ▼
  Kibana
```

Kibana can be used for:

- Security dashboards
- Incident visualization
- Attack trend analysis
- Log investigation
- Threat hunting
- Event correlation

---

## 🧩 Project Components

| Component | Purpose |
|---|---|
| `main.py` | Main SOAR execution workflow |
| `alert_reader.py` | Reads/obtains security alerts |
| `decision_engine.py` | Determines appropriate response |
| `ioc_extractor.py` | Extracts indicators of compromise |
| `threat_intel.py` | Threat intelligence enrichment |
| `incident_logger.py` | Stores incident information |
| `response_action.py` | Executes automated response actions |
| `notifier.py` | Sends Slack/Email notifications |
| `ai_report.py` | AI-assisted incident analysis/report generation |
| `config.py` | Application configuration and environment variables |
| `wazuh_client.py` | Wazuh API communication |
| `storage.py` | Incident storage functionality |
| `Dockerfile` | Container image definition |
| `docker-compose.yml` | Container orchestration |
| `Jenkinsfile` | CI/CD pipeline configuration |
| `requirements.txt` | Python dependencies |
| `reports/` | Generated incident reports |
| `Playbook/` | SOAR playbook resources |

---

## 🛠️ Technology Stack

### Operating Systems & Virtualization

- Debian 12
- Kali Linux
- VMware Workstation

### Security Monitoring

- Wazuh SIEM
- Suricata IDS
- MITRE ATT&CK

### Programming & Automation

- Python
- Bash / Linux commands
- Automated incident response

### Threat Intelligence

- VirusTotal API
- AbuseIPDB API

### Response & Containment

- iptables
- UFW

### Logging & SIEM

- Elasticsearch
- Logstash
- Kibana

### Storage

- SQLite
- JSON

### Notifications

- Slack API
- SMTP Email

### DevSecOps / Source Control

- Git
- GitHub
- Jenkins
- Docker
- Docker Compose

---

## 🔐 Security & Configuration

Sensitive credentials are **not stored directly in the source code**.

Environment variables are used for credentials and API keys.

Examples include:

```bash
GEMINI_API_KEY
VT_KEY
ABUSEIPDB_API_KEY
WAZUH_USER
WAZUH_PASSWORD
SMTP_PASS
```

The application reads configuration values using Python environment-variable access such as:

```python
import os

api_key = os.getenv("GEMINI_API_KEY")
```

For a production deployment, use a dedicated secrets-management solution instead of storing secrets in plain-text system configuration.

### Recommended `.gitignore`

```gitignore
__pycache__/
*.py[cod]

.env
.env.*
!.env.example

secrets/
secrets.py
secrets.json

*.pem
*.key

*.bak
*.backup
*.backup_*

venv/
.venv/

.vscode/
.idea/

*.log
```

**Never commit API keys, passwords, private keys, tokens, or other credentials to GitHub.**

---

## 🚀 Installation & Setup

### Prerequisites

Install/configure:

- VMware Workstation
- Debian 12 VMs
- Kali Linux
- Python 3
- Wazuh
- Suricata
- Elasticsearch
- Logstash
- Kibana
- Git
- Docker / Docker Compose
- Jenkins

### Clone the Repository

```bash
git clone https://github.com/Deepam2k23/AI-Powered-Intelligent-Automated-Security-Incident-Response-Platform-SOAR-lite-.git
cd AI-Powered-Intelligent-Automated-Security-Incident-Response-Platform-SOAR-lite-
```

### Create a Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Environment Variables

Set the required variables in the operating system environment.

For example:

```bash
export GEMINI_API_KEY="your-key"
export VT_KEY="your-key"
export ABUSEIPDB_API_KEY="your-key"
```

For persistent system-wide configuration on Debian, environment variables can be configured through the appropriate system environment configuration.

Verify that variables are available without exposing their values:

```bash
if [ -n "$GEMINI_API_KEY" ]; then echo "GEMINI_API_KEY is set"; fi
```

### Run the SOAR Application

The exact entry point depends on the configured deployment mode. For a direct Python execution:

```bash
python3 main.py
```

or, if the project workflow uses the SOAR orchestrator:

```bash
python3 soar.py
```

---

## 🐳 Docker Deployment

The project includes:

```text
Dockerfile
docker-compose.yml
```

Build the application:

```bash
docker build -t soar-lite .
```

Run with Docker Compose:

```bash
docker compose up -d
```

Check containers:

```bash
docker ps
```

Stop the stack:

```bash
docker compose down
```

---

## 🔄 CI/CD

A Jenkins pipeline is included through:

```text
Jenkinsfile
```

The intended workflow is:

```text
Developer
    │
    ▼
Git
    │
    ▼
GitHub
    │
    ▼
Jenkins
    │
    ├── Checkout
    ├── Validation
    ├── Security/Secret Checks
    ├── Build
    └── Deployment
         │
         ▼
     SOAR Platform
```

Jenkins can be integrated with Docker to build and deploy the SOAR application.

---

## 🧪 Example Incident

### Scenario

Kali Linux performs an SSH brute-force attack against the monitored Debian server.

```text
Kali Linux
     │
     │ SSH Brute Force
     ▼
Debian Target
     │
     ├── auth.log
     └── Suricata events
             │
             ▼
        Wazuh Agent
             │
             ▼
        Wazuh Manager
             │
             ▼
       Python SOAR
             │
             ├── Extract Source IP
             │
             ├── VirusTotal
             │
             ├── AbuseIPDB
             │
             ├── AI Analysis
             │
             ├── Risk Score
             │
             └── Decision
                    │
                    ▼
              IP Blocked
                    │
             ┌──────┴──────┐
             ▼             ▼
          SQLite        Slack/Email
             │
             ▼
        AI Report
             │
             ▼
      Elasticsearch
             │
             ▼
          Kibana
```

---

## 🧠 MITRE ATT&CK Mapping

The platform can associate detected behavior with MITRE ATT&CK techniques.

Example:

```text
SSH Brute Force
      │
      ▼
T1110 — Brute Force
```

MITRE ATT&CK mapping helps security analysts understand attacker behavior using a standardized adversary-technique framework.

---

## 📊 Benefits

The platform provides:

- Automated security alert processing
- Real-time threat detection
- IOC extraction
- Threat intelligence enrichment
- AI-assisted incident analysis
- Automated risk prioritization
- Automated IP containment
- Incident logging
- Centralized security logs
- Threat hunting support
- Interactive security dashboards
- Automated Slack notifications
- Automated email reporting
- AI-generated incident reports
- Reduced manual SOC workload
- Improved incident response speed

---

## 🎯 Key Features

### Detection

- Wazuh SIEM
- Suricata IDS
- Authentication log monitoring
- Security event correlation
- MITRE ATT&CK mapping

### Analysis

- IOC extraction
- VirusTotal enrichment
- AbuseIPDB reputation
- AI-assisted analysis
- Risk scoring
- Incident summarization

### Response

- Automatic malicious-IP blocking
- iptables/UFW integration
- Incident state tracking
- Automated notifications

### Reporting

- SQLite incident storage
- AI-generated incident reports
- Slack notifications
- SMTP email notifications
- Elastic Stack visualization

---

## 📁 Repository Structure

```text
soar_suricata_new/
│
├── ai_report.py
├── config.py
├── decision.py
├── enrichment.py
├── notifier.py
├── response.py
├── soar.py
├── storage.py
├── wazuh_client.py
│
├── alert_reader.py
├── decision_engine.py
├── incident_logger.py
├── ioc_extractor.py
├── main.py
├── response_action.py
├── threat_intel.py
│
├── Dockerfile
├── docker-compose.yml
├── Jenkinsfile
├── requirements.txt
├── .gitignore
│
├── Playbook/
├── reports/
│
└── __pycache__/        # Generated; should not be committed
```

> The exact file list may vary depending on the active version of the SOAR implementation. Generated files such as `__pycache__`, `.pyc`, logs, backups, and local secrets should be excluded through `.gitignore`.

---

## 🗺️ Architecture Diagram

<img width="1536" height="1024" alt="AI-Powered Intelligent Automated Security Incident Response_Architecture" src="https://github.com/user-attachments/assets/87fe2999-bc30-4eda-b307-04700eb1cf57" />



The project architecture consists of:

1. **Threat Actor** — Kali Linux
2. **Target Server** — Debian 12
3. **Monitoring & Log Collection** — Wazuh Agent / Suricata
4. **SIEM** — Wazuh Manager
5. **Automation Playbook** — Python SOAR-lite
6. **Integrations** — VirusTotal / AbuseIPDB
7. **Incident Storage & Logging** — SQLite / Elastic Stack
8. **Notifications & Visibility** — Slack / SMTP / Kibana

The architecture demonstrates an end-to-end automated SOC workflow:

```text
Attack
  ↓
Detection
  ↓
Alert Collection
  ↓
IOC Extraction
  ↓
Threat Intelligence
  ↓
AI Analysis
  ↓
Risk Scoring
  ↓
Decision Engine
  ↓
Automated Response
  ↓
Incident Logging
  ↓
AI Report
  ↓
Notification + Dashboard
```

---

## 🔮 Future Enhancements

Potential improvements include:

- Automated malware analysis
- SOAR web dashboard
- More response playbooks
- Automated host isolation
- Active Directory integration
- EDR integration
- Additional threat intelligence feeds
- Machine-learning-based anomaly detection
- Advanced correlation rules
- Case management
- Role-based access control
- Kubernetes deployment
- Cloud-native SOC deployment
- Secrets management with Vault
- OpenTelemetry integration
- Automated MITRE ATT&CK coverage reporting

---

## ⚠️ Disclaimer

This project is intended for **educational, research, cybersecurity lab, and authorized security testing purposes**.

Only perform attack simulations against systems and networks that you own or have explicit permission to test.

Do not use the automated response functionality against unauthorized systems.

---

## 👨‍💻 Project Summary

**AI-Powered Intelligent Automated Security Incident Response Platform (SOAR-lite)** demonstrates practical implementation of modern SOC and DevSecOps concepts by integrating:

**Python + Wazuh + Suricata + VirusTotal + AbuseIPDB + AI + iptables + SQLite + Elasticsearch + Logstash + Kibana + Slack + SMTP + Jenkins + Docker + Git/GitHub**

The platform automates the complete security incident lifecycle from **threat detection and alert ingestion through IOC enrichment, AI-assisted risk analysis, automated containment, incident logging, notification, and report generation**.

---

## ⭐ Project Highlights

- AI-assisted SOC automation
- Automated incident response
- Wazuh SIEM integration
- Suricata IDS integration
- Threat intelligence enrichment
- VirusTotal API integration
- AbuseIPDB API integration
- MITRE ATT&CK-based analysis
- Automated firewall response
- SQLite incident management
- Elastic Stack centralized logging
- Kibana security visualization
- Slack and SMTP notifications
- Dockerized deployment
- Jenkins CI/CD integration
- Git/GitHub version control
- VMware-based multi-VM SOC lab
