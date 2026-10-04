# LOGSENTRY — Log Analyzer & Attack Detection System

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.2+-61DAFB.svg)](https://react.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3.4+-38B2AC.svg)](https://tailwindcss.com/)
[![Tests](https://img.shields.io/badge/Tests-Pytest%2013%20Passed-success.svg)](https://docs.pytest.org/)
[![Defensive](https://img.shields.io/badge/Security-Defensive%20Only-emerald.svg)](#security-considerations)

**LOGSENTRY** is a production-grade defensive cybersecurity log analyzer, attack detection engine, and Security Operations Center (SOC) dashboard. It ingests Linux authentication, Apache/Nginx web server, and application logs, normalizes disparate formats into a common 16-field security data structure, runs configurable sliding-window attack detection rules, correlates multi-stage attack kill chains, calculates transparent risk scores (0–100), and generates professional executive PDF reports.

> **Defensive Security Notice**: This platform is designed solely for defensive log auditing, threat hunting, and educational incident response. It does not perform active network scanning, exploitation, credential harvesting, or destructive actions.

---

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Technology Stack](#technology-stack)
4. [Detection Methodology & Rules](#detection-methodology--rules)
5. [Risk Scoring Model](#risk-scoring-model)
6. [Sample Datasets](#sample-datasets)
7. [Installation & Setup](#installation--setup)
8. [Running the Application](#running-the-application)
9. [Running Tests](#running-tests)
10. [REST API Documentation](#rest-api-documentation)
11. [PDF Report Generation](#pdf-report-generation)
12. [Security Considerations](#security-considerations)
13. [Limitations & Future Roadmap](#limitations--future-roadmap)

---

## Features

- **Multi-Format Log Ingestion**:
  - Linux Authentication (`/var/log/auth.log`, `/var/log/secure`, SSHD, Sudo, Su, PAM).
  - Web Server Logs (Apache & Nginx Common & Combined Log Format).
  - Generic Application Logs (ISO8601 timestamps, log levels, microservice payloads).
  - Custom Log Format pre-inspection preview before running analysis.
- **Unified 16-Field Normalized Schema**:
  - `id`, `timestamp` (UTC), `source_ip`, `destination_ip`, `username`, `event_type`, `method`, `endpoint`, `status_code`, `protocol`, `source_port`, `destination_port`, `process`, `message`, `raw_log`, `severity`.
- **11 Modular Detection Rules**:
  - Sliding-window brute force detection.
  - Password spraying across multiple accounts.
  - Account and identity enumeration.
  - HTTP error spike detection (4xx/5xx bursts).
  - DoS request flooding detection.
  - Port & endpoint reconnaissance scanning indicators.
  - Contextual privilege escalation (unauthorized sudo/su).
  - Unusual HTTP request methods (PUT, DELETE, TRACE, CONNECT).
  - Sensitive resource enumeration (`/.env`, `/admin`, `/etc/passwd`).
  - Repeated access denied (403 / permission denied).
  - Statistical anomaly detection (Z-Score calculation).
- **Multi-Stage Attack Correlation**:
  - Correlates isolated findings into high-level Incidents (e.g., Brute Force -> Auth Success -> Privilege Escalation to root).
  - SOC workflow state machine: `NEW` -> `INVESTIGATING` -> `RESOLVED` / `FALSE_POSITIVE`.
- **Explainable 5-Factor Risk Scoring**:
  - $0 - 100$ transparent mathematical formula factoring in base severity, frequency, detection confidence, correlation kill-chain, and asset context.
  - Transparent risk tiers: Low (0-20), Guarded (21-40), Medium (41-60), High (61-80), Critical (81-100).
- **Professional ReportLab PDF Generator**:
  - Multi-page SOC deliverable featuring executive summaries, telemetry charts, incident timelines, top source IPs, and remediation guidance.
- **Cyber SOC Dark Theme React Dashboard**:
  - Live metric KPI cards, Recharts time-series graphs, category breakdowns, filterable log explorer with raw/normalized JSON inspection, and detection rule tuning controls.

---

## Architecture

```
                    ┌─────────────────────┐
                    │    React SOC UI     │
                    │ (Vite, Recharts)    │
                    └──────────┬──────────┘
                               │ HTTP REST
                    ┌──────────▼──────────┐
                    │    FastAPI Server   │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
       Log Ingestion      Log Parser       Detection Engine
       (Chunked Stream)   (Format Detect)  (11 Rule Matrix)
              │                │                │
              └────────────────┼────────────────┘
                               │
                       Correlation Engine
                       (Multi-Stage APT)
                               │
                         Risk Engine
                       (5-Factor Model)
                               │
                    ┌──────────▼──────────┐
                    │  SQLite DB Storage  │
                    │  & ReportLab PDF    │
                    └─────────────────────┘
```

---

## Technology Stack

- **Backend**: Python 3.11+, FastAPI, SQLAlchemy, SQLite, Pydantic V2, Uvicorn.
- **Log Processing**: Python Standard Library (`re`, `datetime`, `collections`, `math`, `ipaddress`).
- **Reports**: ReportLab PDF Toolkit.
- **Testing**: Pytest, Pytest-Asyncio, HTTPX.
- **Frontend**: React 18, Vite 5, Tailwind CSS, Axios, Recharts, Lucide React, React Router 6.
- **Containerization**: Docker, Docker Compose, Nginx.

---

## Detection Methodology & Rules

| Rule ID | Detection Name | Category | Severity | Window | Trigger Logic |
|---|---|---|---|---|---|
| **DET-001** | Brute Force Authentication | Authentication | **HIGH** | 300s | $\ge 5$ failed auth attempts from the same IP. |
| **DET-002** | Password Spraying | Authentication | **HIGH** | 600s | Auth failures against $\ge 3$ distinct usernames from one IP. |
| **DET-003** | Account Enumeration | Reconnaissance | **MEDIUM** | 300s | Attempts against $\ge 4$ invalid/unknown identities. |
| **DET-004** | HTTP Error Spike | Web | **MEDIUM** | 120s | $\ge 12$ error status codes (401, 403, 404, 500) from one source. |
| **DET-005** | Request Flooding (DoS) | Anomaly | **HIGH** | 30s | $\ge 40$ requests in 30 seconds from a single source. |
| **DET-006** | Port / Endpoint Scanning | Reconnaissance | **MEDIUM** | 60s | Probes against $\ge 7$ distinct endpoints/ports. |
| **DET-007** | Privilege Abuse / Escalation | Privilege | **HIGH** | 300s | Failed sudo commands, unauthorized su, or access to sensitive files. |
| **DET-008** | Unusual HTTP Methods | Web | **LOW** | 300s | Requests using PUT, DELETE, TRACE, CONNECT, DEBUG. |
| **DET-009** | Sensitive Resource Enumeration | Reconnaissance | **HIGH** | 180s | Requests probing `/.env`, `/admin`, `/config`, `/etc/passwd`. |
| **DET-010** | Repeated Access Denied | Web | **MEDIUM** | 180s | $\ge 4$ occurrences of 403 Forbidden or permission denied. |
| **DET-011** | Statistical Traffic Anomaly | Anomaly | **MEDIUM** | 60s | Minute request rate Z-score $\ge 2.5$ ($\sigma > 0$). |

### Explainability Matrix
Every finding explicitly answers:
1. **WHAT**: Exact count and nature of observed security events.
2. **WHERE**: Originating source IP and targeted resource/port.
3. **WHEN**: First seen and last seen timestamps in UTC.
4. **WHY**: Configured threshold vs. observed count.
5. **WHY SUSPICIOUS**: Attacker intent (automated brute force, horizontal spray, reconnaissance).
6. **WHAT TO INVESTIGATE**: Specific firewall, host, and identity remediation procedures.

---

## Risk Scoring Model

The risk calculation is deterministic and transparent:

$$\text{Risk Score} = \text{Base Severity (0–40)} + \text{Frequency (0–20)} + \text{Confidence (0–15)} + \text{Correlation (0–15)} + \text{Context (0–10)}$$

- **Base Severity**: Informational ($1 \times 4$), Low ($2 \times 4$), Medium ($5 \times 4$), High ($8 \times 4$), Critical ($10 \times 4$).
- **Frequency Factor**: Bounded logarithmic scaling ($1 \to 3$ pts, $\le 5 \to 7$ pts, $\le 20 \to 12$ pts, $\le 50 \to 16$ pts, $> 50 \to 20$ pts).
- **Confidence Weight**: Low ($3$), Medium ($8$), High ($15$).
- **Correlation Multiplier**: Standalone ($2$), 2 stages ($8$), $\ge 3$ stages / kill-chain ($15$).
- **Asset Context**: Standard user ($3$), Credential/Database ($7$), Root / Admin / `/.env` / Shadow ($10$).

Normalized Score Range: **0 to 100**.

---

## Sample Datasets

Synthetic, non-sensitive sample log files are located in `logsentry/sample_logs/`:

- `combined_apt_scenario.log`: Multi-stage attack progression (SSH user enumeration -> brute force -> successful auth -> privilege escalation to root).
- `brute_force.log`: 13 rapid failed password attempts against SSH from `192.168.1.145`.
- `password_spraying.log`: Horizontal password guessing targeting 8 distinct accounts from `10.0.0.88`.
- `http_error_spike.log`: Burst of 401, 403, 404, 500 error responses from `198.51.100.42`.
- `resource_enumeration.log`: Web reconnaissance probing `/.env`, `/admin`, `/config`, `/etc/passwd`.
- `privilege_abuse.log`: Failed sudo password attempts and unauthorized su to root.
- `normal_auth.log`: Benign background baseline Linux auth activity.

---

## Installation & Setup

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- (Optional) Docker & Docker Compose

### Clone Repository
```bash
git clone https://github.com/your-org/logsentry.git
cd logsentry
```

---

## Running the Application

### Option A: Local Development

#### 1. Start the Backend
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
The FastAPI backend and documentation will be live at:
- API Server: `http://localhost:8000`
- Interactive Swagger UI: `http://localhost:8000/docs`
- Redoc Reference: `http://localhost:8000/redoc`

#### 2. Start the Frontend
```bash
cd ../frontend
npm install
npm run dev
```
The SOC Web Console will be accessible at:
- Web Console: `http://localhost:5173`

---

### Option B: Docker Compose

To launch the full containerized stack in one command:
```bash
docker-compose up --build
```
- Frontend UI: `http://localhost:3000`
- Backend API: `http://localhost:8000`

---

## Running Tests

Run the complete Pytest unit and integration test suite:
```bash
cd backend
pytest tests/ -v
```

Test coverage includes:
- `test_parsers.py`: Syslog, ISO8601, SSH, Sudo, Apache/Nginx CLF, and Generic parsers.
- `test_detectors.py`: Brute force, password spraying, resource enumeration sliding windows.
- `test_correlation_and_risk.py`: Multi-stage attack correlation and 5-factor risk scoring bounds.
- `test_integration.py`: End-to-end test verifying Upload -> Parse -> Detect -> Correlate -> Store -> Report Generation.

---

## PDF Report Generation

LOGSENTRY creates professional executive PDF reports on demand:
- **Executive Summary**
- **Analysis Metadata & Log Statistics**
- **Security Posture Risk Overview**
- **Correlated Incident Details**
- **Top Source IP Traffic Table**
- **Defensive Remediation Guidelines**
- **Technical Methodology**

Reports can be generated directly in the **Security Reports** page or via the REST API:
```bash
curl -X POST http://localhost:8000/api/reports/generate \
  -H "Content-Type: application/json" \
  -d '{"analysis_job_id": "<JOB_ID>"}'
```

---

## Security Considerations

- **Non-Destructive Defensive Scope**: LOGSENTRY only inspects log records locally provided. It will never send network requests, ping external hosts, or request discovered endpoints.
- **Strict Filename Sanitization**: Strips path separators (`/`, `\`), null bytes, and traversal attempts (`../`).
- **Whitelisted File Extensions**: Only `.log`, `.txt`, `.syslog`, and `.gz` are processed.
- **Zero Shell Execution**: Native Python regex and standard library parsing ensures no shell command execution (`exec`, `subprocess`).
- **Parameterized SQL**: All database operations leverage SQLAlchemy ORM parameterized queries to prevent SQL injection.
- **DOM Content Escaping**: Log payloads and raw text in the frontend are sanitized and rendered in preformatted text blocks to prevent XSS.

---

## Limitations & Future Roadmap

Current scope focus is designed for authorized local analysis. Planned future enhancements include:
- Syslog RFC 5424 daemon listener for live network streaming.
- Windows EVTX binary event log parsing.
- MITRE ATT&CK Matrix TTP tagging.
- MaxMind GeoIP / ASN context enrichment.
- OpenSearch / Elasticsearch backend connector.

---

## Author & License

Designed and developed by Senior Cybersecurity SOC Engineering & Research Team.  
Released under the MIT License for defensive and educational security operations.
