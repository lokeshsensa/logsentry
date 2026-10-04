# LOGSENTRY — System Architecture Specification

## Overview

**LOGSENTRY** is a defensive cybersecurity log analysis and attack detection platform designed to ingest system, authentication, web server, and application logs, normalize disparate formats into a unified 16-field telemetry model, execute configurable sliding-window attack detection rules, correlate multi-stage incident kill chains, and calculate transparent risk scores.

---

## Architectural Flow Diagram

```
                              ┌────────────────────────────────────────┐
                              │           React SOC Web UI             │
                              │ (Vite, Tailwind, Recharts, Lucide)     │
                              └───────────────────┬────────────────────┘
                                                  │ HTTP REST (JSON / Multipart)
                                                  ▼
                              ┌────────────────────────────────────────┐
                              │            FastAPI Server              │
                              │ (Async, Pydantic V2, Thread-Safe Pool) │
                              └───────────────────┬────────────────────┘
                                                  │
                  ┌───────────────────────────────┼───────────────────────────────┐
                  ▼                               ▼                               ▼
       ┌─────────────────────┐         ┌─────────────────────┐         ┌─────────────────────┐
       │   Log Ingestion     │         │   Parser Manager    │         │  Detection Engine   │
       │ • Filename sanitize │ ──────> │ • LinuxAuthParser   │ ──────> │ • 11 Active Rules   │
       │ • Size validation   │         │ • ApacheNginxParser │         │ • Sliding Windows   │
       │ • Stream chunking   │         │ • GenericParser     │         │ • Deduplication     │
       └─────────────────────┘         └─────────────────────┘         └──────────┬──────────┘
                                                  │                               │
                                                  ▼                               ▼
                                       ┌─────────────────────┐         ┌─────────────────────┐
                                       │ Normalized DB Batch │         │ Correlation Engine  │
                                       │ (16-field model)    │         │ • Multi-Stage Kill  │
                                       └─────────────────────┘         │   Chain Correlation │
                                                                       └──────────┬──────────┘
                                                                                  │
                                                                                  ▼
                                                                       ┌─────────────────────┐
                                                                       │     Risk Engine     │
                                                                       │ • 5-Factor Formula  │
                                                                       │ • 0-100 Score Scale │
                                                                       └──────────┬──────────┘
                                                                                  │
                                                                                  ▼
                                                                       ┌─────────────────────┐
                                                                       │ SQLite DB Storage   │
                                                                       │ & ReportLab PDF Gen │
                                                                       └─────────────────────┘
```

---

## Modular Subsystems

### 1. Ingestion Subsystem (`app/api/logs.py`, `app/core/security.py`)
- **Safe Streaming**: Ingests files up to 50MB using 1MB chunked streams to maintain minimal RAM overhead.
- **Defensive Sanitation**: Strips path separators, rejects directory traversal attempts (`../`), and permits only authorized extensions (`.log`, `.txt`, `.syslog`).
- **Format Pre-Inspection**: Inspects the first 50 lines to detect format before initiating full analysis.

### 2. Log Parsing & Normalization (`app/parsers/`)
- **Modular Polymorphic Architecture**: All parsers inherit from `BaseLogParser` (`can_parse()`, `parse_line()`).
- **LinuxAuthParser**: Supports standard BSD Syslog and RFC 5424 ISO8601 formats (`sshd`, `sudo`, `su`, `pam_unix`).
- **ApacheNginxParser**: Decodes Combined and Common Log Format (CLF).
- **GenericParser**: Fallback parser for microservice and application logs.
- **Fail-Safe Processing**: Malformed lines are recorded as failed lines without halting analysis.

### 3. Attack Detection Engine (`app/detectors/`)
- **Sliding-Window Time Slicing**: Evaluates chronological event subsets within defined windows (e.g. 300s).
- **Entity Grouping**: Buckets by source IP or target username to detect horizontal divergence (spraying) and vertical depth (brute force).
- **Rule Deduplication**: Merges overlapping detection windows into consolidated findings.
- **Statistical Anomaly Engine**: Calculates moving mean, standard deviation, and Z-scores ($Z = \frac{x - \mu}{\sigma}$).

### 4. Correlation Engine (`app/correlation/`)
- Correlates isolated atomic findings into holistic high-level incidents.
- Detects multi-stage attack progressions (e.g., Recon -> Brute Force -> Auth Success -> Privilege Escalation to root).

### 5. Risk Scoring Engine (`app/risk/`)
- Transparent, explainable 5-factor mathematical formula normalizing findings from 0 to 100.
