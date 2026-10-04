# LOGSENTRY — Database Schema Reference

LOGSENTRY uses SQLite with SQLAlchemy ORM, indexed on high-frequency query columns (`timestamp`, `source_ip`, `username`, `event_type`, `severity`). All timestamps are standardized in UTC.

---

## Entity Relationship Overview

```
log_sources (1) ───< analysis_jobs (N)
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
       log_events     detections     incidents (1)
                                         │
                                         ▼
                                   incident_events (N)
```

---

## Table Schemas

### 1. `users`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | VARCHAR(36) | PRIMARY KEY | UUID |
| `username` | VARCHAR(64) | UNIQUE, NOT NULL | SOC Operator Handle |
| `email` | VARCHAR(128) | UNIQUE, NOT NULL | Analyst Email |
| `role` | VARCHAR(32) | DEFAULT 'SOC_ANALYST' | Authorization Role |
| `created_at` | DATETIME | DEFAULT UTC_NOW | Registration timestamp |

### 2. `log_sources`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | VARCHAR(36) | PRIMARY KEY | UUID |
| `original_filename`| VARCHAR(255) | NOT NULL | Sanitized filename |
| `stored_filename`  | VARCHAR(255) | NOT NULL | Internal stored UUID filename |
| `file_path`        | VARCHAR(512) | NOT NULL | Full path on disk |
| `file_size_bytes`  | INTEGER | NOT NULL | Size in bytes |
| `format_type`      | VARCHAR(50) | DEFAULT 'AUTO' | Format selector |
| `created_at`       | DATETIME | DEFAULT UTC_NOW | Ingestion timestamp |

### 3. `analysis_jobs`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | VARCHAR(36) | PRIMARY KEY | UUID |
| `log_source_id` | VARCHAR(36) | FK(log_sources.id) | Ingested source reference |
| `status` | VARCHAR(32) | INDEX | PENDING, PROCESSING, COMPLETED, FAILED |
| `profile` | VARCHAR(32) | DEFAULT 'STANDARD'| QUICK, STANDARD, DETAILED |
| `total_lines` | INTEGER | DEFAULT 0 | Raw lines processed |
| `parsed_lines` | INTEGER | DEFAULT 0 | Lines normalized |
| `failed_lines` | INTEGER | DEFAULT 0 | Malformed lines skipped |
| `parser_type` | VARCHAR(50) | NULLABLE | Parser used (e.g. LINUX_AUTH) |
| `duration_seconds` | FLOAT | DEFAULT 0.0 | Pipeline execution duration |
| `risk_score` | FLOAT | DEFAULT 0.0 | Overall job risk score (0-100) |
| `risk_level` | VARCHAR(20) | DEFAULT 'LOW' | Posture level |
| `risk_explanation` | TEXT | NULLABLE | Scoring narrative |
| `events_count` | INTEGER | DEFAULT 0 | Stored events |
| `detections_count` | INTEGER | DEFAULT 0 | Detections found |
| `incidents_count` | INTEGER | DEFAULT 0 | Incidents correlated |
| `created_at` | DATETIME | INDEX | Job initialization timestamp |
| `completed_at` | DATETIME | NULLABLE | Job completion timestamp |

### 4. `log_events` (Normalized Common Log Model)
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | VARCHAR(36) | PRIMARY KEY | UUID |
| `analysis_job_id` | VARCHAR(36) | FK(analysis_jobs.id), INDEX | Analysis job parent |
| `line_number` | INTEGER | NULLABLE | Line index in original file |
| `timestamp` | DATETIME | INDEX | Extracted event time (UTC) |
| `source_ip` | VARCHAR(64) | INDEX | Origin IP |
| `destination_ip` | VARCHAR(64) | NULLABLE | Target host IP |
| `username` | VARCHAR(128) | INDEX | Subject user identity |
| `event_type` | VARCHAR(64) | INDEX | AUTH_FAILURE, AUTH_SUCCESS, HTTP_REQUEST, etc. |
| `method` | VARCHAR(16) | NULLABLE | HTTP Method (GET, POST, etc.) |
| `endpoint` | VARCHAR(512) | NULLABLE | Requested URI / Path |
| `status_code` | INTEGER | NULLABLE | HTTP status response code |
| `protocol` | VARCHAR(32) | NULLABLE | Protocol (SSH, HTTP/1.1, etc.) |
| `source_port` | INTEGER | NULLABLE | Client ephemeral port |
| `destination_port`| INTEGER | NULLABLE | Service port (22, 80, 443) |
| `process` | VARCHAR(64) | NULLABLE | Process/daemon name (`sshd`, `sudo`, `web`) |
| `message` | TEXT | NULLABLE | Normalized log message |
| `raw_log` | TEXT | NOT NULL | Exact raw line unmodified |
| `severity` | VARCHAR(20) | INDEX | INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL |

### 5. `detections`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | VARCHAR(36) | PRIMARY KEY | UUID |
| `analysis_job_id` | VARCHAR(36) | FK(analysis_jobs.id), INDEX | Analysis job |
| `rule_id` | VARCHAR(64) | INDEX | Rule identifier (e.g. DET-001) |
| `attack_type` | VARCHAR(128) | INDEX | Attack category name |
| `title` | VARCHAR(255) | NOT NULL | Summary finding title |
| `severity` | VARCHAR(20) | INDEX | Severity tier |
| `confidence` | VARCHAR(20) | NOT NULL | LOW, MEDIUM, HIGH |
| `source_ip` | VARCHAR(64) | INDEX | Offending source IP |
| `target_endpoint` | VARCHAR(512) | NULLABLE | Target path or port |
| `event_count` | INTEGER | NOT NULL | Events triggering the finding |
| `threshold` | FLOAT | NULLABLE | Configured threshold |
| `time_window` | INTEGER | NULLABLE | Window duration (seconds) |
| `explanation` | TEXT | NOT NULL | Structured explainability narrative |
| `remediation` | TEXT | NULLABLE | Recommended actions |
| `status` | VARCHAR(32) | DEFAULT 'ACTIVE' | ACTIVE, RESOLVED, FALSE_POSITIVE |

### 6. `incidents`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | VARCHAR(36) | PRIMARY KEY | UUID |
| `analysis_job_id` | VARCHAR(36) | FK(analysis_jobs.id), INDEX | Analysis job |
| `title` | VARCHAR(255) | NOT NULL | Incident title |
| `severity` | VARCHAR(20) | INDEX | CRITICAL, HIGH, MEDIUM, LOW |
| `confidence` | VARCHAR(20) | NOT NULL | Confidence tier |
| `source_ip` | VARCHAR(64) | INDEX | Adversary source IP |
| `event_count` | INTEGER | NOT NULL | Total security events involved |
| `risk_score` | FLOAT | DEFAULT 0.0 | Calculated risk score (0-100) |
| `risk_level` | VARCHAR(20) | DEFAULT 'LOW' | Score tier |
| `explanation` | TEXT | NOT NULL | Incident narrative with risk formula breakdown |
| `remediation` | TEXT | NOT NULL | Prescribed SOC containment steps |
| `status` | VARCHAR(32) | DEFAULT 'NEW' | NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE |

### 7. `detection_rules`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | VARCHAR(36) | PRIMARY KEY | UUID |
| `rule_id` | VARCHAR(64) | UNIQUE, INDEX | DET-001 through DET-011 |
| `name` | VARCHAR(255) | NOT NULL | Human-readable name |
| `description` | TEXT | NOT NULL | Rule logic summary |
| `category` | VARCHAR(64) | NOT NULL | Classification |
| `severity` | VARCHAR(20) | NOT NULL | Severity rating |
| `confidence` | VARCHAR(20) | NOT NULL | Confidence rating |
| `threshold` | FLOAT | NOT NULL | Event trigger count |
| `time_window` | INTEGER | NOT NULL | Window in seconds |
| `enabled` | BOOLEAN | DEFAULT TRUE | Active toggle |
| `remediation` | TEXT | NULLABLE | Suggested actions |

### 8. `reports`
Stores generated PDF reports with metadata and disk paths.

### 9. `audit_logs`
Records administrative actions (`timestamp`, `action`, `actor`, `resource`, `result`, `details`).
