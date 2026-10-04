# LOGSENTRY — REST API Reference

Interactive OpenAPI documentation is available live at `http://localhost:8000/docs` and Redoc at `http://localhost:8000/redoc`.

---

## Endpoints Summary

### System Health
- `GET /api/health`: Health status, system name, and server timestamp.

### Log Ingestion
- `POST /api/logs/upload`: Multipart upload with size and format validation.
- `POST /api/logs/preview-detect`: Analyzes the first 15 lines of an uploaded log to report detected format.
- `GET /api/logs/sources`: Lists previously uploaded log sources.

### Analysis Management
- `POST /api/analysis/start`: Triggers end-to-end analysis (`log_source_id`, `profile`, `timezone_name`, `run_sync`).
- `GET /api/analysis`: Lists all historical analysis jobs.
- `GET /api/analysis/{id}`: Detailed telemetry metrics and risk score for a specific job.
- `GET /api/analysis/{id}/events`: Filterable, searchable, and paginated normalized events (`source_ip`, `username`, `event_type`, `severity`, `status_code`, `search`, `limit`, `offset`).

### Detections
- `GET /api/detections`: Lists detected rule indicators (`job_id`, `severity`, `category`, `source_ip`).
- `GET /api/detections/{id}`: Returns single detection with explainability narrative.

### Incidents
- `GET /api/incidents`: Lists correlated incidents (`job_id`, `severity`, `status`, `source_ip`).
- `GET /api/incidents/{id}`: Returns incident with related detections and sample log event evidence.
- `PATCH /api/incidents/{id}`: Updates SOC workflow state (`status`: `NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).

### Dashboard & Metrics
- `GET /api/dashboard/stats`: Aggregated metrics, temporal event charts, severity distribution, category counts, top source IPs, and targeted endpoints.

### Rules Configuration
- `GET /api/rules`: Lists active detection rules with thresholds and time windows.
- `PATCH /api/rules/{id}`: Dynamically adjusts threshold, time window, severity, or enabled state.

### Security Reports
- `POST /api/reports/generate`: Generates a professional ReportLab PDF report for an analysis job.
- `GET /api/reports`: Lists generated PDF reports.
- `GET /api/reports/{id}/download`: Streams binary PDF deliverable.

### Audit Ledger
- `GET /api/audit`: Returns immutable administrative audit records.
