# LOGSENTRY — Defensive Security & Safety Controls

## Mission & Purpose

**LOGSENTRY** is strictly an authorized defensive cybersecurity solution designed for defensive security operations, threat hunting, and educational log analysis. It does **not** include exploit automation, credential harvesting, malware execution, or offensive probes.

---

## Defensive Engineering Controls

### 1. Ingestion & File Handling Safety
- **No Remote Requests**: LOGSENTRY only inspects log records supplied locally. It will never send network requests, ping external hosts, or request discovered endpoints.
- **Strict Filename Sanitization**: Strips path separators (`/`, `\`), null bytes (`\0`), and path traversal sequences (`../`).
- **Whitelisted File Extensions**: Only files ending in `.log`, `.txt`, `.syslog`, and `.gz` are accepted.
- **Upload Size Limits**: Ingestion enforces an explicit 50MB ceiling with stream validation to prevent disk exhaustion.
- **Zero Shell / Subprocess Execution**: Parsers and detectors use native Python standard library and regular expressions. No shell interpreters (`/bin/sh`, `exec`, `subprocess`) are invoked during log processing.

### 2. Injection & Database Safety
- **Parameterized Queries**: All database operations use SQLAlchemy ORM parameterized statements, eliminating SQL injection.
- **Memory Bounded Streams**: Streaming generator pipelines prevent Denial of Service (DoS) from large files exhausting server memory.

### 3. Frontend Content Escaping
- **XSS Prevention**: React automatically escapes untrusted string variables rendered in the DOM.
- **Raw Log Display**: Raw log content and JSON payloads are rendered in `<pre>` blocks using text nodes, preventing script execution from crafted log messages.
