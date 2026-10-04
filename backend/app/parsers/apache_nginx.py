import re
from datetime import datetime, timezone
from typing import Optional
from app.parsers.base import BaseLogParser, ParsedEvent

class ApacheNginxParser(BaseLogParser):
    @property
    def parser_name(self) -> str:
        return "APACHE_NGINX"

    # Regex matching Common & Combined Log Format
    # IP - USER [TIMESTAMP] "METHOD ENDPOINT PROTOCOL" STATUS BYTES "REFERER" "USER_AGENT"
    COMBINED_RE = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
    )

    MONTH_MAP = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
    }

    def _parse_clf_time(self, time_str: str) -> Optional[datetime]:
        # Example: 10/Oct/2026:13:55:36 +0000 or without tz
        try:
            # 10/Oct/2026:13:55:36
            parts = time_str.split(" ")
            dt_part = parts[0]
            d, m_str, rest = dt_part.split("/")
            y, h, minute, s = rest.split(":")
            month = self.MONTH_MAP.get(m_str, 1)
            
            # Simple UTC parse
            dt = datetime(int(y), month, int(d), int(h), int(minute), int(s), tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    def can_parse(self, sample_lines: list[str]) -> bool:
        matches = 0
        for line in sample_lines:
            line = line.strip()
            if not line:
                continue
            if self.COMBINED_RE.match(line):
                matches += 1
        return matches >= max(1, len(sample_lines) // 4)

    def parse_line(self, line: str, line_number: int = 1) -> Optional[ParsedEvent]:
        raw_line = line.strip()
        if not raw_line:
            return None

        match = self.COMBINED_RE.match(raw_line)
        if not match:
            # Try looser web line match
            parts = raw_line.split('"')
            if len(parts) >= 3:
                # May be slightly unusual quotes
                pass
            return None

        data = match.groupdict()
        source_ip = data["ip"]
        raw_user = data["user"]
        username = raw_user if raw_user != "-" else None
        
        timestamp = self._parse_clf_time(data["time"])
        if not timestamp:
            timestamp = datetime.now(timezone.utc)

        status_code = int(data["status"])
        
        # Parse request line: "GET /index.html HTTP/1.1"
        req_parts = data["request"].strip().split()
        method = None
        endpoint = None
        protocol = "HTTP/1.1"

        if len(req_parts) >= 1:
            method = req_parts[0].upper()
        if len(req_parts) >= 2:
            endpoint = req_parts[1]
        if len(req_parts) >= 3:
            protocol = req_parts[2]

        # Determine event type & severity
        event_type = "HTTP_REQUEST"
        severity = "INFORMATIONAL"

        endpoint_lower = (endpoint or "").lower()
        is_auth_endpoint = any(k in endpoint_lower for k in ("login", "signin", "auth", "session", "oauth"))

        if status_code == 401:
            event_type = "AUTH_FAILURE"
            severity = "MEDIUM"
        elif status_code == 403:
            event_type = "ACCESS_DENIED"
            severity = "MEDIUM"
        elif status_code == 404:
            event_type = "HTTP_ERROR"
            severity = "LOW"
        elif 400 <= status_code < 500:
            event_type = "HTTP_ERROR"
            severity = "LOW"
        elif status_code >= 500:
            event_type = "HTTP_ERROR"
            severity = "MEDIUM"
        elif status_code in (200, 201, 302) and is_auth_endpoint and method == "POST":
            event_type = "AUTH_SUCCESS"
            severity = "INFORMATIONAL"

        message = f'{method or "REQUEST"} {endpoint or "/"} -> {status_code}'

        return ParsedEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=None,
            username=username,
            event_type=event_type,
            method=method,
            endpoint=endpoint,
            status_code=status_code,
            protocol=protocol,
            source_port=None,
            destination_port=443 if protocol == "HTTPS" else 80,
            process="webserver",
            message=message,
            raw_log=raw_line,
            severity=severity,
            line_number=line_number
        )
