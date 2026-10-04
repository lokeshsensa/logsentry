import re
from datetime import datetime, timezone
from typing import Optional
from app.parsers.base import BaseLogParser, ParsedEvent

class GenericParser(BaseLogParser):
    @property
    def parser_name(self) -> str:
        return "GENERIC"

    TIMESTAMP_PATTERNS = [
        re.compile(r"^(?P<dt>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
        re.compile(r"^(?P<dt>\d{4}/\d{2}/\d{2}[T\s]\d{2}:\d{2}:\d{2})"),
        re.compile(r"\[(?P<dt>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]"),
    ]

    IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    USER_RE = re.compile(r"(?:user(?:name)?|account)[=:\s]+['\"]?([a-zA-Z0-9_\-\.]+)['\"]?", re.IGNORECASE)
    STATUS_RE = re.compile(r"(?:status(?:_code)?|code)[=:\s]+(\d{3})", re.IGNORECASE)
    ENDPOINT_RE = re.compile(r"(?:path|endpoint|uri|url)[=:\s]+([/\w\-\.]+)", re.IGNORECASE)
    LEVEL_RE = re.compile(r"\b(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\b", re.IGNORECASE)

    def can_parse(self, sample_lines: list[str]) -> bool:
        # Fallback parser - matches if any lines have timestamp or log level
        for line in sample_lines:
            if any(p.search(line) for p in self.TIMESTAMP_PATTERNS) or self.LEVEL_RE.search(line):
                return True
        return len(sample_lines) > 0

    def parse_line(self, line: str, line_number: int = 1) -> Optional[ParsedEvent]:
        raw_line = line.strip()
        if not raw_line:
            return None

        timestamp = None
        for p in self.TIMESTAMP_PATTERNS:
            match = p.search(raw_line)
            if match:
                dt_str = match.group("dt").replace("Z", "+00:00")
                try:
                    timestamp = datetime.fromisoformat(dt_str)
                    if timestamp.tzinfo is None:
                        timestamp = timestamp.replace(tzinfo=timezone.utc)
                except Exception:
                    pass
                break
        
        if not timestamp:
            timestamp = datetime.now(timezone.utc)

        # Source IP
        source_ip = None
        ip_match = self.IP_RE.search(raw_line)
        if ip_match:
            source_ip = ip_match.group(0)

        # Username
        username = None
        user_match = self.USER_RE.search(raw_line)
        if user_match:
            username = user_match.group(1)

        # Status code
        status_code = None
        status_match = self.STATUS_RE.search(raw_line)
        if status_match:
            status_code = int(status_match.group(1))

        # Endpoint
        endpoint = None
        endpoint_match = self.ENDPOINT_RE.search(raw_line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)

        # Log level
        level = "INFO"
        level_match = self.LEVEL_RE.search(raw_line)
        if level_match:
            level = level_match.group(1).upper()

        lower_line = raw_line.lower()
        event_type = "APPLICATION_EVENT"
        severity = "INFORMATIONAL"

        if "failed password" in lower_line or "auth failure" in lower_line or "login failed" in lower_line or status_code == 401:
            event_type = "AUTH_FAILURE"
            severity = "MEDIUM"
        elif "login successful" in lower_line or "login success" in lower_line or "accepted password" in lower_line:
            event_type = "AUTH_SUCCESS"
            severity = "INFORMATIONAL"
        elif "access denied" in lower_line or "permission denied" in lower_line or status_code == 403:
            event_type = "ACCESS_DENIED"
            severity = "MEDIUM"
        elif "sudo" in lower_line or "privilege" in lower_line:
            event_type = "PRIVILEGE_EVENT"
            severity = "HIGH" if "fail" in lower_line or "error" in lower_line else "LOW"
        elif level in ("ERROR", "CRITICAL", "FATAL"):
            event_type = "SYSTEM_ERROR"
            severity = "HIGH" if level in ("CRITICAL", "FATAL") else "MEDIUM"
        elif level in ("WARN", "WARNING"):
            severity = "LOW"

        return ParsedEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=None,
            username=username,
            event_type=event_type,
            method=None,
            endpoint=endpoint,
            status_code=status_code,
            protocol="APP",
            source_port=None,
            destination_port=None,
            process="app",
            message=raw_line,
            raw_log=raw_line,
            severity=severity,
            line_number=line_number
        )
