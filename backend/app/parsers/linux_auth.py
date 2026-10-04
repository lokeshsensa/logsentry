import re
from datetime import datetime, timezone
from typing import Optional
from app.parsers.base import BaseLogParser, ParsedEvent

# Month name mapping
MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

class LinuxAuthParser(BaseLogParser):
    @property
    def parser_name(self) -> str:
        return "LINUX_AUTH"

    # Regex patterns
    SYSLOG_PREFIX_RE = re.compile(
        r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>[^\s]+)\s+(?P<process>[A-Za-z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
    )
    ISO_PREFIX_RE = re.compile(
        r"^(?P<isotime>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>[^\s]+)\s+(?P<process>[A-Za-z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
    )
    
    IP_RE = re.compile(r"(?:from\s+)?(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)")
    PORT_RE = re.compile(r"port\s+(\d+)")
    
    # Specific message matchers
    SSH_FAILED_RE = re.compile(r"Failed password for (?:invalid user )?([a-zA-Z0-9_\-\.]+) from ([0-9\.]+)(?: port (\d+))?")
    SSH_ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for ([a-zA-Z0-9_\-\.]+) from ([0-9\.]+)(?: port (\d+))?")
    SSH_INVALID_RE = re.compile(r"Invalid user ([a-zA-Z0-9_\-\.]+) from ([0-9\.]+)")
    SUDO_RE = re.compile(r"([a-zA-Z0-9_\-\.]+)\s*:\s*(?:(?P<error>\d+ incorrect password attempts|authentication failure|user NOT in sudoers)\s*;)?.*USER=([a-zA-Z0-9_\-\.]+)\s*;\s*COMMAND=(.*)")
    SU_FAILED_RE = re.compile(r"FAILED SU \(to ([a-zA-Z0-9_\-\.]+)\)\s*([a-zA-Z0-9_\-\.]+)?")
    SU_SUCCESS_RE = re.compile(r"Successful su for ([a-zA-Z0-9_\-\.]+) by ([a-zA-Z0-9_\-\.]+)")

    def can_parse(self, sample_lines: list[str]) -> bool:
        matches = 0
        for line in sample_lines:
            line = line.strip()
            if not line:
                continue
            if self.SYSLOG_PREFIX_RE.match(line) or self.ISO_PREFIX_RE.match(line):
                # Check for common linux auth keywords
                if any(k in line for k in ("sshd", "sudo", "su", "pam_unix", "auth", "login")):
                    matches += 1
        return matches >= max(1, len(sample_lines) // 4)

    def parse_line(self, line: str, line_number: int = 1) -> Optional[ParsedEvent]:
        raw_line = line.strip()
        if not raw_line:
            return None

        timestamp = None
        process = None
        message = raw_line
        
        # Check syslog prefix
        match_syslog = self.SYSLOG_PREFIX_RE.match(raw_line)
        if match_syslog:
            groups = match_syslog.groupdict()
            month = MONTH_MAP.get(groups["month"], 1)
            day = int(groups["day"])
            now = datetime.now(timezone.utc)
            # Default to current year
            time_parts = [int(p) for p in groups["time"].split(":")]
            timestamp = datetime(now.year, month, day, time_parts[0], time_parts[1], time_parts[2], tzinfo=timezone.utc)
            process = groups["process"]
            message = groups["message"]
        else:
            match_iso = self.ISO_PREFIX_RE.match(raw_line)
            if match_iso:
                groups = match_iso.groupdict()
                isotime = groups["isotime"].replace("Z", "+00:00")
                try:
                    timestamp = datetime.fromisoformat(isotime)
                    if timestamp.tzinfo is None:
                        timestamp = timestamp.replace(tzinfo=timezone.utc)
                except Exception:
                    timestamp = datetime.now(timezone.utc)
                process = groups["process"]
                message = groups["message"]

        # Default normalized attributes
        source_ip = None
        source_port = None
        username = None
        event_type = "SYSTEM_EVENT"
        severity = "INFORMATIONAL"

        # Check for SSH Failed
        ssh_failed = self.SSH_FAILED_RE.search(message)
        if ssh_failed:
            username = ssh_failed.group(1)
            source_ip = ssh_failed.group(2)
            if ssh_failed.group(3):
                source_port = int(ssh_failed.group(3))
            event_type = "AUTH_FAILURE"
            severity = "MEDIUM"
        else:
            # Check for SSH Accepted
            ssh_accepted = self.SSH_ACCEPTED_RE.search(message)
            if ssh_accepted:
                username = ssh_accepted.group(1)
                source_ip = ssh_accepted.group(2)
                if ssh_accepted.group(3):
                    source_port = int(ssh_accepted.group(3))
                event_type = "AUTH_SUCCESS"
                severity = "INFORMATIONAL"
            else:
                # Check for Invalid user
                ssh_invalid = self.SSH_INVALID_RE.search(message)
                if ssh_invalid:
                    username = ssh_invalid.group(1)
                    source_ip = ssh_invalid.group(2)
                    event_type = "AUTH_FAILURE"
                    severity = "MEDIUM"
                else:
                    # Sudo activity
                    sudo_match = self.SUDO_RE.search(message)
                    if sudo_match:
                        source_user = sudo_match.group(1)
                        is_error = bool(sudo_match.group("error")) or any(err in message.lower() for err in ("incorrect password", "authentication failure", "not in sudoers", "failed"))
                        target_user = sudo_match.group(3)
                        command = sudo_match.group(4)
                        username = source_user
                        event_type = "PRIVILEGE_EVENT"
                        if is_error:
                            severity = "HIGH"
                            message = f"Sudo privilege failure by {source_user} attempting {command} as {target_user}"
                        else:
                            severity = "LOW" if target_user == "root" else "INFORMATIONAL"
                    else:
                        # Su activity
                        su_fail = self.SU_FAILED_RE.search(message)
                        if su_fail:
                            target_user = su_fail.group(1)
                            source_user = su_fail.group(2)
                            username = source_user or "unknown"
                            event_type = "PRIVILEGE_EVENT"
                            severity = "HIGH"
                        else:
                            su_ok = self.SU_SUCCESS_RE.search(message)
                            if su_ok:
                                target_user = su_ok.group(1)
                                source_user = su_ok.group(2)
                                username = source_user
                                event_type = "PRIVILEGE_EVENT"
                                severity = "INFORMATIONAL"

        # Fallback IP extraction if not captured yet
        if not source_ip:
            ip_found = self.IP_RE.search(message)
            if ip_found:
                source_ip = ip_found.group(1)

        # Fallback port extraction
        if not source_port:
            port_found = self.PORT_RE.search(message)
            if port_found:
                try:
                    source_port = int(port_found.group(1))
                except ValueError:
                    pass

        # Identify generic auth failure strings in message
        if event_type == "SYSTEM_EVENT":
            lower_msg = message.lower()
            if "authentication failure" in lower_msg or "password check failed" in lower_msg or "failed login" in lower_msg:
                event_type = "AUTH_FAILURE"
                severity = "MEDIUM"
            elif "session opened" in lower_msg or "accepted connection" in lower_msg:
                event_type = "AUTH_SUCCESS"
                severity = "INFORMATIONAL"
            elif "permission denied" in lower_msg:
                event_type = "ACCESS_DENIED"
                severity = "MEDIUM"

        return ParsedEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=None,
            username=username,
            event_type=event_type,
            method=None,
            endpoint=None,
            status_code=None,
            protocol="SSH/PAM" if process in ("sshd", "sudo", "su", "pam") else "SYSTEM",
            source_port=source_port,
            destination_port=22 if process == "sshd" else None,
            process=process,
            message=message,
            raw_log=raw_line,
            severity=severity,
            line_number=line_number
        )
