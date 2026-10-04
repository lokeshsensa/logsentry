from typing import List
from collections import defaultdict
from datetime import timedelta
from app.parsers.base import ParsedEvent
from app.detectors.base import BaseDetector, DetectionResult

class ResourceEnumerationDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            rule_id="DET-009",
            detector_id="sensitive_resource_enum",
            name="Sensitive Resource Enumeration",
            description="Detects requests targeting sensitive, hidden, or administrative resources (e.g., /.env, /admin, /config, /etc/passwd, /backup).",
            category="Reconnaissance",
            severity="HIGH",
            confidence="HIGH",
            threshold=3.0,  # 3 sensitive path requests
            time_window=180,  # 3 minutes
            remediation="Block scanning source IP at firewall/WAF; verify that web root contains no sensitive config or backup files; ensure directory listing is disabled."
        )

    SENSITIVE_PATTERNS = [
        "/.env", "/admin", "/config", "/backup", "/etc/passwd", "/.git",
        "/wp-admin", "/phpmyadmin", "/setup", "/test", "/actuator", "/swagger",
        "/web.config", "/.svn", "/server-status", "/database.sql", "/dump.sql"
    ]

    def _is_sensitive_path(self, endpoint: str) -> bool:
        if not endpoint:
            return False
        ep_lower = endpoint.lower()
        return any(pattern in ep_lower for pattern in self.SENSITIVE_PATTERNS)

    def detect(self, events: List[ParsedEvent]) -> List[DetectionResult]:
        enum_events = [
            e for e in events
            if e.source_ip and e.timestamp and self._is_sensitive_path(e.endpoint or "")
        ]

        if not enum_events:
            return []

        by_ip = defaultdict(list)
        for e in enum_events:
            by_ip[e.source_ip].append(e)

        results: List[DetectionResult] = []
        window_delta = timedelta(seconds=self.time_window)

        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda x: x.timestamp)
            n = len(ip_events)
            left = 0

            while left < n:
                right = left
                sensitive_paths = set()
                while right < n and (ip_events[right].timestamp - ip_events[left].timestamp) <= window_delta:
                    sensitive_paths.add(ip_events[right].endpoint)
                    right += 1

                count = right - left
                if count >= self.threshold:
                    matched = ip_events[left:right]
                    t_start = matched[0].timestamp
                    t_end = matched[-1].timestamp
                    sample_paths = ", ".join(sorted(list(sensitive_paths))[:5])

                    explanation = self.generate_explanation(
                        count=count,
                        source_ip=ip,
                        first_seen=t_start,
                        last_seen=t_end,
                        threshold=int(self.threshold),
                        window_sec=self.time_window,
                        extra_context=f"Targeted sensitive files and directories: [{sample_paths}]. Strong indicator of directory busting / web vulnerability scanning."
                    )

                    results.append(DetectionResult(
                        rule_id=self.rule_id,
                        detector_id=self.detector_id,
                        attack_type="Sensitive Resource Enumeration",
                        title=f"Directory/Resource Enumeration from {ip}",
                        category=self.category,
                        severity=self.severity,
                        confidence=self.confidence,
                        source_ip=ip,
                        target_endpoint=list(sensitive_paths)[0],
                        first_seen=t_start,
                        last_seen=t_end,
                        event_count=count,
                        threshold=self.threshold,
                        time_window=self.time_window,
                        explanation=explanation,
                        remediation=self.remediation,
                        related_event_indices=[e.line_number or 0 for e in matched]
                    ))
                    left = right
                else:
                    left += 1

        return self.deduplicate(results)
