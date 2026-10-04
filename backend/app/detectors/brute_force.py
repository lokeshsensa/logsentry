from typing import List
from collections import defaultdict
from datetime import timedelta
from app.parsers.base import ParsedEvent
from app.detectors.base import BaseDetector, DetectionResult

class BruteForceDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            rule_id="DET-001",
            detector_id="brute_force_auth",
            name="Brute Force Authentication",
            description="Detects multiple failed authentication attempts from the same IP within a sliding time window.",
            category="Authentication",
            severity="HIGH",
            confidence="HIGH",
            threshold=5.0,
            time_window=300,
            remediation="Enforce temporary IP rate-limit/ban (e.g. via fail2ban/iptables), reset affected credentials, and enable Multi-Factor Authentication (MFA)."
        )

    def detect(self, events: List[ParsedEvent]) -> List[DetectionResult]:
        # Filter for auth failure events with valid source_ip and timestamp
        auth_failures = [
            e for e in events
            if e.source_ip and e.timestamp and e.event_type == "AUTH_FAILURE"
        ]

        if not auth_failures:
            return []

        # Group by source IP
        by_ip = defaultdict(list)
        for e in auth_failures:
            by_ip[e.source_ip].append(e)

        results: List[DetectionResult] = []
        window_delta = timedelta(seconds=self.time_window)

        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda x: x.timestamp)
            n = len(ip_events)
            left = 0
            
            while left < n:
                right = left
                while right < n and (ip_events[right].timestamp - ip_events[left].timestamp) <= window_delta:
                    right += 1

                count = right - left
                if count >= self.threshold:
                    matched = ip_events[left:right]
                    t_start = matched[0].timestamp
                    t_end = matched[-1].timestamp
                    usernames = list({e.username for e in matched if e.username})
                    user_str = f" Targeted accounts: {', '.join(usernames[:5])}." if usernames else ""
                    
                    explanation = self.generate_explanation(
                        count=count,
                        source_ip=ip,
                        first_seen=t_start,
                        last_seen=t_end,
                        threshold=int(self.threshold),
                        window_sec=self.time_window,
                        extra_context=f"Recorded {count} failed logins.{user_str}"
                    )

                    results.append(DetectionResult(
                        rule_id=self.rule_id,
                        detector_id=self.detector_id,
                        attack_type="Brute Force",
                        title=f"Brute Force Authentication from {ip}",
                        category=self.category,
                        severity=self.severity,
                        confidence=self.confidence,
                        source_ip=ip,
                        target_endpoint=matched[0].endpoint or "/ssh/login",
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
