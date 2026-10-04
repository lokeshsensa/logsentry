from typing import List
from collections import defaultdict
from datetime import timedelta
from app.parsers.base import ParsedEvent
from app.detectors.base import BaseDetector, DetectionResult

class PasswordSprayingDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            rule_id="DET-002",
            detector_id="password_spraying",
            name="Password Spraying",
            description="Detects repeated authentication failures against multiple distinct usernames from the same source.",
            category="Authentication",
            severity="HIGH",
            confidence="MEDIUM",
            threshold=3.0,  # 3 distinct usernames
            time_window=600,
            remediation="Implement progressive lockout per source IP, monitor for subsequent successful logins on sprayed accounts, enforce strong password policies and MFA."
        )

    def detect(self, events: List[ParsedEvent]) -> List[DetectionResult]:
        auth_failures = [
            e for e in events
            if e.source_ip and e.timestamp and e.event_type == "AUTH_FAILURE" and e.username
        ]

        if not auth_failures:
            return []

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
                distinct_users = set()
                while right < n and (ip_events[right].timestamp - ip_events[left].timestamp) <= window_delta:
                    distinct_users.add(ip_events[right].username)
                    right += 1

                if len(distinct_users) >= self.threshold:
                    matched = ip_events[left:right]
                    t_start = matched[0].timestamp
                    t_end = matched[-1].timestamp
                    user_list = sorted(list(distinct_users))
                    user_preview = ", ".join(user_list[:6])

                    explanation = self.generate_explanation(
                        count=len(matched),
                        source_ip=ip,
                        first_seen=t_start,
                        last_seen=t_end,
                        threshold=int(self.threshold),
                        window_sec=self.time_window,
                        extra_context=f"Attacker targeted {len(distinct_users)} distinct usernames ({user_preview}) indicating horizontal credential guessing."
                    )

                    results.append(DetectionResult(
                        rule_id=self.rule_id,
                        detector_id=self.detector_id,
                        attack_type="Password Spraying",
                        title=f"Password Spraying Campaign from {ip}",
                        category=self.category,
                        severity=self.severity,
                        confidence=self.confidence,
                        source_ip=ip,
                        target_endpoint=matched[0].endpoint or "/auth",
                        first_seen=t_start,
                        last_seen=t_end,
                        event_count=len(matched),
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
