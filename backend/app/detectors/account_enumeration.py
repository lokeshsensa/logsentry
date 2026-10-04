from typing import List
from collections import defaultdict
from datetime import timedelta
from app.parsers.base import ParsedEvent
from app.detectors.base import BaseDetector, DetectionResult

class AccountEnumerationDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            rule_id="DET-003",
            detector_id="account_enumeration",
            name="Account Enumeration",
            description="Detects suspicious repeated attempts against many different usernames/accounts to discover valid identities.",
            category="Reconnaissance",
            severity="MEDIUM",
            confidence="MEDIUM",
            threshold=4.0,  # 4 invalid or unassigned accounts
            time_window=300,
            remediation="Normalize error responses across valid and non-existent users; implement honeypot accounts and CAPTCHA."
        )

    def detect(self, events: List[ParsedEvent]) -> List[DetectionResult]:
        enum_events = [
            e for e in events
            if e.source_ip and e.timestamp and (
                "invalid user" in (e.message or "").lower()
                or (e.event_type == "AUTH_FAILURE" and e.username in {"admin", "root", "guest", "test", "support", "user", "oracle", "postgres"})
            )
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
                probed_users = set()
                while right < n and (ip_events[right].timestamp - ip_events[left].timestamp) <= window_delta:
                    if ip_events[right].username:
                        probed_users.add(ip_events[right].username)
                    right += 1

                if len(probed_users) >= self.threshold or (right - left) >= self.threshold:
                    matched = ip_events[left:right]
                    t_start = matched[0].timestamp
                    t_end = matched[-1].timestamp
                    user_list = sorted(list(probed_users))
                    user_str = f" Probed usernames: {', '.join(user_list[:5])}." if user_list else ""

                    explanation = self.generate_explanation(
                        count=len(matched),
                        source_ip=ip,
                        first_seen=t_start,
                        last_seen=t_end,
                        threshold=int(self.threshold),
                        window_sec=self.time_window,
                        extra_context=f"Detected active account enumeration probe targeting {len(probed_users)} usernames.{user_str}"
                    )

                    results.append(DetectionResult(
                        rule_id=self.rule_id,
                        detector_id=self.detector_id,
                        attack_type="Account Enumeration",
                        title=f"Account Enumeration Probing from {ip}",
                        category=self.category,
                        severity=self.severity,
                        confidence=self.confidence,
                        source_ip=ip,
                        target_endpoint="/auth/enum",
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
