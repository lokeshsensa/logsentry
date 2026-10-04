from typing import List
from collections import defaultdict
from datetime import timedelta
from app.parsers.base import ParsedEvent
from app.detectors.base import BaseDetector, DetectionResult

class AccessDeniedDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            rule_id="DET-010",
            detector_id="repeated_access_denied",
            name="Repeated Access Denied",
            description="Detects repeated 403 Forbidden, permission denied, or access denied events from the same source.",
            category="Web",
            severity="MEDIUM",
            confidence="HIGH",
            threshold=4.0,  # 4 access denied events
            time_window=180,  # 3 minutes
            remediation="Review access control policies, verify authentication tokens, inspect for authorization bypass attempts or broken object level authorization (BOLA)."
        )

    def detect(self, events: List[ParsedEvent]) -> List[DetectionResult]:
        denied_events = [
            e for e in events
            if e.source_ip and e.timestamp and (
                e.status_code == 403
                or e.event_type == "ACCESS_DENIED"
                or "permission denied" in (e.message or "").lower()
                or "access denied" in (e.message or "").lower()
            )
        ]

        if not denied_events:
            return []

        by_ip = defaultdict(list)
        for e in denied_events:
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

                    explanation = self.generate_explanation(
                        count=count,
                        source_ip=ip,
                        first_seen=t_start,
                        last_seen=t_end,
                        threshold=int(self.threshold),
                        window_sec=self.time_window,
                        extra_context=f"Persistent authorization failures observed. Offender repeatedly attempted to access restricted resources."
                    )

                    results.append(DetectionResult(
                        rule_id=self.rule_id,
                        detector_id=self.detector_id,
                        attack_type="Repeated Access Denied",
                        title=f"Repeated Access Denied Events from {ip}",
                        category=self.category,
                        severity=self.severity,
                        confidence=self.confidence,
                        source_ip=ip,
                        target_endpoint=matched[0].endpoint or "/restricted",
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
