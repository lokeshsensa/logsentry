from typing import List
from collections import defaultdict
from datetime import timedelta
from app.parsers.base import ParsedEvent
from app.detectors.base import BaseDetector, DetectionResult

class SuspiciousMethodsDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            rule_id="DET-008",
            detector_id="suspicious_http_methods",
            name="Unusual HTTP Methods",
            description="Detects unexpected or risky HTTP request methods (PUT, DELETE, TRACE, CONNECT) targeting web servers.",
            category="Web",
            severity="LOW",
            confidence="MEDIUM",
            threshold=2.0,
            time_window=300,
            remediation="Restrict HTTP methods on web server to strictly necessary verbs (GET/POST); disable TRACE and TRACK to prevent XST attacks."
        )

    SUSPICIOUS_VERBS = {"PUT", "DELETE", "TRACE", "TRACK", "CONNECT", "DEBUG"}

    def detect(self, events: List[ParsedEvent]) -> List[DetectionResult]:
        verb_events = [
            e for e in events
            if e.source_ip and e.timestamp and e.method and e.method.upper() in self.SUSPICIOUS_VERBS
        ]

        if not verb_events:
            return []

        by_ip = defaultdict(list)
        for e in verb_events:
            by_ip[e.source_ip].append(e)

        results: List[DetectionResult] = []
        window_delta = timedelta(seconds=self.time_window)

        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda x: x.timestamp)
            n = len(ip_events)
            left = 0

            while left < n:
                right = left
                methods_seen = set()
                while right < n and (ip_events[right].timestamp - ip_events[left].timestamp) <= window_delta:
                    methods_seen.add(ip_events[right].method.upper())
                    right += 1

                count = right - left
                if count >= self.threshold:
                    matched = ip_events[left:right]
                    t_start = matched[0].timestamp
                    t_end = matched[-1].timestamp
                    method_str = ", ".join(sorted(list(methods_seen)))

                    explanation = self.generate_explanation(
                        count=count,
                        source_ip=ip,
                        first_seen=t_start,
                        last_seen=t_end,
                        threshold=int(self.threshold),
                        window_sec=self.time_window,
                        extra_context=f"Detected unusual HTTP methods ({method_str}) which are typically disabled or indicative of web probing."
                    )

                    results.append(DetectionResult(
                        rule_id=self.rule_id,
                        detector_id=self.detector_id,
                        attack_type="Unusual HTTP Methods",
                        title=f"Unusual HTTP Methods ({method_str}) from {ip}",
                        category=self.category,
                        severity=self.severity,
                        confidence=self.confidence,
                        source_ip=ip,
                        target_endpoint=matched[0].endpoint or "/",
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
