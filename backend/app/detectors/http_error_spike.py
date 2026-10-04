from typing import List
from collections import defaultdict
from datetime import timedelta
from app.parsers.base import ParsedEvent
from app.detectors.base import BaseDetector, DetectionResult

class HttpErrorSpikeDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            rule_id="DET-004",
            detector_id="http_error_spike",
            name="HTTP Error Spike",
            description="Detects abnormal increases in 401, 403, 404, or 500 error responses from a source IP or endpoint.",
            category="Web",
            severity="MEDIUM",
            confidence="HIGH",
            threshold=12.0,
            time_window=120,
            remediation="Analyze error responses, verify WAF rules, review application health logs, and block abusive IP if non-legitimate."
        )

    def detect(self, events: List[ParsedEvent]) -> List[DetectionResult]:
        error_events = [
            e for e in events
            if e.source_ip and e.timestamp and e.status_code and e.status_code in {401, 403, 404, 500, 502, 503}
        ]

        if not error_events:
            return []

        by_ip = defaultdict(list)
        for e in error_events:
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
                    status_counts = defaultdict(int)
                    for e in matched:
                        status_counts[e.status_code] += 1
                    status_summary = ", ".join([f"{code}: {cnt}x" for code, cnt in sorted(status_counts.items())])

                    explanation = self.generate_explanation(
                        count=count,
                        source_ip=ip,
                        first_seen=t_start,
                        last_seen=t_end,
                        threshold=int(self.threshold),
                        window_sec=self.time_window,
                        extra_context=f"Error status breakdown: {status_summary}."
                    )

                    results.append(DetectionResult(
                        rule_id=self.rule_id,
                        detector_id=self.detector_id,
                        attack_type="HTTP Error Spike",
                        title=f"HTTP Error Spike from {ip} ({count} errors)",
                        category=self.category,
                        severity=self.severity,
                        confidence=self.confidence,
                        source_ip=ip,
                        target_endpoint=matched[0].endpoint or "/web",
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
