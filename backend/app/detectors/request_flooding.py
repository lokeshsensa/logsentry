from typing import List
from collections import defaultdict
from datetime import timedelta
from app.parsers.base import ParsedEvent
from app.detectors.base import BaseDetector, DetectionResult

class RequestFloodingDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            rule_id="DET-005",
            detector_id="request_flooding",
            name="Request Flooding (DoS Indicator)",
            description="Detects an abnormally high request frequency from a single source IP in a short duration.",
            category="Anomaly",
            severity="HIGH",
            confidence="HIGH",
            threshold=40.0,
            time_window=30,  # 30 seconds
            remediation="Implement edge rate-limiting / leaky-bucket filtering; challenge with CAPTCHA or drop traffic via firewall."
        )

    def detect(self, events: List[ParsedEvent]) -> List[DetectionResult]:
        requests = [
            e for e in events
            if e.source_ip and e.timestamp
        ]

        if not requests:
            return []

        by_ip = defaultdict(list)
        for e in requests:
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
                    rate = round(count / max(1, (t_end - t_start).total_seconds()), 1)

                    explanation = self.generate_explanation(
                        count=count,
                        source_ip=ip,
                        first_seen=t_start,
                        last_seen=t_end,
                        threshold=int(self.threshold),
                        window_sec=self.time_window,
                        extra_context=f"Observed peak request throughput of approx. {rate} requests/second."
                    )

                    results.append(DetectionResult(
                        rule_id=self.rule_id,
                        detector_id=self.detector_id,
                        attack_type="Request Flooding",
                        title=f"Request Flooding Spike from {ip} ({count} req in {self.time_window}s)",
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
