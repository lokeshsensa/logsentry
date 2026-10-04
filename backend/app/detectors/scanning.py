from typing import List
from collections import defaultdict
from datetime import timedelta
from app.parsers.base import ParsedEvent
from app.detectors.base import BaseDetector, DetectionResult

class ScanningDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            rule_id="DET-006",
            detector_id="port_endpoint_scanning",
            name="Endpoint / Port Scanning Indicator",
            description="Detects rapid probing of numerous distinct endpoints or destination ports from a single source.",
            category="Reconnaissance",
            severity="MEDIUM",
            confidence="MEDIUM",
            threshold=7.0,  # 7 distinct endpoints or ports
            time_window=60,  # 1 minute
            remediation="Review perimeter firewall rules, inspect targeted URIs/ports, block source IP at network edge if unsolicited scan."
        )

    def detect(self, events: List[ParsedEvent]) -> List[DetectionResult]:
        scan_events = [
            e for e in events
            if e.source_ip and e.timestamp and (e.endpoint or e.destination_port)
        ]

        if not scan_events:
            return []

        by_ip = defaultdict(list)
        for e in scan_events:
            by_ip[e.source_ip].append(e)

        results: List[DetectionResult] = []
        window_delta = timedelta(seconds=self.time_window)

        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda x: x.timestamp)
            n = len(ip_events)
            left = 0

            while left < n:
                right = left
                distinct_targets = set()
                while right < n and (ip_events[right].timestamp - ip_events[left].timestamp) <= window_delta:
                    if ip_events[right].endpoint:
                        distinct_targets.add(f"uri:{ip_events[right].endpoint}")
                    if ip_events[right].destination_port:
                        distinct_targets.add(f"port:{ip_events[right].destination_port}")
                    right += 1

                if len(distinct_targets) >= self.threshold:
                    matched = ip_events[left:right]
                    t_start = matched[0].timestamp
                    t_end = matched[-1].timestamp
                    targets_sample = ", ".join(sorted(list(distinct_targets))[:6])

                    explanation = self.generate_explanation(
                        count=len(matched),
                        source_ip=ip,
                        first_seen=t_start,
                        last_seen=t_end,
                        threshold=int(self.threshold),
                        window_sec=self.time_window,
                        extra_context=f"Targeted {len(distinct_targets)} distinct endpoints/ports ({targets_sample}). Classified as possible reconnaissance activity."
                    )

                    results.append(DetectionResult(
                        rule_id=self.rule_id,
                        detector_id=self.detector_id,
                        attack_type="Reconnaissance / Scanning",
                        title=f"Port/Endpoint Scanning Activity from {ip}",
                        category=self.category,
                        severity=self.severity,
                        confidence=self.confidence,
                        source_ip=ip,
                        target_endpoint=f"{len(distinct_targets)} distinct targets",
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
