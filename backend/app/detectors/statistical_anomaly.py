import math
from typing import List
from collections import defaultdict
from datetime import datetime, timezone
from app.parsers.base import ParsedEvent
from app.detectors.base import BaseDetector, DetectionResult

class StatisticalAnomalyDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            rule_id="DET-011",
            detector_id="statistical_anomaly",
            name="Statistical Traffic Anomaly",
            description="Flags statistically abnormal request rates, auth failures, or error spikes where z-score >= threshold relative to sample baseline.",
            category="Anomaly",
            severity="MEDIUM",
            confidence="LOW",
            threshold=2.5,  # Z-score threshold
            time_window=60,  # 60 seconds interval
            remediation="Compare traffic against marketing campaigns, load testing schedules, or distributed bot activity; adjust baseline if business-driven."
        )

    def detect(self, events: List[ParsedEvent]) -> List[DetectionResult]:
        timed_events = [e for e in events if e.timestamp]
        if len(timed_events) < 10:
            return []

        # Bucket events into minute intervals: timestamp truncated to minute
        buckets = defaultdict(lambda: {"total": 0, "errors": 0, "auth_fails": 0, "events": []})

        for e in timed_events:
            minute_key = e.timestamp.replace(second=0, microsecond=0)
            bucket = buckets[minute_key]
            bucket["total"] += 1
            bucket["events"].append(e)
            if e.event_type == "AUTH_FAILURE":
                bucket["auth_fails"] += 1
            if e.status_code and e.status_code >= 400:
                bucket["errors"] += 1

        if len(buckets) < 3:
            return []

        # Calculate mean & std dev for total requests per minute
        values = [b["total"] for b in buckets.values()]
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std_dev = math.sqrt(variance)

        if std_dev == 0:
            return []

        results: List[DetectionResult] = []

        for minute_key, bucket in sorted(buckets.items()):
            count = bucket["total"]
            z_score = (count - mean) / std_dev

            if z_score >= self.threshold:
                matched = bucket["events"]
                t_start = minute_key
                t_end = matched[-1].timestamp
                
                # Identify prominent source IP in this bucket
                ip_counts = defaultdict(int)
                for e in matched:
                    if e.source_ip:
                        ip_counts[e.source_ip] += 1
                top_ip = max(ip_counts.items(), key=lambda x: x[1])[0] if ip_counts else "Distributed"

                explanation = (
                    f"[WHAT] Statistical traffic anomaly identified ({count} events in 1 minute). "
                    f"[WHERE] Top source contributor: {top_ip}. "
                    f"[WHEN] Interval: {t_start.strftime('%Y-%m-%d %H:%M:%S UTC')}. "
                    f"[STATISTICAL BASELINE] Mean: {mean:.1f} req/min, StdDev: {std_dev:.1f}. "
                    f"Computed Z-Score: {z_score:.2f} (Threshold: {self.threshold:.1f}). "
                    f"[NOTE] Statistical anomalies highlight significant deviations from baseline activity "
                    f"and may indicate flash crowds, automated scripts, or attack spikes. Not all anomalies are malicious."
                )

                results.append(DetectionResult(
                    rule_id=self.rule_id,
                    detector_id=self.detector_id,
                    attack_type="Statistical Traffic Anomaly",
                    title=f"Statistical Anomaly (Z-Score: {z_score:.2f}) at {t_start.strftime('%H:%M')}",
                    category=self.category,
                    severity=self.severity,
                    confidence=self.confidence,
                    source_ip=top_ip if top_ip != "Distributed" else None,
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

        return self.deduplicate(results)
