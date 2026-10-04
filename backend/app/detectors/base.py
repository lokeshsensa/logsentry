from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime
from app.parsers.base import ParsedEvent

@dataclass
class DetectionResult:
    rule_id: str
    detector_id: str
    attack_type: str
    title: str
    category: str
    severity: str
    confidence: str
    source_ip: Optional[str]
    target_endpoint: Optional[str]
    first_seen: datetime
    last_seen: datetime
    event_count: int
    threshold: float
    time_window: int
    explanation: str
    remediation: str
    related_event_indices: List[int]  # Line numbers or event indices

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "detector_id": self.detector_id,
            "attack_type": self.attack_type,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "source_ip": self.source_ip,
            "target_endpoint": self.target_endpoint,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "threshold": self.threshold,
            "time_window": self.time_window,
            "explanation": self.explanation,
            "remediation": self.remediation,
            "related_event_indices": self.related_event_indices,
        }

class BaseDetector(ABC):
    def __init__(
        self,
        rule_id: str,
        detector_id: str,
        name: str,
        description: str,
        category: str,
        severity: str,
        confidence: str,
        threshold: float,
        time_window: int,
        remediation: str
    ):
        self.rule_id = rule_id
        self.detector_id = detector_id
        self.name = name
        self.description = description
        self.category = category
        self.severity = severity
        self.confidence = confidence
        self.threshold = threshold
        self.time_window = time_window  # in seconds
        self.remediation = remediation

    def update_config(self, threshold: Optional[float] = None, time_window: Optional[int] = None, severity: Optional[str] = None):
        if threshold is not None:
            self.threshold = threshold
        if time_window is not None:
            self.time_window = time_window
        if severity is not None:
            self.severity = severity

    @abstractmethod
    def detect(self, events: List[ParsedEvent]) -> List[DetectionResult]:
        """Run detection logic over ordered events and return findings"""
        pass

    def deduplicate(self, results: List[DetectionResult]) -> List[DetectionResult]:
        """
        Deduplicate overlapping windows for the same source and detector.
        Combines adjacent or overlapping time windows into a single comprehensive finding.
        """
        if not results:
            return []

        # Sort by source_ip and first_seen
        sorted_res = sorted(results, key=lambda x: (x.source_ip or "", x.first_seen))
        deduped = []
        current = sorted_res[0]

        for next_item in sorted_res[1:]:
            # If same source_ip and time ranges overlap or within window
            if (
                current.source_ip == next_item.source_ip
                and current.rule_id == next_item.rule_id
                and next_item.first_seen <= current.last_seen
            ):
                # Merge into current
                current.last_seen = max(current.last_seen, next_item.last_seen)
                current.event_count = max(current.event_count, current.event_count + next_item.event_count - len(set(current.related_event_indices) & set(next_item.related_event_indices)))
                current.related_event_indices = sorted(list(set(current.related_event_indices + next_item.related_event_indices)))
                # Update explanation
                current.explanation = self.generate_explanation(
                    count=current.event_count,
                    source_ip=current.source_ip or "Unknown",
                    first_seen=current.first_seen,
                    last_seen=current.last_seen,
                    threshold=int(self.threshold),
                    window_sec=self.time_window
                )
            else:
                deduped.append(current)
                current = next_item

        deduped.append(current)
        return deduped

    def generate_explanation(
        self,
        count: int,
        source_ip: str,
        first_seen: datetime,
        last_seen: datetime,
        threshold: int,
        window_sec: int,
        extra_context: str = ""
    ) -> str:
        """
        Build an explainable narrative answering:
        WHAT happened? WHY was it detected? WHEN did it happen? WHERE did it originate?
        HOW many events were involved? WHY is it considered suspicious? WHAT should be investigated?
        """
        t1 = first_seen.strftime("%Y-%m-%d %H:%M:%S UTC")
        t2 = last_seen.strftime("%Y-%m-%d %H:%M:%S UTC")
        mins = max(1, window_sec // 60)
        
        return (
            f"[WHAT] Detected {count} matching security events for {self.name}. "
            f"[WHERE] Originated from source IP: {source_ip}. "
            f"[WHEN] Observed between {t1} and {t2}. "
            f"[WHY] Configured threshold is {threshold} events within {mins} minutes ({window_sec}s). "
            f"The observed activity ({count} events) exceeded this limit. {extra_context}"
            f"[WHY SUSPICIOUS] Exceeding this baseline indicates automated or adversarial behavior rather than standard benign operation. "
            f"[WHAT TO INVESTIGATE] Verify if {source_ip} belongs to authorized personnel or automated scripts. Inspect surrounding firewall logs and targeted accounts."
        )
