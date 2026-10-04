from typing import List
from collections import defaultdict
from datetime import timedelta
from app.parsers.base import ParsedEvent
from app.detectors.base import BaseDetector, DetectionResult

class PrivilegeEventDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            rule_id="DET-007",
            detector_id="privilege_abuse",
            name="Suspicious Privilege-Related Activity",
            description="Detects suspicious privilege escalation attempts, such as failed sudo commands, unauthorized su invocations, or permission denied on root.",
            category="Privilege",
            severity="HIGH",
            confidence="HIGH",
            threshold=2.0,  # 2 suspicious privilege events
            time_window=300,
            remediation="Review /etc/sudoers file, audit user bash history, immediately revoke unauthorized privileges, and investigate the host for potential lateral movement."
        )

    SENSITIVE_TARGETS = {"/etc/shadow", "/etc/passwd", "/root", "/bin/sh", "/bin/bash", "cat /etc/shadow", "chmod", "chown"}

    def detect(self, events: List[ParsedEvent]) -> List[DetectionResult]:
        priv_events = []
        for e in events:
            if not e.timestamp:
                continue
            is_priv = False
            raw_lower = (e.raw_log or "").lower()
            msg_lower = (e.message or "").lower()
            
            # Check for failed privilege escalation or sensitive sudo usage
            if e.event_type == "PRIVILEGE_EVENT" and e.severity in ("HIGH", "MEDIUM"):
                is_priv = True
            elif "incorrect password attempts" in raw_lower or "failed su" in raw_lower or "not in sudoers" in raw_lower:
                is_priv = True
            elif "sudo" in raw_lower and any(target in raw_lower for target in self.SENSITIVE_TARGETS):
                is_priv = True

            if is_priv:
                priv_events.append(e)

        if not priv_events:
            return []

        # Group by username or source_ip
        grouped = defaultdict(list)
        for e in priv_events:
            key = e.source_ip or e.username or "local_system"
            grouped[key].append(e)

        results: List[DetectionResult] = []
        window_delta = timedelta(seconds=self.time_window)

        for key, k_events in grouped.items():
            k_events.sort(key=lambda x: x.timestamp)
            n = len(k_events)
            left = 0

            while left < n:
                right = left
                while right < n and (k_events[right].timestamp - k_events[left].timestamp) <= window_delta:
                    right += 1

                count = right - left
                if count >= self.threshold:
                    matched = k_events[left:right]
                    t_start = matched[0].timestamp
                    t_end = matched[-1].timestamp
                    user_str = matched[0].username or key

                    explanation = self.generate_explanation(
                        count=count,
                        source_ip=matched[0].source_ip or "LocalHost",
                        first_seen=t_start,
                        last_seen=t_end,
                        threshold=int(self.threshold),
                        window_sec=self.time_window,
                        extra_context=f"Subject user '{user_str}' triggered {count} unauthorized or failed privilege escalation operations."
                    )

                    results.append(DetectionResult(
                        rule_id=self.rule_id,
                        detector_id=self.detector_id,
                        attack_type="Privilege Escalation Attempt",
                        title=f"Suspicious Privilege Activity by {user_str}",
                        category=self.category,
                        severity=self.severity,
                        confidence=self.confidence,
                        source_ip=matched[0].source_ip,
                        target_endpoint="sudo/su",
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
