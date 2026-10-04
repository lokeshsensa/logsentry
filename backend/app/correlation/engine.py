from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime, timezone
from app.parsers.base import ParsedEvent
from app.detectors.base import DetectionResult

class CorrelatedIncidentData:
    def __init__(
        self,
        title: str,
        severity: str,
        confidence: str,
        source_ip: Optional[str],
        first_seen: datetime,
        last_seen: datetime,
        event_count: int,
        detections: List[DetectionResult],
        explanation: str,
        remediation: str,
        attack_stages: List[str]
    ):
        self.title = title
        self.severity = severity
        self.confidence = confidence
        self.source_ip = source_ip
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.event_count = event_count
        self.detections = detections
        self.explanation = explanation
        self.remediation = remediation
        self.attack_stages = attack_stages
        self.risk_score: float = 0.0
        self.risk_level: str = "LOW"
        self.risk_breakdown: Dict[str, Any] = {}

class CorrelationEngine:
    """
    Correlates atomic detections and log events into high-level, context-rich security Incidents.
    """
    def correlate(
        self,
        detections: List[DetectionResult],
        events: List[ParsedEvent]
    ) -> List[CorrelatedIncidentData]:
        if not detections:
            return []

        # Group detections by source IP
        by_ip: Dict[str, List[DetectionResult]] = defaultdict(list)
        unassociated: List[DetectionResult] = []

        for det in detections:
            if det.source_ip:
                by_ip[det.source_ip].append(det)
            else:
                unassociated.append(det)

        incidents: List[CorrelatedIncidentData] = []

        # Find any successful logins or sudo events per source IP from raw events
        successful_logins_by_ip = defaultdict(list)
        privilege_events_by_ip = defaultdict(list)
        for ev in events:
            if ev.source_ip:
                if ev.event_type == "AUTH_SUCCESS":
                    successful_logins_by_ip[ev.source_ip].append(ev)
                elif ev.event_type == "PRIVILEGE_EVENT":
                    privilege_events_by_ip[ev.source_ip].append(ev)

        # Correlate per source IP
        for ip, ip_dets in by_ip.items():
            rule_ids = {d.rule_id for d in ip_dets}
            attack_types = {d.attack_type for d in ip_dets}
            first_seen = min(d.first_seen for d in ip_dets)
            last_seen = max(d.last_seen for d in ip_dets)
            total_events = sum(d.event_count for d in ip_dets)
            
            stages = []
            has_auth_attack = bool(rule_ids & {"DET-001", "DET-002", "DET-003"})
            has_recon = bool(rule_ids & {"DET-006", "DET-009"})
            has_web_exploit = bool(rule_ids & {"DET-004", "DET-008", "DET-010"})
            has_priv_det = "DET-007" in rule_ids or len(privilege_events_by_ip[ip]) > 0
            has_auth_success = len(successful_logins_by_ip[ip]) > 0

            # 1. Multi-Stage Account Takeover Scenario
            if has_auth_attack and has_auth_success and has_priv_det:
                stages = ["Reconnaissance/Brute-Force", "Successful Authentication", "Privilege Escalation"]
                title = f"CRITICAL Multi-Stage Account Compromise & Privilege Escalation from {ip}"
                severity = "CRITICAL"
                confidence = "HIGH"
                explanation = (
                    f"[INCIDENT SUMMARY] High-severity coordinated attack progression detected from {ip}. "
                    f"Phase 1: Attacker executed authentication brute force/credential guessing ({', '.join(attack_types)}). "
                    f"Phase 2: Log records subsequent successful authentication for user. "
                    f"Phase 3: Immediate privilege escalation (sudo/su) activity was observed. "
                    f"Total {total_events} security events observed between {first_seen.strftime('%H:%M:%S')} and {last_seen.strftime('%H:%M:%S')} UTC."
                )
                remediation = (
                    f"1. Immediately isolate host systems accessed by {ip}.\n"
                    f"2. Terminate active sessions and revoke credentials for affected accounts.\n"
                    f"3. Block source IP {ip} at network edge/firewall.\n"
                    f"4. Conduct digital forensics on executed commands and audit sudo logs."
                )
            # 2. Credential Breach (Brute Force + Subsequent Success)
            elif has_auth_attack and has_auth_success:
                stages = ["Brute-Force / Credential Guessing", "Successful Authentication"]
                title = f"Potential Account Compromise (Brute Force followed by Success) from {ip}"
                severity = "HIGH"
                confidence = "HIGH"
                explanation = (
                    f"[INCIDENT SUMMARY] Attacker at {ip} conducted authentication brute force attacks "
                    f"and subsequently succeeded in establishing a verified session. "
                    f"Observed {total_events} events across {len(ip_dets)} detection indicators."
                )
                remediation = (
                    f"1. Force password reset for accounts targeted by {ip}.\n"
                    f"2. Revoke current session tokens and verify multi-factor authentication status.\n"
                    f"3. Place {ip} on network blocklist."
                )
            # 3. Targeted Web Recon & Exploitation
            elif has_recon and has_web_exploit:
                stages = ["Discovery / Scanning", "Vulnerability Probing / Access Denied"]
                title = f"Targeted Web Vulnerability Probing & Reconnaissance Campaign from {ip}"
                severity = "HIGH"
                confidence = "HIGH"
                explanation = (
                    f"[INCIDENT SUMMARY] Correlated reconnaissance activity from {ip}. "
                    f"Source scanned sensitive paths ({', '.join(attack_types)}) triggering repeated "
                    f"authorization denials and error spikes across {total_events} requests."
                )
                remediation = (
                    f"1. Apply IP block on WAF for {ip}.\n"
                    f"2. Validate that target paths are adequately protected by HTTP authentication or restricted subnets.\n"
                    f"3. Inspect web server access logs for potential payload injection."
                )
            # 4. Multi-Vector Credential Assault
            elif len(rule_ids & {"DET-001", "DET-002", "DET-003"}) >= 2:
                stages = ["Password Spraying", "Brute Force", "User Enumeration"]
                title = f"Coordinated Multi-Vector Authentication Attack from {ip}"
                severity = "HIGH"
                confidence = "HIGH"
                explanation = (
                    f"[INCIDENT SUMMARY] Multiple credential attack methodologies ({', '.join(attack_types)}) "
                    f"originated from {ip} across {total_events} events. Indicates automated tooling targeting identities."
                )
                remediation = (
                    f"1. Block {ip} at border gateway/firewall.\n"
                    f"2. Implement global CAPTCHA or proof-of-work on authentication endpoints.\n"
                    f"3. Check for compromised passwords across Active Directory/LDAP/database."
                )
            # 5. Single / Clustered Detection Incident
            else:
                max_sev = "LOW"
                for d in ip_dets:
                    if d.severity == "CRITICAL":
                        max_sev = "CRITICAL"
                    elif d.severity == "HIGH" and max_sev != "CRITICAL":
                        max_sev = "HIGH"
                    elif d.severity == "MEDIUM" and max_sev not in ("CRITICAL", "HIGH"):
                        max_sev = "MEDIUM"

                primary_type = ip_dets[0].attack_type
                stages = [primary_type]
                title = f"Security Incident: {primary_type} Detected from {ip}"
                severity = max_sev
                confidence = ip_dets[0].confidence
                explanation = f"[INCIDENT SUMMARY] {len(ip_dets)} security findings triggered from {ip}. {ip_dets[0].explanation}"
                remediation = ip_dets[0].remediation

            incidents.append(CorrelatedIncidentData(
                title=title,
                severity=severity,
                confidence=confidence,
                source_ip=ip,
                first_seen=first_seen,
                last_seen=last_seen,
                event_count=total_events,
                detections=ip_dets,
                explanation=explanation,
                remediation=remediation,
                attack_stages=stages
            ))

        # Handle unassociated findings (e.g. system-wide statistical anomalies without single IP)
        for det in unassociated:
            incidents.append(CorrelatedIncidentData(
                title=det.title,
                severity=det.severity,
                confidence=det.confidence,
                source_ip=None,
                first_seen=det.first_seen,
                last_seen=det.last_seen,
                event_count=det.event_count,
                detections=[det],
                explanation=det.explanation,
                remediation=det.remediation,
                attack_stages=[det.attack_type]
            ))

        return incidents

correlation_engine = CorrelationEngine()
