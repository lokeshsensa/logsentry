import pytest
from datetime import datetime, timezone
from app.detectors.base import DetectionResult
from app.correlation.engine import CorrelationEngine
from app.risk.scorer import RiskScorer
from app.parsers.base import ParsedEvent

def test_correlation_multi_stage_compromise():
    engine = CorrelationEngine()
    now = datetime.now(timezone.utc)
    
    det1 = DetectionResult(
        rule_id="DET-001",
        detector_id="brute_force_auth",
        attack_type="Brute Force",
        title="Brute Force from 192.168.1.200",
        category="Authentication",
        severity="HIGH",
        confidence="HIGH",
        source_ip="192.168.1.200",
        target_endpoint="/ssh",
        first_seen=now,
        last_seen=now,
        event_count=10,
        threshold=5.0,
        time_window=300,
        explanation="Brute force auth",
        remediation="Block IP",
        related_event_indices=[1, 2]
    )

    events = [
        ParsedEvent(
            timestamp=now,
            source_ip="192.168.1.200",
            destination_ip=None,
            username="lokesh",
            event_type="AUTH_SUCCESS",
            method=None,
            endpoint=None,
            status_code=None,
            protocol="SSH",
            source_port=None,
            destination_port=22,
            process="sshd",
            message="Accepted password for lokesh",
            raw_log="Accepted password",
            severity="INFORMATIONAL",
            line_number=3
        ),
        ParsedEvent(
            timestamp=now,
            source_ip="192.168.1.200",
            destination_ip=None,
            username="lokesh",
            event_type="PRIVILEGE_EVENT",
            method=None,
            endpoint=None,
            status_code=None,
            protocol="PAM",
            source_port=None,
            destination_port=None,
            process="sudo",
            message="sudo command to root",
            raw_log="sudo /bin/bash",
            severity="HIGH",
            line_number=4
        )
    ]

    incidents = engine.correlate([det1], events)
    assert len(incidents) == 1
    assert "Multi-Stage Account Compromise" in incidents[0].title
    assert incidents[0].severity == "CRITICAL"

def test_risk_scoring_bounds_and_explainability():
    scorer = RiskScorer()
    now = datetime.now(timezone.utc)
    from app.correlation.engine import CorrelatedIncidentData

    inc = CorrelatedIncidentData(
        title="Critical Compromise",
        severity="CRITICAL",
        confidence="HIGH",
        source_ip="1.2.3.4",
        first_seen=now,
        last_seen=now,
        event_count=45,
        detections=[],
        explanation="Targeting root administrator with privilege escalation",
        remediation="Revoke access",
        attack_stages=["Brute Force", "Success", "Privilege Escalation"]
    )

    risk_info = scorer.calculate_incident_risk(inc)
    assert 0 <= risk_info["score"] <= 100
    assert risk_info["level"] in ("HIGH", "CRITICAL")
    assert "Base Severity" in risk_info["breakdown"]
    assert "Correlation" in risk_info["breakdown"]
