import pytest
from datetime import datetime, timezone, timedelta
from app.parsers.base import ParsedEvent
from app.detectors.brute_force import BruteForceDetector
from app.detectors.password_spraying import PasswordSprayingDetector
from app.detectors.http_error_spike import HttpErrorSpikeDetector
from app.detectors.resource_enumeration import ResourceEnumerationDetector

def test_brute_force_detector():
    detector = BruteForceDetector()
    detector.threshold = 5.0
    detector.time_window = 300

    base_time = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        ParsedEvent(
            timestamp=base_time + timedelta(seconds=i * 10),
            source_ip="192.168.1.100",
            destination_ip=None,
            username="root",
            event_type="AUTH_FAILURE",
            method=None,
            endpoint=None,
            status_code=None,
            protocol="SSH",
            source_port=1000 + i,
            destination_port=22,
            process="sshd",
            message="Failed password for root",
            raw_log=f"Failed password {i}",
            severity="MEDIUM",
            line_number=i
        )
        for i in range(8)
    ]

    findings = detector.detect(events)
    assert len(findings) == 1
    assert findings[0].attack_type == "Brute Force"
    assert findings[0].source_ip == "192.168.1.100"
    assert findings[0].event_count >= 5
    assert "[WHAT]" in findings[0].explanation
    assert "[WHY]" in findings[0].explanation

def test_password_spraying_detector():
    detector = PasswordSprayingDetector()
    detector.threshold = 3.0
    detector.time_window = 600

    base_time = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)
    users = ["alice", "bob", "carol", "dave"]
    events = [
        ParsedEvent(
            timestamp=base_time + timedelta(seconds=i * 20),
            source_ip="10.0.0.50",
            destination_ip=None,
            username=users[i],
            event_type="AUTH_FAILURE",
            method=None,
            endpoint=None,
            status_code=None,
            protocol="SSH",
            source_port=2000 + i,
            destination_port=22,
            process="sshd",
            message=f"Failed password for {users[i]}",
            raw_log=f"Failed {users[i]}",
            severity="MEDIUM",
            line_number=i
        )
        for i in range(len(users))
    ]

    findings = detector.detect(events)
    assert len(findings) == 1
    assert findings[0].attack_type == "Password Spraying"
    assert findings[0].source_ip == "10.0.0.50"

def test_resource_enumeration_detector():
    detector = ResourceEnumerationDetector()
    detector.threshold = 3.0
    detector.time_window = 180

    base_time = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)
    endpoints = ["/.env", "/admin", "/backup", "/etc/passwd"]
    events = [
        ParsedEvent(
            timestamp=base_time + timedelta(seconds=i * 15),
            source_ip="203.0.113.5",
            destination_ip=None,
            username=None,
            event_type="HTTP_REQUEST",
            method="GET",
            endpoint=endpoints[i],
            status_code=404,
            protocol="HTTP/1.1",
            source_port=None,
            destination_port=80,
            process="web",
            message=f"GET {endpoints[i]}",
            raw_log=f"GET {endpoints[i]}",
            severity="INFORMATIONAL",
            line_number=i
        )
        for i in range(len(endpoints))
    ]

    findings = detector.detect(events)
    assert len(findings) == 1
    assert findings[0].attack_type == "Sensitive Resource Enumeration"
