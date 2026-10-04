from app.database.session import Base, engine, SessionLocal
from app.models.rule import DetectionRule
from app.models.user import User
from app.core.logging import logger

DEFAULT_RULES = [
    {
        "rule_id": "DET-001",
        "name": "Brute Force Authentication",
        "description": "Detects multiple failed authentication attempts from the same source IP within a sliding time window.",
        "category": "Authentication",
        "severity": "HIGH",
        "confidence": "HIGH",
        "threshold": 5.0,
        "time_window": 300,
        "remediation": "Temporarily block offending IP via fail2ban or firewall; enforce account lockouts and MFA.",
    },
    {
        "rule_id": "DET-002",
        "name": "Password Spraying",
        "description": "Detects authentication failures against multiple distinct usernames from a single source IP.",
        "category": "Authentication",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "threshold": 3.0,
        "time_window": 600,
        "remediation": "Audit targeted accounts; implement IP rate-limiting on auth endpoints; inspect authentication logs for successful logins.",
    },
    {
        "rule_id": "DET-003",
        "name": "Account Enumeration",
        "description": "Detects repeated failed attempts targeting unknown or invalid usernames from a single source.",
        "category": "Reconnaissance",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "threshold": 4.0,
        "time_window": 300,
        "remediation": "Ensure authentication failure responses do not leak username existence (generic 'Invalid credentials').",
    },
    {
        "rule_id": "DET-004",
        "name": "HTTP Error Spike",
        "description": "Detects an abnormal spike in client/server HTTP errors (401, 403, 404, 500) from a single source.",
        "category": "Web",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "threshold": 12.0,
        "time_window": 120,
        "remediation": "Analyze error payloads; inspect WAF blocks; verify web service health.",
    },
    {
        "rule_id": "DET-005",
        "name": "Request Flooding (DoS Indicator)",
        "description": "Detects an unusually high volume of HTTP requests from a single source IP in a short duration.",
        "category": "Anomaly",
        "severity": "HIGH",
        "confidence": "HIGH",
        "threshold": 40.0,
        "time_window": 30,
        "remediation": "Deploy rate limiting at reverse proxy/WAF; verify client IP reputation; evaluate DDoS mitigation.",
    },
    {
        "rule_id": "DET-006",
        "name": "Endpoint / Port Scanning Indicator",
        "description": "Detects reconnaissance activity where a source rapidly probes numerous distinct endpoints or destination ports.",
        "category": "Reconnaissance",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "threshold": 7.0,
        "time_window": 60,
        "remediation": "Review perimeter firewall rules; block scanning source IP; verify sensitive endpoints are not exposed.",
    },
    {
        "rule_id": "DET-007",
        "name": "Suspicious Privilege-Related Activity",
        "description": "Detects suspicious privilege escalation attempts, such as failed sudo commands, unauthorized su invocations, or permission denied on root.",
        "category": "Privilege",
        "severity": "HIGH",
        "confidence": "HIGH",
        "threshold": 2.0,
        "time_window": 300,
        "remediation": "Audit sudoers configuration, inspect user bash history, isolate compromised host if unauthorized.",
    },
    {
        "rule_id": "DET-008",
        "name": "Suspicious HTTP Methods",
        "description": "Detects unexpected or dangerous HTTP request methods (PUT, DELETE, TRACE, CONNECT) targeting web servers.",
        "category": "Web",
        "severity": "LOW",
        "confidence": "MEDIUM",
        "threshold": 2.0,
        "time_window": 300,
        "remediation": "Disable unneeded HTTP verbs on web server configuration (TRACE, CONNECT, etc.).",
    },
    {
        "rule_id": "DET-009",
        "name": "Sensitive Resource Enumeration",
        "description": "Detects requests targeting sensitive, hidden, or administrative resources (e.g., /.env, /admin, /config, /etc/passwd, /backup).",
        "category": "Reconnaissance",
        "severity": "HIGH",
        "confidence": "HIGH",
        "threshold": 3.0,
        "time_window": 180,
        "remediation": "Block directory traversal and probing IPs; ensure sensitive files are not reachable from web root.",
    },
    {
        "rule_id": "DET-010",
        "name": "Repeated Access Denied",
        "description": "Detects persistent 403 Forbidden or permission denied events from a single source.",
        "category": "Web",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "threshold": 4.0,
        "time_window": 180,
        "remediation": "Investigate ACLs and authorization tokens; check for authorization bypass attempts.",
    },
    {
        "rule_id": "DET-011",
        "name": "Statistical Anomaly (Z-Score)",
        "description": "Flags statistically abnormal request rates or error spikes where z-score >= threshold relative to mean.",
        "category": "Anomaly",
        "severity": "MEDIUM",
        "confidence": "LOW",
        "threshold": 2.5,
        "time_window": 60,
        "remediation": "Cross-reference anomalous traffic against business events and marketing campaigns.",
    },
]

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Seed rules if not present
        existing_rules = {r.rule_id for r in db.query(DetectionRule).all()}
        for r_data in DEFAULT_RULES:
            if r_data["rule_id"] not in existing_rules:
                rule = DetectionRule(**r_data, enabled=True, is_custom=False)
                db.add(rule)
        
        # Seed default admin analyst user if none exists
        if not db.query(User).first():
            user = User(
                username="soc_analyst",
                email="analyst@logsentry.local",
                role="SOC_LEAD"
            )
            db.add(user)
            
        db.commit()
        logger.info("Database schema verified and default detection rules initialized.")
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to initialize database: {e}")
        raise e
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
