import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Text
from app.database.session import Base

def utc_now():
    return datetime.now(timezone.utc)

class Detection(Base):
    __tablename__ = "detections"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_job_id = Column(String(36), ForeignKey("analysis_jobs.id"), nullable=False, index=True)
    rule_id = Column(String(64), nullable=False, index=True)
    detector_id = Column(String(64), nullable=False)
    attack_type = Column(String(128), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False)  # Authentication, Web, Reconnaissance, Privilege, Statistical Anomaly
    severity = Column(String(20), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH
    source_ip = Column(String(64), nullable=True, index=True)
    target_endpoint = Column(String(512), nullable=True)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    event_count = Column(Integer, default=1)
    threshold = Column(Float, nullable=True)
    time_window = Column(Integer, nullable=True)  # seconds
    explanation = Column(Text, nullable=False)
    remediation = Column(Text, nullable=True)
    status = Column(String(32), default="ACTIVE", index=True)  # ACTIVE, RESOLVED, FALSE_POSITIVE
    created_at = Column(DateTime, default=utc_now)
