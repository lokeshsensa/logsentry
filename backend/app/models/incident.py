import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database.session import Base

def utc_now():
    return datetime.now(timezone.utc)

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_job_id = Column(String(36), ForeignKey("analysis_jobs.id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH
    source_ip = Column(String(64), nullable=True, index=True)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    event_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="LOW")
    explanation = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    status = Column(String(32), default="NEW", index=True)  # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    incident_events = relationship("IncidentEvent", back_populates="incident", cascade="all, delete-orphan")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False, index=True)
    log_event_id = Column(String(36), ForeignKey("log_events.id"), nullable=True, index=True)
    detection_id = Column(String(36), ForeignKey("detections.id"), nullable=True, index=True)

    incident = relationship("Incident", back_populates="incident_events")
    log_event = relationship("LogEvent")
    detection = relationship("Detection")
