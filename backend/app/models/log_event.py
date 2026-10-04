import uuid
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, Index
from app.database.session import Base

class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_job_id = Column(String(36), ForeignKey("analysis_jobs.id"), nullable=False, index=True)
    line_number = Column(Integer, nullable=True)
    
    timestamp = Column(DateTime, nullable=True, index=True)
    source_ip = Column(String(64), nullable=True, index=True)
    destination_ip = Column(String(64), nullable=True)
    username = Column(String(128), nullable=True, index=True)
    event_type = Column(String(64), nullable=True, index=True)  # AUTH_FAILURE, AUTH_SUCCESS, HTTP_REQUEST, PRIVILEGE_EVENT, SCAN_PROBE, etc.
    method = Column(String(16), nullable=True)
    endpoint = Column(String(512), nullable=True)
    status_code = Column(Integer, nullable=True)
    protocol = Column(String(32), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    process = Column(String(64), nullable=True)
    message = Column(Text, nullable=True)
    raw_log = Column(Text, nullable=False)
    severity = Column(String(20), default="INFORMATIONAL", index=True)  # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL

    __table_args__ = (
        Index("idx_event_source_time", "source_ip", "timestamp"),
        Index("idx_event_job_sev", "analysis_job_id", "severity"),
    )
