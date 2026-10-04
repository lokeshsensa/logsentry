import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database.session import Base

def utc_now():
    return datetime.now(timezone.utc)

class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    log_source_id = Column(String(36), ForeignKey("log_sources.id"), nullable=False, index=True)
    status = Column(String(32), default="PENDING", index=True)  # PENDING, PROCESSING, COMPLETED, FAILED
    profile = Column(String(32), default="STANDARD")  # QUICK, STANDARD, DETAILED
    timezone_name = Column(String(64), default="UTC")
    detected_format = Column(String(50), nullable=True)
    
    # Parser Statistics
    total_lines = Column(Integer, default=0)
    parsed_lines = Column(Integer, default=0)
    failed_lines = Column(Integer, default=0)
    parser_type = Column(String(50), nullable=True)
    duration_seconds = Column(Float, default=0.0)
    
    # Risk summary
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="LOW")  # LOW, GUARDED, MEDIUM, HIGH, CRITICAL
    risk_explanation = Column(Text, nullable=True)
    
    # Counts
    events_count = Column(Integer, default=0)
    detections_count = Column(Integer, default=0)
    incidents_count = Column(Integer, default=0)
    
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, index=True)
    completed_at = Column(DateTime, nullable=True)

    log_source = relationship("LogSource", backref="jobs")
