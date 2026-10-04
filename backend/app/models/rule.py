import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text
from app.database.session import Base

def utc_now():
    return datetime.now(timezone.utc)

class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(64), nullable=False)
    severity = Column(String(20), nullable=False)
    confidence = Column(String(20), nullable=False)
    threshold = Column(Float, nullable=False)
    time_window = Column(Integer, nullable=False)  # in seconds
    enabled = Column(Boolean, default=True)
    remediation = Column(Text, nullable=True)
    is_custom = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)
