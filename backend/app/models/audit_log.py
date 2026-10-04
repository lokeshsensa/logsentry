import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text
from app.database.session import Base

def utc_now():
    return datetime.now(timezone.utc)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=utc_now, index=True)
    action = Column(String(64), nullable=False, index=True)
    actor = Column(String(64), default="system")
    resource = Column(String(128), nullable=False)
    result = Column(String(32), default="SUCCESS")
    details = Column(Text, nullable=True)
