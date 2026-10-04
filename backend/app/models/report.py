import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text
from app.database.session import Base

def utc_now():
    return datetime.now(timezone.utc)

class Report(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_job_id = Column(String(36), ForeignKey("analysis_jobs.id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    format = Column(String(20), default="PDF")
    file_size_bytes = Column(Integer, default=0)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)
