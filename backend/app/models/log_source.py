import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime
from app.database.session import Base

def utc_now():
    return datetime.now(timezone.utc)

class LogSource(Base):
    __tablename__ = "log_sources"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size_bytes = Column(Integer, nullable=False)
    format_type = Column(String(50), default="AUTO")  # LINUX_AUTH, APACHE_NGINX, GENERIC, AUTO
    created_at = Column(DateTime, default=utc_now)
