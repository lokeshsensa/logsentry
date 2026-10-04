import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime
from app.database.session import Base

def utc_now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(128), unique=True, nullable=False)
    role = Column(String(32), default="SOC_ANALYST")
    created_at = Column(DateTime, default=utc_now)
