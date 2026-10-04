from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class LogEventOut(BaseModel):
    id: str
    analysis_job_id: str
    line_number: Optional[int] = None
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: Optional[str] = None
    method: Optional[str] = None
    endpoint: Optional[str] = None
    status_code: Optional[int] = None
    protocol: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    process: Optional[str] = None
    message: Optional[str] = None
    raw_log: str
    severity: str

    model_config = {"from_attributes": True}

class LogEventFilter(BaseModel):
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    status_code: Optional[int] = None
    search: Optional[str] = None
    limit: int = 50
    offset: int = 0
