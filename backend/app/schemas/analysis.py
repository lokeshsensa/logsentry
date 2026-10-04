from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class AnalysisJobCreate(BaseModel):
    log_source_id: str
    profile: Optional[str] = "STANDARD"  # QUICK, STANDARD, DETAILED
    timezone_name: Optional[str] = "UTC"

class AnalysisJobOut(BaseModel):
    id: str
    log_source_id: str
    status: str
    profile: str
    timezone_name: str
    detected_format: Optional[str] = None
    total_lines: int
    parsed_lines: int
    failed_lines: int
    parser_type: Optional[str] = None
    duration_seconds: float
    risk_score: float
    risk_level: str
    risk_explanation: Optional[str] = None
    events_count: int
    detections_count: int
    incidents_count: int
    error_message: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}

class LogSourceOut(BaseModel):
    id: str
    original_filename: str
    stored_filename: str
    file_size_bytes: int
    format_type: str
    created_at: datetime

    model_config = {"from_attributes": True}
