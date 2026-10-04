from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from app.schemas.log_event import LogEventOut

class DetectionOut(BaseModel):
    id: str
    analysis_job_id: str
    rule_id: str
    detector_id: str
    attack_type: str
    title: str
    category: str
    severity: str
    confidence: str
    source_ip: Optional[str] = None
    target_endpoint: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    event_count: int
    threshold: Optional[float] = None
    time_window: Optional[int] = None
    explanation: str
    remediation: Optional[str] = None
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}

class IncidentOut(BaseModel):
    id: str
    analysis_job_id: str
    title: str
    severity: str
    confidence: str
    source_ip: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    event_count: int
    risk_score: float
    risk_level: str
    explanation: str
    remediation: str
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

class IncidentStatusUpdate(BaseModel):
    status: str  # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE

class RuleOut(BaseModel):
    id: str
    rule_id: str
    name: str
    description: str
    category: str
    severity: str
    confidence: str
    threshold: float
    time_window: int
    enabled: bool
    remediation: Optional[str] = None
    is_custom: bool

    model_config = {"from_attributes": True}

class RuleUpdate(BaseModel):
    threshold: Optional[float] = None
    time_window: Optional[int] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None

class ReportOut(BaseModel):
    id: str
    analysis_job_id: str
    title: str
    file_path: str
    format: str
    file_size_bytes: int
    summary: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}

class ReportGenerateRequest(BaseModel):
    analysis_job_id: str

class AuditLogOut(BaseModel):
    id: str
    timestamp: datetime
    action: str
    actor: str
    resource: str
    result: str
    details: Optional[str] = None

    model_config = {"from_attributes": True}

class DashboardStats(BaseModel):
    total_events: int
    total_detections: int
    active_incidents: int
    critical_high_findings: int
    unique_source_ips: int
    auth_failures: int
    http_errors: int
    overall_risk_score: float
    overall_risk_level: str

    events_over_time: List[dict]
    detection_categories: List[dict]
    severity_distribution: List[dict]
    top_source_ips: List[dict]
    top_targeted_endpoints: List[dict]
    auth_success_failure: List[dict]
    incident_timeline: List[dict]
