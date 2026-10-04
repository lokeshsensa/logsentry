from typing import Optional
from collections import defaultdict
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct

from app.database.session import get_db
from app.models.analysis_job import AnalysisJob
from app.models.log_event import LogEvent
from app.models.detection import Detection
from app.models.incident import Incident
from app.schemas.dashboard import DashboardStats

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(
    job_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    # Base queries optionally filtered by job_id
    ev_q = db.query(LogEvent)
    det_q = db.query(Detection)
    inc_q = db.query(Incident)

    if job_id:
        ev_q = ev_q.filter(LogEvent.analysis_job_id == job_id)
        det_q = det_q.filter(Detection.analysis_job_id == job_id)
        inc_q = inc_q.filter(Incident.analysis_job_id == job_id)

    total_events = ev_q.count()
    total_detections = det_q.count()
    active_incidents = inc_q.filter(Incident.status.in_(["NEW", "INVESTIGATING"])).count()
    critical_high_findings = det_q.filter(Detection.severity.in_(["HIGH", "CRITICAL"])).count()

    # Unique source IPs
    unique_source_ips = ev_q.filter(LogEvent.source_ip != None).with_entities(func.count(distinct(LogEvent.source_ip))).scalar() or 0

    # Auth failures
    auth_failures = ev_q.filter(
        (LogEvent.event_type == "AUTH_FAILURE") | (LogEvent.status_code == 401)
    ).count()

    # HTTP errors
    http_errors = ev_q.filter(
        (LogEvent.status_code >= 400) | (LogEvent.event_type == "HTTP_ERROR")
    ).count()

    # Overall risk posture
    latest_job = None
    if job_id:
        latest_job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    else:
        latest_job = db.query(AnalysisJob).filter(AnalysisJob.status == "COMPLETED").order_by(AnalysisJob.created_at.desc()).first()

    overall_risk_score = latest_job.risk_score if latest_job else 0.0
    overall_risk_level = latest_job.risk_level if latest_job else "LOW"

    # 1. Events over time
    events_sample = (
        ev_q.filter(LogEvent.timestamp != None)
        .order_by(LogEvent.timestamp.asc())
        .with_entities(LogEvent.timestamp, LogEvent.severity)
        .all()
    )

    time_buckets = defaultdict(lambda: {"total": 0, "failures": 0, "errors": 0})
    for ts, sev in events_sample:
        minute_str = ts.strftime("%H:%M")
        time_buckets[minute_str]["total"] += 1
        if sev in ("HIGH", "CRITICAL"):
            time_buckets[minute_str]["errors"] += 1

    events_over_time = [
        {"time": k, "count": v["total"], "high_sev": v["errors"]}
        for k, v in sorted(time_buckets.items())
    ]

    # 2. Detection categories
    cat_counts = (
        det_q.with_entities(Detection.category, func.count(Detection.id))
        .group_by(Detection.category)
        .all()
    )
    detection_categories = [
        {"category": c, "count": cnt} for c, cnt in cat_counts if c
    ]

    # 3. Severity distribution
    sev_counts = (
        det_q.with_entities(Detection.severity, func.count(Detection.id))
        .group_by(Detection.severity)
        .all()
    )
    severity_distribution = [
        {"severity": s, "count": cnt} for s, cnt in sev_counts if s
    ]

    # 4. Top source IPs
    top_ips = (
        ev_q.filter(LogEvent.source_ip != None)
        .with_entities(LogEvent.source_ip, func.count(LogEvent.id))
        .group_by(LogEvent.source_ip)
        .order_by(func.count(LogEvent.id).desc())
        .limit(6)
        .all()
    )
    top_source_ips = [{"ip": ip, "count": cnt} for ip, cnt in top_ips]

    # 5. Top targeted endpoints
    top_eps = (
        ev_q.filter(LogEvent.endpoint != None)
        .with_entities(LogEvent.endpoint, func.count(LogEvent.id))
        .group_by(LogEvent.endpoint)
        .order_by(func.count(LogEvent.id).desc())
        .limit(6)
        .all()
    )
    top_targeted_endpoints = [{"endpoint": ep, "count": cnt} for ep, cnt in top_eps]

    # 6. Auth success vs failure
    auth_success_cnt = ev_q.filter(LogEvent.event_type == "AUTH_SUCCESS").count()
    auth_fail_cnt = ev_q.filter(LogEvent.event_type == "AUTH_FAILURE").count()
    auth_success_failure = [
        {"status": "Failed Authentications", "count": auth_fail_cnt},
        {"status": "Successful Logins", "count": auth_success_cnt},
    ]

    # 7. Incident timeline
    incs = inc_q.order_by(Incident.created_at.asc()).all()
    incident_timeline = [
        {
            "id": inc.id,
            "title": inc.title,
            "severity": inc.severity,
            "source_ip": inc.source_ip or "Local",
            "time": inc.first_seen.strftime("%H:%M:%S") if inc.first_seen else inc.created_at.strftime("%H:%M:%S"),
            "risk_score": inc.risk_score
        }
        for inc in incs
    ]

    return DashboardStats(
        total_events=total_events,
        total_detections=total_detections,
        active_incidents=active_incidents,
        critical_high_findings=critical_high_findings,
        unique_source_ips=unique_source_ips,
        auth_failures=auth_failures,
        http_errors=http_errors,
        overall_risk_score=overall_risk_score,
        overall_risk_level=overall_risk_level,
        events_over_time=events_over_time,
        detection_categories=detection_categories,
        severity_distribution=severity_distribution,
        top_source_ips=top_source_ips,
        top_targeted_endpoints=top_targeted_endpoints,
        auth_success_failure=auth_success_failure,
        incident_timeline=incident_timeline
    )
