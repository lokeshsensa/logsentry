from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.incident import Incident, IncidentEvent
from app.models.detection import Detection
from app.models.log_event import LogEvent
from app.schemas.dashboard import IncidentOut, IncidentStatusUpdate
from app.schemas.log_event import LogEventOut
from app.services.audit_service import audit_service

router = APIRouter(prefix="/incidents", tags=["Incidents"])

@router.get("", response_model=List[IncidentOut])
def list_incidents(
    job_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source_ip: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(Incident)
    if job_id:
        query = query.filter(Incident.analysis_job_id == job_id)
    if severity:
        query = query.filter(Incident.severity == severity.upper())
    if status:
        query = query.filter(Incident.status == status.upper())
    if source_ip:
        query = query.filter(Incident.source_ip == source_ip)

    return query.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()

@router.get("/{id}")
def get_incident_detail(
    id: str,
    db: Session = Depends(get_db)
):
    inc = db.query(Incident).filter(Incident.id == id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Fetch related detections and sample events
    inc_events = db.query(IncidentEvent).filter(IncidentEvent.incident_id == id).all()
    det_ids = {ie.detection_id for ie in inc_events if ie.detection_id}
    log_event_ids = {ie.log_event_id for ie in inc_events if ie.log_event_id}

    detections = db.query(Detection).filter(Detection.id.in_(det_ids)).all() if det_ids else []
    sample_events = db.query(LogEvent).filter(LogEvent.id.in_(log_event_ids)).limit(25).all() if log_event_ids else []

    return {
        "incident": IncidentOut.model_validate(inc).model_dump(),
        "detections": [
            {
                "id": d.id,
                "rule_id": d.rule_id,
                "attack_type": d.attack_type,
                "title": d.title,
                "severity": d.severity,
                "confidence": d.confidence,
                "explanation": d.explanation,
                "remediation": d.remediation,
            }
            for d in detections
        ],
        "sample_events": [
            LogEventOut.model_validate(e).model_dump()
            for e in sample_events
        ]
    }

@router.patch("/{id}", response_model=IncidentOut)
def update_incident_status(
    id: str,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db)
):
    valid_statuses = {"NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}
    new_status = payload.status.upper()
    if new_status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{payload.status}'. Allowed: {', '.join(valid_statuses)}"
        )

    inc = db.query(Incident).filter(Incident.id == id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = inc.status
    inc.status = new_status
    inc.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(inc)

    audit_service.log_action(
        db=db,
        action="INCIDENT_STATUS_CHANGED",
        resource=f"Incident:{inc.id}",
        details=f"Status changed from {old_status} to {new_status} for incident '{inc.title}'."
    )

    return inc
