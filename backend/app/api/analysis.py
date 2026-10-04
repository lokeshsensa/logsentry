from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.database.session import get_db, SessionLocal
from app.models.analysis_job import AnalysisJob
from app.models.log_source import LogSource
from app.models.log_event import LogEvent
from app.schemas.analysis import AnalysisJobCreate, AnalysisJobOut
from app.schemas.log_event import LogEventOut
from app.services.analysis_pipeline import analysis_pipeline
from app.services.audit_service import audit_service
from app.core.logging import logger

router = APIRouter(prefix="/analysis", tags=["Analysis"])

def run_pipeline_task(job_id: str):
    db = SessionLocal()
    try:
        analysis_pipeline.run_job(job_id, db)
    except Exception as e:
        logger.error(f"Background task failed for job {job_id}: {e}")
    finally:
        db.close()

@router.post("/start", response_model=AnalysisJobOut)
def start_analysis_job(
    payload: AnalysisJobCreate,
    background_tasks: BackgroundTasks,
    run_sync: bool = Query(True, description="Run synchronously for immediate results or background"),
    db: Session = Depends(get_db)
):
    log_source = db.query(LogSource).filter(LogSource.id == payload.log_source_id).first()
    if not log_source:
        raise HTTPException(status_code=404, detail="Log source not found")

    job = AnalysisJob(
        log_source_id=payload.log_source_id,
        status="PENDING",
        profile=payload.profile or "STANDARD",
        timezone_name=payload.timezone_name or "UTC",
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    audit_service.log_action(
        db=db,
        action="ANALYSIS_STARTED",
        resource=f"AnalysisJob:{job.id}",
        details=f"Job queued with profile '{job.profile}' for file '{log_source.original_filename}'."
    )

    if run_sync:
        job = analysis_pipeline.run_job(job.id, db)
    else:
        background_tasks.add_task(run_pipeline_task, job.id)

    return job

@router.get("", response_model=List[AnalysisJobOut])
def list_analysis_jobs(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    jobs = db.query(AnalysisJob).order_by(AnalysisJob.created_at.desc()).offset(offset).limit(limit).all()
    return jobs

@router.get("/{id}", response_model=AnalysisJobOut)
def get_analysis_job(
    id: str,
    db: Session = Depends(get_db)
):
    job = db.query(AnalysisJob).filter(AnalysisJob.id == id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    return job

@router.get("/{id}/events")
def get_analysis_events(
    id: str,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    status_code: Optional[int] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(LogEvent).filter(LogEvent.analysis_job_id == id)

    if source_ip:
        query = query.filter(LogEvent.source_ip == source_ip)
    if username:
        query = query.filter(LogEvent.username.ilike(f"%{username}%"))
    if event_type:
        query = query.filter(LogEvent.event_type == event_type)
    if severity:
        query = query.filter(LogEvent.severity == severity.upper())
    if status_code:
        query = query.filter(LogEvent.status_code == status_code)
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            or_(
                LogEvent.raw_log.ilike(search_pattern),
                LogEvent.message.ilike(search_pattern),
                LogEvent.endpoint.ilike(search_pattern),
                LogEvent.source_ip.ilike(search_pattern),
                LogEvent.username.ilike(search_pattern),
            )
        )

    total_count = query.count()
    events = query.order_by(LogEvent.line_number.asc()).offset(offset).limit(limit).all()

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "events": [
            LogEventOut.model_validate(e).model_dump()
            for e in events
        ]
    }
