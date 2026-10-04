from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.detection import Detection
from app.schemas.dashboard import DetectionOut

router = APIRouter(prefix="/detections", tags=["Detections"])

@router.get("", response_model=List[DetectionOut])
def list_detections(
    job_id: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    source_ip: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(Detection)
    if job_id:
        query = query.filter(Detection.analysis_job_id == job_id)
    if severity:
        query = query.filter(Detection.severity == severity.upper())
    if category:
        query = query.filter(Detection.category == category)
    if source_ip:
        query = query.filter(Detection.source_ip == source_ip)

    return query.order_by(Detection.created_at.desc()).offset(offset).limit(limit).all()

@router.get("/{id}", response_model=DetectionOut)
def get_detection(
    id: str,
    db: Session = Depends(get_db)
):
    det = db.query(Detection).filter(Detection.id == id).first()
    if not det:
        raise HTTPException(status_code=404, detail="Detection finding not found")
    return det
