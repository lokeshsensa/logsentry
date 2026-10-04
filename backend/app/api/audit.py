from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.audit_log import AuditLog
from app.schemas.dashboard import AuditLogOut

router = APIRouter(prefix="/audit", tags=["Audit Logs"])

@router.get("", response_model=List[AuditLogOut])
def list_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
