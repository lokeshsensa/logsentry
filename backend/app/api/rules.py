from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.rule import DetectionRule
from app.schemas.dashboard import RuleOut, RuleUpdate
from app.services.audit_service import audit_service

router = APIRouter(prefix="/rules", tags=["Detection Rules"])

@router.get("", response_model=List[RuleOut])
def list_rules(
    db: Session = Depends(get_db)
):
    return db.query(DetectionRule).order_by(DetectionRule.rule_id.asc()).all()

@router.patch("/{id}", response_model=RuleOut)
def update_rule(
    id: str,
    payload: RuleUpdate,
    db: Session = Depends(get_db)
):
    rule = db.query(DetectionRule).filter((DetectionRule.id == id) | (DetectionRule.rule_id == id)).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")

    changes = []
    if payload.threshold is not None:
        changes.append(f"threshold: {rule.threshold} -> {payload.threshold}")
        rule.threshold = payload.threshold
    if payload.time_window is not None:
        changes.append(f"window: {rule.time_window}s -> {payload.time_window}s")
        rule.time_window = payload.time_window
    if payload.severity is not None:
        changes.append(f"severity: {rule.severity} -> {payload.severity}")
        rule.severity = payload.severity.upper()
    if payload.enabled is not None:
        changes.append(f"enabled: {rule.enabled} -> {payload.enabled}")
        rule.enabled = payload.enabled

    rule.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(rule)

    audit_service.log_action(
        db=db,
        action="RULE_MODIFIED",
        resource=f"DetectionRule:{rule.rule_id}",
        details=f"Modified rule '{rule.name}' ({'; '.join(changes)})."
    )

    return rule
