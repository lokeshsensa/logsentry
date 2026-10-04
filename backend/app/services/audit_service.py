from typing import Optional
from sqlalchemy.orm import Session
from app.models.audit_log import AuditLog
from app.core.logging import logger

class AuditService:
    @staticmethod
    def log_action(
        db: Session,
        action: str,
        resource: str,
        actor: str = "SOC_ANALYST",
        result: str = "SUCCESS",
        details: Optional[str] = None
    ) -> AuditLog:
        try:
            entry = AuditLog(
                action=action,
                resource=resource,
                actor=actor,
                result=result,
                details=details
            )
            db.add(entry)
            db.commit()
            return entry
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to record audit log: {e}")
            return None

audit_service = AuditService()
