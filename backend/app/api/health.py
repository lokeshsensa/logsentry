from fastapi import APIRouter
from datetime import datetime, timezone
from app.core.config import settings

router = APIRouter()

@router.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "HEALTHY",
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
