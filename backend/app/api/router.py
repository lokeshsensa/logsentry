from fastapi import APIRouter
from app.api.health import router as health_router
from app.api.logs import router as logs_router
from app.api.analysis import router as analysis_router
from app.api.detections import router as detections_router
from app.api.incidents import router as incidents_router
from app.api.dashboard import router as dashboard_router
from app.api.reports import router as reports_router
from app.api.rules import router as rules_router
from app.api.audit import router as audit_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(logs_router)
api_router.include_router(analysis_router)
api_router.include_router(detections_router)
api_router.include_router(incidents_router)
api_router.include_router(dashboard_router)
api_router.include_router(reports_router)
api_router.include_router(rules_router)
api_router.include_router(audit_router)
