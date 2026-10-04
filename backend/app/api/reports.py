import os
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.report import Report
from app.models.analysis_job import AnalysisJob
from app.schemas.dashboard import ReportOut, ReportGenerateRequest
from app.services.report_generator import report_generator
from app.services.audit_service import audit_service

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.post("/generate", response_model=ReportOut)
def generate_report(
    payload: ReportGenerateRequest,
    db: Session = Depends(get_db)
):
    job = db.query(AnalysisJob).filter(AnalysisJob.id == payload.analysis_job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")

    report = report_generator.generate_pdf_report(payload.analysis_job_id, db)

    audit_service.log_action(
        db=db,
        action="REPORT_GENERATED",
        resource=f"Report:{report.id}",
        details=f"Generated PDF security report '{report.title}' for Job {job.id}."
    )

    return report

@router.get("", response_model=List[ReportOut])
def list_reports(
    db: Session = Depends(get_db)
):
    return db.query(Report).order_by(Report.created_at.desc()).all()

@router.get("/{id}", response_model=ReportOut)
def get_report(
    id: str,
    db: Session = Depends(get_db)
):
    rep = db.query(Report).filter(Report.id == id).first()
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found")
    return rep

@router.get("/{id}/download")
def download_report(
    id: str,
    db: Session = Depends(get_db)
):
    rep = db.query(Report).filter(Report.id == id).first()
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found")

    if not os.path.exists(rep.file_path):
        raise HTTPException(status_code=404, detail="PDF report file not found on disk")

    filename = os.path.basename(rep.file_path)
    return FileResponse(
        path=rep.file_path,
        filename=filename,
        media_type="application/pdf"
    )
