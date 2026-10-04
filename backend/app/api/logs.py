import shutil
import uuid
from typing import List, Optional
from pathlib import Path
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.log_source import LogSource
from app.schemas.analysis import LogSourceOut
from app.parsers.manager import parser_manager
from app.core.config import settings
from app.core.security import sanitize_filename, validate_file_size
from app.services.audit_service import audit_service
from app.core.logging import logger

router = APIRouter(prefix="/logs", tags=["Log Ingestion"])

@router.post("/upload", response_model=LogSourceOut)
async def upload_log_file(
    file: UploadFile = File(...),
    format_type: Optional[str] = Form("AUTO"),
    db: Session = Depends(get_db)
):
    """
    Safely ingest and validate uploaded log file.
    Validates file extension, sanitizes filename, and prevents path traversal.
    """
    clean_name = sanitize_filename(file.filename)
    
    # Generate unique stored filename
    stored_name = f"{uuid.uuid4()}_{clean_name}"
    target_path = settings.UPLOAD_DIR / stored_name

    # Save file in chunks to avoid memory spikes
    total_bytes = 0
    try:
        with open(target_path, "wb") as buffer:
            while chunk := await file.read(1024 * 1024):  # 1MB chunks
                total_bytes += len(chunk)
                validate_file_size(total_bytes)
                buffer.write(chunk)
    except Exception as e:
        if target_path.exists():
            target_path.unlink()
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=400, detail=f"File upload failed: {str(e)}")

    # Detect format preview
    sample_lines = []
    with open(target_path, "r", encoding="utf-8", errors="replace") as f:
        for _ in range(50):
            line = f.readline()
            if not line:
                break
            sample_lines.append(line)

    detected = parser_manager.detect_format(sample_lines)
    chosen_format = detected if (not format_type or format_type == "AUTO") else format_type

    log_source = LogSource(
        original_filename=clean_name,
        stored_filename=stored_name,
        file_path=str(target_path),
        file_size_bytes=total_bytes,
        format_type=chosen_format
    )
    db.add(log_source)
    db.commit()
    db.refresh(log_source)

    audit_service.log_action(
        db=db,
        action="FILE_UPLOADED",
        resource=f"LogSource:{log_source.id}",
        details=f"Uploaded '{clean_name}' ({total_bytes} bytes). Detected format: {detected}."
    )

    return log_source

@router.post("/preview-detect")
async def preview_and_detect_log(
    file: UploadFile = File(...)
):
    """
    Read first 10 lines of file and report auto-detected format before running job.
    Never assume format without showing detected format.
    """
    clean_name = sanitize_filename(file.filename)
    sample_lines = []
    
    # Read first 30KB to grab sample lines
    content = await file.read(32768)
    text = content.decode("utf-8", errors="replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()][:15]

    detected = parser_manager.detect_format(lines)

    return {
        "filename": clean_name,
        "detected_format": detected,
        "sample_lines": lines[:8]
    }

@router.get("/sources", response_model=List[LogSourceOut])
def list_log_sources(
    limit: int = 50,
    db: Session = Depends(get_db)
):
    sources = db.query(LogSource).order_by(LogSource.created_at.desc()).limit(limit).all()
    return sources
