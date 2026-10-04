import re
import os
from pathlib import Path
from fastapi import HTTPException
from app.core.config import settings

SAFE_FILENAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]+$")

def sanitize_filename(filename: str) -> str:
    """
    Sanitize uploaded filename to prevent directory traversal or unsafe characters.
    """
    # Remove directory path if present
    clean_name = os.path.basename(filename)
    # Replace whitespace with underscore
    clean_name = clean_name.replace(" ", "_")
    # Retain only alphanumeric, dash, dot, underscore
    clean_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "", clean_name)
    
    if not clean_name:
        clean_name = "upload.log"
        
    # Check extension
    ext = Path(clean_name).suffix.lower()
    if ext not in settings.ALLOWED_LOG_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file extension '{ext}'. Allowed extensions: {', '.join(settings.ALLOWED_LOG_EXTENSIONS)}"
        )
    return clean_name

def validate_file_size(size_bytes: int):
    """Ensure upload does not exceed limit"""
    if size_bytes > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed upload size of {settings.MAX_UPLOAD_SIZE_BYTES // (1024*1024)} MB"
        )
