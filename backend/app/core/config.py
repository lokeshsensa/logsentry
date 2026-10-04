import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR = BASE_DIR.parent / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

class Settings(BaseSettings):
    PROJECT_NAME: str = "LOGSENTRY — Log Analyzer & Attack Detection System"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Storage
    BASE_DIR: Path = BASE_DIR
    DATA_DIR: Path = DATA_DIR
    UPLOAD_DIR: Path = UPLOAD_DIR
    REPORTS_DIR: Path = REPORTS_DIR
    
    # SQLite Database
    DATABASE_URL: str = f"sqlite:///{DATA_DIR / 'logsentry.db'}"
    
    # Security & Upload constraints
    MAX_UPLOAD_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
    ALLOWED_LOG_EXTENSIONS: set = {".log", ".txt", ".gz", ".syslog"}
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "*"
    ]

    model_config = SettingsConfigDict(env_file=".env", extra="allow")

settings = Settings()
