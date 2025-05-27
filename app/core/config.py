# app/core/config.py
from pydantic_settings import BaseSettings
from functools import lru_cache
from pathlib import Path
from typing import List

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    DISTRIBUTION_REGISTRY_URL: str = "http://127.0.0.1:5000"
    API_TIMEOUT_SECONDS: int = 300
    HTPASSWD_FILE: Path = Path("/home/rosaria01/secret/.htpasswd")

    AUDIT_DATABASE_URL: str = f"sqlite:///{BASE_DIR}/audit.db"
    ADMIN_USERNAMES: List[str] = ["admin"]
    LOG_LEVEL: str = "INFO"
    API_VERSION: str = "0.2.0"  # <--- 이 부분을 추가해주세요 (버전은 예시입니다)

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'

@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()