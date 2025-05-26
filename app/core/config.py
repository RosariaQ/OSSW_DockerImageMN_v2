# app/core/config.py
from pydantic_settings import BaseSettings
from functools import lru_cache
from pathlib import Path
from typing import List

# BASE_DIR might still be useful for other things, but not strictly for an absolute HTPASSWD_FILE path
BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    DISTRIBUTION_REGISTRY_URL: str = "http://127.0.0.1:5000"
    API_TIMEOUT_SECONDS: int = 300
    HTPASSWD_FILE: Path = Path("/home/rosaria01/secret/.htpasswd") #

    # SQLite 데이터베이스 URL 추가 (프로젝트 루트에 audit.db 파일로 생성)
    AUDIT_DATABASE_URL: str = f"sqlite:///{BASE_DIR}/audit.db" #

    # 관리자 사용자 이름 목록 (환경 변수로 재정의 가능)
    # 예: MYAPP_ADMIN_USERNAMES='["admin","another_admin"]'
    ADMIN_USERNAMES: List[str] = ["admin"]

    # 로깅 레벨 설정
    LOG_LEVEL: str = "INFO"


    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'
        # Pydantic v2는 기본적으로 env_prefix를 사용하지 않음.
        # 특정 prefix를 사용하려면 fields에서 env 속성을 지정하거나,
        # 이전 버전처럼 env_prefix = 'MYAPP_' 등을 설정할 수 있습니다.

@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()