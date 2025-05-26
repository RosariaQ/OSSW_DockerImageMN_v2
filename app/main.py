# app/main.py
import logging
from fastapi import FastAPI

from app.api.v2 import endpoints as v2_endpoints
from app.api.management import users as users_management_endpoints
from app.api.management import images as images_management_endpoints
from app.api.management import audit as audit_management_endpoints
from app.core.config import settings # settings 임포트
from app.db.database import create_db_and_tables

# 로깅 설정 (config에서 레벨 가져오기)
logging.basicConfig(
    level=settings.LOG_LEVEL.upper(), # 예: "INFO" -> INFO
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# API 버전 (예시, config 또는 다른 곳에서 관리 가능)
# settings에 API_VERSION을 추가했다면 사용: settings.API_VERSION
APP_VERSION = "0.2.0" # 리팩토링 반영 버전


app = FastAPI(
    title="My Private Docker Registry Service",
    version=APP_VERSION, # 버전 업데이트
    description="""
    A private Docker Image Management Service with enhanced modularity and auditing.
    Allows users to push, pull, list, and manage Docker images.
    Provides user management and audit logging capabilities.
    """,
    contact={
        "name": "Service Administrator",
        "url": "http://example.com/contact",
        "email": "admin@example.com",
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    },
)

@app.on_event("startup")
async def startup_event(): #
    logger.info(f"Application startup... Version: {APP_VERSION}, Log Level: {settings.LOG_LEVEL}")
    try:
        create_db_and_tables() #
    except Exception as e:
        logger.critical(f"Could not create database tables during startup: {e}", exc_info=True)
        # Depending on severity, you might want to exit or prevent app from fully starting

    logger.info(f"Proxying to Distribution Registry at: {settings.DISTRIBUTION_REGISTRY_URL}") #
    if not settings.HTPASSWD_FILE.exists(): #
        logger.warning(
            f"HTPASSWD_FILE not found at {settings.HTPASSWD_FILE}. " #
            "User authentication will fail for operations requiring it."
        )
    else:
        logger.info(f"Using HTPASSWD_FILE at {settings.HTPASSWD_FILE}")
    logger.info(f"Admin usernames: {settings.ADMIN_USERNAMES}")


@app.on_event("shutdown")
async def shutdown_event(): #
    logger.info("Application shutdown...")

# API Routers
app.include_router(v2_endpoints.router, prefix="/v2", tags=["V2 Registry Proxy"]) #
app.include_router(users_management_endpoints.router, prefix="/users", tags=["User Management"]) #
app.include_router(images_management_endpoints.router, prefix="/images", tags=["Image Management"]) #
app.include_router(audit_management_endpoints.router, prefix="/audit", tags=["Audit Log Management"]) #

@app.get("/", tags=["Root"])
async def read_root(): #
    """
    Root endpoint for the service.
    Provides a welcome message and basic service information.
    """
    logger.info("Root path '/' accessed.")
    return {
        "message": "Welcome to My Private Docker Registry Service!",
        "version": app.version, #
        "docs_url": "/docs", #
        "redoc_url": "/redoc" #
    }

# settings에 API_VERSION 추가 시 반영
# if hasattr(settings, 'API_VERSION'):
#    app.version = settings.API_VERSION