# app/main.py
import logging
from fastapi import FastAPI, Request, status # Request, status 추가
from fastapi.staticfiles import StaticFiles # StaticFiles 추가
from fastapi.templating import Jinja2Templates # Jinja2Templates 추가
from fastapi.responses import RedirectResponse # RedirectResponse 추가
from pathlib import Path # Path 추가

from app.api.v2 import endpoints as v2_endpoints
from app.api.management import users as users_management_endpoints
from app.api.management import images as images_management_endpoints
from app.api.management import audit as audit_management_endpoints
from app.core.config import settings # settings 임포트
from app.db.database import create_db_and_tables

# UI 라우터 임포트는 아래에서 추가합니다.
# from app.ui import web_routes

# 로깅 설정 (config에서 레벨 가져오기)
logging.basicConfig(
    level=settings.LOG_LEVEL.upper(), # 예: "INFO" -> INFO
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# API 버전 (예시, config 또는 다른 곳에서 관리 가능)
# settings에 API_VERSION을 추가했다면 사용: settings.API_VERSION
APP_VERSION = settings.API_VERSION # config.py 에서 API_VERSION 사용


app = FastAPI(
    title="My Private Docker Registry Service",
    version=APP_VERSION, # 버전 업데이트
    description="""
    A private Docker Image Management Service with enhanced modularity and auditing.
    Allows users to push, pull, list, and manage Docker images.
    Provides user management and audit logging capabilities.
    Includes a Web UI for interaction.
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

# --- 정적 파일 및 템플릿 설정 ---
# BASE_PROJECT_DIR는 v2/app/main.py 파일의 부모의 부모 폴더, 즉 v2/ 폴더를 가리킵니다.
BASE_PROJECT_DIR = Path(__file__).resolve().parent.parent

# 정적 파일 마운트: /static 경로로 요청이 오면 v2/static 폴더에서 파일을 찾습니다.
app.mount("/static", StaticFiles(directory=BASE_PROJECT_DIR / "static"), name="static")

# Jinja2 템플릿 설정: v2/templates 폴더에 HTML 템플릿이 있다고 지정합니다.
templates = Jinja2Templates(directory=BASE_PROJECT_DIR / "templates")


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

# --- API Routers ---
app.include_router(v2_endpoints.router, prefix="/v2", tags=["V2 Registry Proxy"]) #
app.include_router(users_management_endpoints.router, prefix="/users", tags=["User Management"]) #
app.include_router(images_management_endpoints.router, prefix="/images", tags=["Image Management"]) #
app.include_router(audit_management_endpoints.router, prefix="/audit", tags=["Audit Log Management"]) #


# --- 루트 경로 및 웹 UI 라우터 포함 ---
# 기존 루트 경로는 /web/으로 리디렉션하도록 변경합니다.
@app.get("/", tags=["Root"], include_in_schema=False) # 스키마에서 숨김
async def redirect_to_web_ui(request: Request): #
    """
    Root endpoint that redirects to the main Web UI page.
    """
    logger.info("Root path '/' accessed, redirecting to /web/")
    return RedirectResponse(url="/web/", status_code=status.HTTP_302_FOUND)

# 웹 UI 라우터 (아래에서 생성할 app.ui.web_routes 파일을 임포트합니다)
from app.ui import web_routes # 이 줄의 주석을 해제하거나 새로 추가
app.include_router(web_routes.router, prefix="/web", tags=["Web UI"])


# settings에 API_VERSION 추가 시 반영
# if hasattr(settings, 'API_VERSION'):
#    app.version = settings.API_VERSION