# app/auth/security.py
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import logging
from typing import Optional

from app.core.config import settings
from app.db.database import log_audit_event
from app.models.audit import AuditLogDBCreate
from app.models.audit_actions import AuditAction # 신규 임포트
from app.services.htpasswd_service import ( # 신규 임포트
    HtpasswdService,
    get_htpasswd_service,
    HtpasswdFileAccessError
)

logger = logging.getLogger(__name__)
security = HTTPBasic(auto_error=False) # auto_error=False로 설정하여 커스텀 예외 처리

# ADMIN_USERNAMES는 config에서 로드
# ADMIN_USERNAMES = ["admin"] # 삭제


# get_htpasswd_file() 함수는 HtpasswdService로 대체되었으므로 삭제
# def get_htpasswd_file(): ...

async def authenticate_user(
    request: Request,
    credentials: Optional[HTTPBasicCredentials] = Depends(security),
    htpasswd_service: HtpasswdService = Depends(get_htpasswd_service) # 서비스 주입
):
    """
    HTTP Basic 인증을 사용하여 사용자를 인증합니다.
    인증 성공 시 사용자 이름을 반환하고, 실패 시 HTTPException을 발생시킵니다.
    로그인 시도 및 성공/실패에 대한 감사 로그를 기록합니다.
    """
    client_ip = request.client.host if request.client else "Unknown" #
    action_details = {} # 기본 상세 정보

    if credentials is None:
        logger.debug(f"Authentication attempt without credentials from IP: {client_ip}")
        # 이 경우 WWW-Authenticate 헤더를 보내 로그인 프롬프트를 유도
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Basic"},
        )

    username = credentials.username
    password = credentials.password
    action_details["attempted_username"] = username # 시도한 사용자 이름 로깅

    try:
        # HtpasswdService를 통해 비밀번호 확인
        if not htpasswd_service.check_password(username, password):
            logger.warning(f"Authentication failed for user: '{username}' from IP: {client_ip}")
            await log_audit_event(AuditLogDBCreate(
                username=username,
                action=AuditAction.USER_LOGIN_ATTEMPT,
                client_ip=client_ip,
                status="FAILURE",
                details={**action_details, "reason": "Incorrect username or password"}
            ))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Basic"},
            )
    except HtpasswdFileAccessError as e: # Htpasswd 파일 접근/로드 실패 시
        logger.error(
            f"Htpasswd file system unavailable during authentication attempt by user '{username}' from IP: {client_ip}. Error: {e}"
        )
        await log_audit_event(AuditLogDBCreate(
            username=username,
            action=AuditAction.USER_LOGIN_ATTEMPT, # 또는 AuditAction.SYSTEM_HTPASSWD_UNAVAILABLE
            client_ip=client_ip,
            status="FAILURE",
            details={**action_details, "reason": f"User authentication system unavailable: Htpasswd file issue ({e})"}
        ))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User authentication system is currently unavailable.",
        )
    except Exception as e: # 기타 예외
        logger.error(f"Unexpected error during authentication for '{username}': {e}", exc_info=True)
        await log_audit_event(AuditLogDBCreate(
            username=username, action=AuditAction.USER_LOGIN_ATTEMPT, client_ip=client_ip,
            status="FAILURE", details={**action_details, "reason": f"Unexpected authentication error: {str(e)}"}
        ))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during authentication."
        )

    logger.info(f"User '{username}' authenticated successfully from IP: {client_ip}.")
    await log_audit_event(AuditLogDBCreate(
        username=username,
        action=AuditAction.USER_LOGIN,
        client_ip=client_ip,
        status="SUCCESS",
        details=action_details
    ))
    return username

async def get_current_admin_user(
    request: Request,
    current_user: str = Depends(authenticate_user)
):
    """
    현재 인증된 사용자가 관리자인지 확인합니다. (settings.ADMIN_USERNAMES 기준)
    관리자가 아니면 HTTPException (403 Forbidden)을 발생시킵니다.
    관리자 접근 시도에 대한 감사 로그를 기록합니다.
    """
    client_ip = request.client.host if request.client else "Unknown"

    if current_user not in settings.ADMIN_USERNAMES: # 설정에서 관리자 목록 사용
        logger.warning(
            f"User '{current_user}' from IP '{client_ip}' attempted admin access to a resource "
            f"but is not in ADMIN_USERNAMES ({settings.ADMIN_USERNAMES})."
        )
        await log_audit_event(AuditLogDBCreate(
            username=current_user,
            action=AuditAction.ADMIN_ACCESS_DENIED,
            client_ip=client_ip,
            status="FAILURE",
            details={"reason": "User is not in the configured admin list."}
        ))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this resource. Administrator privileges required."
        )

    logger.info(f"Admin user '{current_user}' from IP '{client_ip}' granted admin access.")
    # ADMIN_ACCESS_GRANTED 로그는 실제 관리자 작업 성공 시 남기는 것이 더 유용할 수 있음
    # 또는 여기서 간단히 접근 허용 로그를 남길 수 있음:
    # await log_audit_event(AuditLogDBCreate(
    #     username=current_user, action=AuditAction.ADMIN_ACCESS_GRANTED,
    #     client_ip=client_ip, status="SUCCESS"
    # ))
    return current_user