# app/api/management/users.py
from fastapi import APIRouter, Depends, HTTPException, status, Body, Request
from pydantic import BaseModel, Field
import logging

from app.auth.security import get_current_admin_user
# from app.core.config import settings # HtpasswdService가 settings를 사용
from app.db.database import log_audit_event
from app.models.audit import AuditLogDBCreate
from app.models.audit_actions import AuditAction # 신규 임포트
from app.services.htpasswd_service import ( # 신규 임포트
    HtpasswdService,
    get_htpasswd_service,
    HtpasswdCommandError,
    HtpasswdUtilityNotFoundError,
    HtpasswdFileAccessError,
    HtpasswdError
)

router = APIRouter()
logger = logging.getLogger(__name__)

# --- Pydantic 모델 정의 ---
class UserCreate(BaseModel): #
    username: str = Field(..., min_length=1, description="새 사용자의 사용자 이름") #
    password: str = Field(..., min_length=6, description="새 사용자의 비밀번호 (최소 6자)") #

class UserResponse(BaseModel): #
    users: list[str]

class MessageResponse(BaseModel): #
    message: str

# --- API 엔드포인트 ---
@router.get(
    "",
    response_model=UserResponse,
    summary="모든 사용자 목록 조회",
    description="htpasswd 파일에서 모든 사용자 이름 목록을 가져옵니다.\n\n관리자만 접근 가능합니다."
)
async def list_users(
    request: Request,
    admin_user: str = Depends(get_current_admin_user),
    htpasswd_service: HtpasswdService = Depends(get_htpasswd_service) # 서비스 주입
):
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path}

    try:
        users = htpasswd_service.list_users()
        logger.info(f"Admin '{admin_user}' (IP: {client_ip}) listed users (count: {len(users)}).")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_LIST, client_ip=client_ip,
            status="SUCCESS", details={**action_details, "listed_user_count": len(users)}
        ))
        return {"users": users}
    except HtpasswdFileAccessError as e:
        logger.error(f"Admin '{admin_user}' (IP: {client_ip}) failed to list users: {e}")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_LIST_ATTEMPT, client_ip=client_ip,
            status="FAILURE", details={**action_details, "reason": f"User database (htpasswd file) access error: {e}"}
        ))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"사용자 데이터베이스를 사용할 수 없습니다: {e}"
        )
    except Exception as e: # HtpasswdService 내부의 다른 예외 또는 기타 예외
        logger.error(f"Admin '{admin_user}' (IP: {client_ip}) encountered an unexpected error listing users: {e}", exc_info=True)
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_LIST_ATTEMPT, client_ip=client_ip,
            status="FAILURE", details={**action_details, "reason": f"Unexpected error: {str(e)}"}
        ))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="사용자 목록을 가져오는 중 예기치 않은 오류가 발생했습니다."
        )


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=MessageResponse,
    summary="새 사용자 생성",
    description="htpasswd 파일에 새 사용자를 생성합니다.\n\n관리자만 접근 가능합니다.\n비밀번호는 bcrypt로 해시됩니다."
)
async def create_user(
    request: Request,
    user_data: UserCreate,
    admin_user: str = Depends(get_current_admin_user),
    htpasswd_service: HtpasswdService = Depends(get_htpasswd_service) # 서비스 주입
):
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path, "target_username": user_data.username}

    try:
        if htpasswd_service.user_exists(user_data.username):
            logger.warning(f"Admin '{admin_user}' (IP: {client_ip}) attempted to create existing user '{user_data.username}'.")
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.USER_CREATE_ATTEMPT, client_ip=client_ip,
                resource_type="user", resource_name=user_data.username, status="FAILURE",
                details={**action_details, "reason": f"User '{user_data.username}' already exists."}
            ))
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"사용자 '{user_data.username}'는(은) 이미 존재합니다."
            )

        htpasswd_service.add_user(user_data.username, user_data.password) # 서비스 호출
        logger.info(f"User '{user_data.username}' created successfully by admin '{admin_user}'.")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_CREATE, client_ip=client_ip,
            resource_type="user", resource_name=user_data.username, status="SUCCESS",
            details=action_details
        ))
        return {"message": f"사용자 '{user_data.username}'이(가) 성공적으로 생성되었습니다."}

    except (HtpasswdCommandError, HtpasswdError) as e: # htpasswd 명령어 관련 오류
        error_reason = str(e.stderr) if isinstance(e, HtpasswdCommandError) and e.stderr else str(e)
        logger.error(f"Failed to create user '{user_data.username}' by admin '{admin_user}'. Error: {error_reason}")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_CREATE_ATTEMPT, client_ip=client_ip,
            resource_type="user", resource_name=user_data.username, status="FAILURE",
            details={**action_details, "reason": f"htpasswd operation failed: {error_reason}"}
        ))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"사용자 생성 실패: {error_reason}"
        )
    except HtpasswdUtilityNotFoundError as e: # htpasswd 유틸리티 없음
        logger.error(f"htpasswd command not found when admin '{admin_user}' tried to create user '{user_data.username}'. Error: {e}")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_CREATE_ATTEMPT, client_ip=client_ip,
            resource_type="user", resource_name=user_data.username, status="FAILURE",
            details={**action_details, "reason": f"Server configuration error: {e}"}
        ))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"서버 설정 오류: {e}"
        )
    except HtpasswdFileAccessError as e: # htpasswd 파일 접근 오류
        logger.error(f"Admin '{admin_user}' (IP: {client_ip}) failed to create user '{user_data.username}': {e}")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_CREATE_ATTEMPT, client_ip=client_ip,
            resource_type="user", resource_name=user_data.username, status="FAILURE",
            details={**action_details, "reason": f"User database (htpasswd file) access error: {e}"}
        ))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"사용자 데이터베이스 처리 중 오류: {e}"
        )
    except Exception as e:
        logger.error(f"Unexpected error creating user '{user_data.username}' by admin '{admin_user}': {e}", exc_info=True)
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_CREATE_ATTEMPT, client_ip=client_ip,
            resource_type="user", resource_name=user_data.username, status="FAILURE",
            details={**action_details, "reason": f"Unexpected error: {str(e)}"}
        ))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="사용자 생성 중 예기치 않은 오류가 발생했습니다."
        )


@router.delete(
    "/{username_to_delete}",
    response_model=MessageResponse,
    summary="사용자 삭제",
    description="htpasswd 파일에서 사용자를 삭제합니다.\n\n관리자만 접근 가능합니다.\n관리자는 자기 자신을 삭제할 수 없습니다."
)
async def delete_user(
    request: Request,
    username_to_delete: str,
    admin_user: str = Depends(get_current_admin_user),
    htpasswd_service: HtpasswdService = Depends(get_htpasswd_service) # 서비스 주입
):
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path, "target_username": username_to_delete}

    try:
        if not htpasswd_service.user_exists(username_to_delete):
            logger.warning(f"Admin '{admin_user}' (IP: {client_ip}) attempted to delete non-existing user '{username_to_delete}'.")
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.USER_DELETE_ATTEMPT, client_ip=client_ip,
                resource_type="user", resource_name=username_to_delete, status="FAILURE",
                details={**action_details, "reason": f"User '{username_to_delete}' not found."}
            ))
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"사용자 '{username_to_delete}'을(를) 찾을 수 없습니다."
            )

        if username_to_delete == admin_user:
            logger.warning(f"Admin '{admin_user}' (IP: {client_ip}) attempted to delete themselves ('{username_to_delete}').")
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.USER_DELETE_ATTEMPT, client_ip=client_ip,
                resource_type="user", resource_name=username_to_delete, status="FAILURE",
                details={**action_details, "reason": "Admins cannot delete themselves."}
            ))
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="관리자는 자기 자신을 삭제할 수 없습니다."
            )

        htpasswd_service.delete_user(username_to_delete) # 서비스 호출
        logger.info(f"User '{username_to_delete}' deleted successfully by admin '{admin_user}'.")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_DELETE, client_ip=client_ip,
            resource_type="user", resource_name=username_to_delete, status="SUCCESS",
            details=action_details
        ))
        return {"message": f"사용자 '{username_to_delete}'이(가) 성공적으로 삭제되었습니다."}

    except (HtpasswdCommandError, HtpasswdError) as e: # htpasswd 명령어 관련 오류
        error_reason = str(e.stderr) if isinstance(e, HtpasswdCommandError) and e.stderr else str(e)
        logger.error(f"Failed to delete user '{username_to_delete}' by admin '{admin_user}'. Error: {error_reason}")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="user", resource_name=username_to_delete, status="FAILURE",
            details={**action_details, "reason": f"htpasswd operation failed: {error_reason}"}
        ))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"사용자 삭제 실패: {error_reason}"
        )
    except HtpasswdUtilityNotFoundError as e: # htpasswd 유틸리티 없음
        logger.error(f"htpasswd command not found when admin '{admin_user}' tried to delete user '{username_to_delete}'. Error: {e}")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="user", resource_name=username_to_delete, status="FAILURE",
            details={**action_details, "reason": f"Server configuration error: {e}"}
        ))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"서버 설정 오류: {e}"
        )
    except HtpasswdFileAccessError as e: # htpasswd 파일 접근 오류
        logger.error(f"Admin '{admin_user}' (IP: {client_ip}) failed to delete user '{username_to_delete}': {e}")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="user", resource_name=username_to_delete, status="FAILURE",
            details={**action_details, "reason": f"User database (htpasswd file) access error: {e}"}
        ))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"사용자 데이터베이스 처리 중 오류: {e}"
        )
    except Exception as e:
        logger.error(f"Unexpected error deleting user '{username_to_delete}' by admin '{admin_user}': {e}", exc_info=True)
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="user", resource_name=username_to_delete, status="FAILURE",
            details={**action_details, "reason": f"Unexpected error: {str(e)}"}
        ))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="사용자 삭제 중 예기치 않은 오류가 발생했습니다."
        )