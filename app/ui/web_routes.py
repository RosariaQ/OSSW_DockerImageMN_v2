# app/ui/web_routes.py
import logging
from fastapi import APIRouter, Request, Depends, HTTPException, status, Form, Query # Query 추가
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from typing import Optional, List # List 추가
from starlette.datastructures import URL 

from app.core.config import settings
from app.auth.security import authenticate_user, get_current_admin_user
from app.services.registry_client_service import get_registry_service, RegistryService, RegistryClientError, RegistryImageNotFoundError, RegistryPermissionError
from app.services.htpasswd_service import get_htpasswd_service, HtpasswdService, HtpasswdError, HtpasswdFileAccessError, HtpasswdCommandError, HtpasswdUtilityNotFoundError

# 감사 로그 관련 임포트
from app.db.database import engine, audit_log_table, log_audit_event # engine, audit_log_table 추가
from app.models.audit import AuditLogDB, AuditLogDBCreate # AuditLogDB 추가
from app.models.audit_actions import AuditAction

# SQLAlchemy 관련 임포트 (view_audit_logs_web_ui 에서 사용)
from sqlalchemy import select, desc, and_


# 로거 객체 생성
logger = logging.getLogger(__name__)

router = APIRouter()

BASE_PROJECT_DIR = Path(__file__).resolve().parent.parent.parent
templates = Jinja2Templates(directory=BASE_PROJECT_DIR / "templates")


@router.get("/", response_class=HTMLResponse, name="read_root_web")
async def read_root_web(request: Request):
    """웹 UI의 메인 홈 페이지를 보여줍니다."""
    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "홈",
        "app_version": settings.API_VERSION
    })

@router.get("/images", response_class=HTMLResponse, name="list_images_web_ui")
async def list_images_web_ui(
    request: Request,
    registry_service: RegistryService = Depends(get_registry_service),
    current_user: str = Depends(authenticate_user),
    message: Optional[str] = None, 
    error: Optional[str] = None     
):
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path, "viewed_via": "web_ui"}
    repositories_list = [] 
    fetch_error_msg = None

    try:
        repositories_data, _ = await registry_service.list_repositories(n=100)
        repositories_list = repositories_data
    except RegistryClientError as e:
        logger.error(f"Web UI: User '{current_user}' failed to fetch image repositories: {e}", exc_info=True)
        fetch_error_msg = f"레지스트리에서 이미지 목록을 가져올 수 없습니다: {str(e)}"
        await log_audit_event(AuditLogDBCreate( 
            username=current_user, action=AuditAction.IMAGE_CATALOG_LIST_ATTEMPT, client_ip=client_ip,
            status="FAILURE", details={**action_details, "reason": str(e), "backend_status_code": e.status_code}
        ))
    except Exception as e:
        logger.error(f"Web UI: User '{current_user}' encountered unexpected error fetching image repositories: {e}", exc_info=True)
        fetch_error_msg = f"이미지 목록을 가져오는 중 예기치 않은 오류가 발생했습니다: {str(e)}"
        await log_audit_event(AuditLogDBCreate( 
            username=current_user, action=AuditAction.IMAGE_CATALOG_LIST_ATTEMPT, client_ip=client_ip,
            status="FAILURE", details={**action_details, "reason": f"Unexpected error: {str(e)}"}
        ))
    
    final_error_to_display = error or fetch_error_msg 

    return templates.TemplateResponse("images/list_images.html", {
        "request": request, "title": "이미지 리포지토리", "repositories": repositories_list,
        "current_user": current_user, "app_version": settings.API_VERSION,
        "message": message, 
        "error": final_error_to_display
    })

@router.get("/images/{image_name:path}/tags", response_class=HTMLResponse, name="list_image_tags_web_ui")
async def list_image_tags_web_ui(
    request: Request, image_name: str,
    registry_service: RegistryService = Depends(get_registry_service),
    current_user: str = Depends(authenticate_user),
    message: Optional[str] = None, 
    error: Optional[str] = None     
):
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path, "target_image": image_name, "viewed_via": "web_ui"}
    tags_list = [] 
    fetch_error_msg = None

    try:
        image_data = await registry_service.list_image_tags(image_name)
        tags_from_service = image_data.get("tags", [])
        if tags_from_service is None: tags_from_service = []
        tags_list = tags_from_service
    except RegistryImageNotFoundError:
        logger.warning(f"Web UI: User '{current_user}' failed to find image '{image_name}' when fetching tags.", exc_info=True)
        fetch_error_msg = f"이미지 '{image_name}'을(를) 찾을 수 없습니다."
        await log_audit_event(AuditLogDBCreate( 
            username=current_user, action=AuditAction.IMAGE_TAGS_LIST_ATTEMPT, client_ip=client_ip,
            resource_type="image_tags", resource_name=image_name, status="FAILURE",
            details={**action_details, "reason": "Image not found"}
        ))
    except RegistryClientError as e:
        logger.error(f"Web UI: User '{current_user}' failed to fetch tags for '{image_name}': {e}", exc_info=True)
        fetch_error_msg = f"'{image_name}' 이미지의 태그를 가져올 수 없습니다: {str(e)}"
        await log_audit_event(AuditLogDBCreate( 
            username=current_user, action=AuditAction.IMAGE_TAGS_LIST_ATTEMPT, client_ip=client_ip,
            resource_type="image_tags", resource_name=image_name, status="FAILURE",
            details={**action_details, "reason": str(e), "backend_status_code": e.status_code}
        ))
    except Exception as e:
        logger.error(f"Web UI: User '{current_user}' encountered unexpected error fetching tags for '{image_name}': {e}", exc_info=True)
        fetch_error_msg = f"태그 목록을 가져오는 중 예기치 않은 오류가 발생했습니다: {str(e)}"
        await log_audit_event(AuditLogDBCreate( 
            username=current_user, action=AuditAction.IMAGE_TAGS_LIST_ATTEMPT, client_ip=client_ip,
            resource_type="image_tags", resource_name=image_name, status="FAILURE",
            details={**action_details, "reason": f"Unexpected error: {str(e)}"}
        ))

    final_error_to_display = error or fetch_error_msg

    return templates.TemplateResponse("images/list_tags.html", {
        "request": request, "title": f"'{image_name}' 이미지 태그", "image_name": image_name, "tags": tags_list,
        "current_user": current_user, "app_version": settings.API_VERSION,
        "message": message, 
        "error": final_error_to_display
    })

@router.get("/admin/users", response_class=HTMLResponse, name="manage_users_web_ui")
async def manage_users_web_ui(
    request: Request,
    htpasswd_service: HtpasswdService = Depends(get_htpasswd_service),
    admin_user: str = Depends(get_current_admin_user),
    message: Optional[str] = None,
    error: Optional[str] = None
):
    users = []
    fetch_error = None
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path, "viewed_via": "web_ui"}

    try:
        users = htpasswd_service.list_users()
    except HtpasswdFileAccessError as e:
        logger.error(f"Admin UI: Admin '{admin_user}' failed to list users: {e}", exc_info=True)
        fetch_error = f"사용자 목록을 가져오는 데 실패했습니다: {e}"
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_LIST_ATTEMPT, client_ip=client_ip,
            status="FAILURE", details={**action_details, "reason": f"User database (htpasswd file) access error: {e}"}
        ))
    except Exception as e:
        logger.error(f"Admin UI: Admin '{admin_user}' encountered an unexpected error listing users: {e}", exc_info=True)
        fetch_error = f"사용자 목록을 가져오는 중 예기치 않은 오류가 발생했습니다: {e}"
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_LIST_ATTEMPT, client_ip=client_ip,
            status="FAILURE", details={**action_details, "reason": f"Unexpected error: {str(e)}"}
        ))

    return templates.TemplateResponse("admin/users_management.html", {
        "request": request, "title": "사용자 관리", "users": users,
        "current_user": admin_user, "message": message, "error": error or fetch_error,
        "app_version": settings.API_VERSION, "settings": settings
    })

@router.post("/admin/users/create", response_class=HTMLResponse, name="create_user_web_ui")
async def create_user_web_ui(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    htpasswd_service: HtpasswdService = Depends(get_htpasswd_service),
    admin_user: str = Depends(get_current_admin_user)
):
    success_message = None
    error_message = None
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"target_username": username, "created_via": "web_ui"}

    if not username or len(username) < 1:
        error_message = "사용자 이름은 필수입니다."
    elif not password or len(password) < 6:
        error_message = "비밀번호는 최소 6자 이상이어야 합니다."
    else:
        try:
            if htpasswd_service.user_exists(username):
                error_message = f"사용자 '{username}'은(는) 이미 존재합니다."
                await log_audit_event(AuditLogDBCreate(
                    username=admin_user, action=AuditAction.USER_CREATE_ATTEMPT, client_ip=client_ip,
                    resource_type="user", resource_name=username, status="FAILURE",
                    details={**action_details, "reason": f"User '{username}' already exists."}
                ))
            else:
                htpasswd_service.add_user(username, password)
                success_message = f"사용자 '{username}'이(가) 성공적으로 생성되었습니다."
                logger.info(f"Admin UI: User '{username}' created by admin '{admin_user}'.")
                await log_audit_event(AuditLogDBCreate(
                    username=admin_user, action=AuditAction.USER_CREATE, client_ip=client_ip,
                    resource_type="user", resource_name=username, status="SUCCESS",
                    details=action_details
                ))
        except HtpasswdFileAccessError as e:
            logger.error(f"Admin UI: Admin '{admin_user}' failed to create user '{username}': {e}", exc_info=True)
            error_message = f"사용자 데이터베이스 접근 오류: {e}"
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.USER_CREATE_ATTEMPT, client_ip=client_ip,
                resource_type="user", resource_name=username, status="FAILURE",
                details={**action_details, "reason": f"User database (htpasswd file) access error: {e}"}
            ))
        except (HtpasswdCommandError, HtpasswdUtilityNotFoundError, HtpasswdError) as e:
            logger.error(f"Admin UI: Admin '{admin_user}' failed to create user '{username}': {e}", exc_info=True)
            error_message = f"사용자 생성 실패: {e}"
            error_reason_detail = str(e.stderr) if isinstance(e, HtpasswdCommandError) and e.stderr else str(e)
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.USER_CREATE_ATTEMPT, client_ip=client_ip,
                resource_type="user", resource_name=username, status="FAILURE",
                details={**action_details, "reason": f"htpasswd operation failed: {error_reason_detail}"}
            ))
        except Exception as e:
            logger.error(f"Admin UI: Admin '{admin_user}' encountered an unexpected error creating user '{username}': {e}", exc_info=True)
            error_message = f"예기치 않은 오류 발생: {e}"
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.USER_CREATE_ATTEMPT, client_ip=client_ip,
                resource_type="user", resource_name=username, status="FAILURE",
                details={**action_details, "reason": f"Unexpected error: {str(e)}"}
            ))
    
    final_redirect_url_obj: URL = request.url_for("manage_users_web_ui")
    query_params = {}
    if success_message:
        query_params["message"] = success_message
    elif error_message:
        query_params["error"] = error_message
    
    if query_params:
        final_redirect_url_obj = final_redirect_url_obj.include_query_params(**query_params)
        
    return RedirectResponse(url=str(final_redirect_url_obj), status_code=status.HTTP_303_SEE_OTHER)


@router.post("/admin/users/delete/{username_to_delete}", response_class=HTMLResponse, name="delete_user_web_ui")
async def delete_user_web_ui(
    request: Request,
    username_to_delete: str,
    htpasswd_service: HtpasswdService = Depends(get_htpasswd_service),
    admin_user: str = Depends(get_current_admin_user)
):
    success_message = None
    error_message = None
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"target_username": username_to_delete, "deleted_via": "web_ui"}

    try:
        if not htpasswd_service.user_exists(username_to_delete):
            error_message = f"삭제할 사용자 '{username_to_delete}'을(를) 찾을 수 없습니다."
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.USER_DELETE_ATTEMPT, client_ip=client_ip,
                resource_type="user", resource_name=username_to_delete, status="FAILURE",
                details={**action_details, "reason": "User not found."}
            ))
        elif username_to_delete == admin_user:
            error_message = "관리자는 자기 자신을 삭제할 수 없습니다."
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.USER_DELETE_ATTEMPT, client_ip=client_ip,
                resource_type="user", resource_name=username_to_delete, status="FAILURE",
                details={**action_details, "reason": "Admin attempted to delete self."}
            ))
        elif username_to_delete in settings.ADMIN_USERNAMES:
             error_message = f"다른 관리자 계정('{username_to_delete}')은 삭제할 수 없습니다."
             await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.USER_DELETE_ATTEMPT, client_ip=client_ip,
                resource_type="user", resource_name=username_to_delete, status="FAILURE",
                details={**action_details, "reason": "Attempted to delete another admin user."}
            ))
        else:
            htpasswd_service.delete_user(username_to_delete)
            success_message = f"사용자 '{username_to_delete}'이(가) 성공적으로 삭제되었습니다."
            logger.info(f"Admin UI: User '{username_to_delete}' deleted by admin '{admin_user}'.")
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.USER_DELETE, client_ip=client_ip,
                resource_type="user", resource_name=username_to_delete, status="SUCCESS",
                details=action_details
            ))
    except HtpasswdFileAccessError as e:
        logger.error(f"Admin UI: Admin '{admin_user}' failed to delete user '{username_to_delete}': {e}", exc_info=True)
        error_message = f"사용자 데이터베이스 접근 오류: {e}"
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="user", resource_name=username_to_delete, status="FAILURE",
            details={**action_details, "reason": f"User database (htpasswd file) access error: {e}"}
        ))
    except (HtpasswdCommandError, HtpasswdUtilityNotFoundError, HtpasswdError) as e:
        logger.error(f"Admin UI: Admin '{admin_user}' failed to delete user '{username_to_delete}': {e}", exc_info=True)
        error_message = f"사용자 삭제 실패: {e}"
        error_reason_detail = str(e.stderr) if isinstance(e, HtpasswdCommandError) and e.stderr else str(e)
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="user", resource_name=username_to_delete, status="FAILURE",
            details={**action_details, "reason": f"htpasswd operation failed: {error_reason_detail}"}
        ))
    except Exception as e:
        logger.error(f"Admin UI: Admin '{admin_user}' encountered an unexpected error deleting user '{username_to_delete}': {e}", exc_info=True)
        error_message = f"예기치 않은 오류 발생: {e}"
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.USER_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="user", resource_name=username_to_delete, status="FAILURE",
            details={**action_details, "reason": f"Unexpected error: {str(e)}"}
        ))

    final_redirect_url_obj: URL = request.url_for("manage_users_web_ui")
    query_params = {}
    if success_message:
        query_params["message"] = success_message
    elif error_message:
        query_params["error"] = error_message

    if query_params:
        final_redirect_url_obj = final_redirect_url_obj.include_query_params(**query_params)
        
    return RedirectResponse(url=str(final_redirect_url_obj), status_code=status.HTTP_303_SEE_OTHER)


@router.post("/images/{image_name:path}/tags/{tag_name}/delete", response_class=HTMLResponse, name="delete_image_tag_web_ui")
async def delete_image_tag_web_ui(
    request: Request,
    image_name: str,
    tag_name: str,
    registry_service: RegistryService = Depends(get_registry_service),
    admin_user: str = Depends(get_current_admin_user)
):
    success_message = None
    error_message = None
    client_ip = request.client.host if request.client else "Unknown"
    resource_id = f"{image_name}:{tag_name}"
    action_details = {"target_image": image_name, "target_tag": tag_name, "deleted_via": "web_ui"}
    manifest_digest = None

    try:
        manifest_digest = await registry_service.get_manifest_digest(image_name, tag_name)
        if not manifest_digest:
            error_message = f"이미지 '{image_name}'의 태그 '{tag_name}'에 대한 매니페스트를 찾을 수 없어 삭제할 수 없습니다."
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.IMAGE_TAG_DELETE_ATTEMPT, client_ip=client_ip,
                resource_type="image_tag", resource_name=resource_id, status="FAILURE",
                details={**action_details, "reason": "Manifest digest for tag not found or tag does not exist."}
            ))
        else:
            delete_successful = await registry_service.delete_manifest(image_name, manifest_digest)
            if delete_successful:
                success_message = f"이미지 '{image_name}'의 태그 '{tag_name}' (매니페스트 {manifest_digest})이(가) 성공적으로 삭제되었습니다."
                logger.info(f"Admin UI: Tag '{resource_id}' (manifest: {manifest_digest}) deleted by admin '{admin_user}'.")
                await log_audit_event(AuditLogDBCreate(
                    username=admin_user, action=AuditAction.IMAGE_TAG_DELETE, client_ip=client_ip,
                    resource_type="image_tag", resource_name=resource_id, status="SUCCESS",
                    details={**action_details, "deleted_manifest_digest": manifest_digest}
                ))
            else:
                error_message = f"이미지 '{image_name}'의 태그 '{tag_name}' 삭제에 실패했습니다 (서비스에서 명시적 실패 반환)."
                await log_audit_event(AuditLogDBCreate(
                    username=admin_user, action=AuditAction.IMAGE_TAG_DELETE_ATTEMPT, client_ip=client_ip,
                    resource_type="image_tag", resource_name=resource_id, status="FAILURE",
                    details={**action_details, "reason": "Manifest deletion unsuccessful by service.", "manifest_digest_attempted": manifest_digest}
                ))
    except RegistryImageNotFoundError as e:
        logger.warning(f"Admin UI: Tag '{resource_id}' or its manifest not found during deletion attempt by '{admin_user}'. Error: {e}", exc_info=True)
        error_message = f"삭제할 태그 또는 매니페스트를 찾을 수 없습니다: {e}"
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.IMAGE_TAG_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="image_tag", resource_name=resource_id, status="FAILURE",
            details={**action_details, "reason": f"Tag or manifest not found: {e}", "backend_status_code": e.status_code, "manifest_digest_attempted": manifest_digest}
        ))
    except RegistryPermissionError as e: 
        logger.error(f"Admin UI: Permission error deleting manifest for tag '{resource_id}' by '{admin_user}'. Error: {e}", exc_info=True)
        error_message = f"매니페스트 삭제 권한 오류: {e}"
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.IMAGE_TAG_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="image_tag", resource_name=resource_id, status="FAILURE",
            details={**action_details, "reason": f"Permission error: {e}", "backend_status_code": e.status_code, "manifest_digest_attempted": manifest_digest}
        ))
    except RegistryClientError as e:
        logger.error(f"Admin UI: Registry client error deleting tag '{resource_id}' by '{admin_user}'. Error: {e}", exc_info=True)
        error_message = f"레지스트리 통신 오류: {e}"
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.IMAGE_TAG_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="image_tag", resource_name=resource_id, status="FAILURE",
            details={**action_details, "reason": str(e), "backend_status_code": e.status_code, "manifest_digest_attempted": manifest_digest}
        ))
    except Exception as e:
        logger.exception(f"Admin UI: Unexpected error during tag deletion for '{resource_id}' by '{admin_user}': {e}")
        error_message = f"태그 삭제 중 예기치 않은 오류 발생: {e}"
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.IMAGE_TAG_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="image_tag", resource_name=resource_id, status="FAILURE",
            details={**action_details, "reason": f"Unexpected error: {str(e)}", "manifest_digest_attempted": manifest_digest}
        ))

    final_redirect_url_obj: URL = request.url_for("list_image_tags_web_ui", image_name=image_name)
    query_params = {}
    if success_message:
        query_params["message"] = success_message
    elif error_message:
        query_params["error"] = error_message
    
    if query_params:
        final_redirect_url_obj = final_redirect_url_obj.include_query_params(**query_params)
        
    return RedirectResponse(url=str(final_redirect_url_obj), status_code=status.HTTP_303_SEE_OTHER)


@router.post("/images/{image_name:path}/delete", response_class=HTMLResponse, name="delete_image_repository_web_ui")
async def delete_image_repository_web_ui(
    request: Request,
    image_name: str,
    registry_service: RegistryService = Depends(get_registry_service),
    admin_user: str = Depends(get_current_admin_user)
):
    success_message = None
    error_message = None
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"target_image": image_name, "deleted_via": "web_ui"}
    deleted_manifests_log: list = []
    errors_deleting_log: list = []
    overall_status = "SUCCESS"

    try:
        tags_data = await registry_service.list_image_tags(image_name)
        tags: list[str] = tags_data.get("tags", [])
        if tags is None: tags = []

        if not tags:
            success_message = f"이미지 리포지토리 '{image_name}'에 태그가 없어 삭제할 내용이 없습니다."
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.IMAGE_REPO_DELETE, client_ip=client_ip,
                resource_type="image_repository", resource_name=image_name, status="SUCCESS",
                details={**action_details, "reason": "Repository has no tags or is empty."}
            ))
        else:
            for tag_item in tags: 
                manifest_digest_repo = None 
                try:
                    manifest_digest_repo = await registry_service.get_manifest_digest(image_name, tag_item)
                    if not manifest_digest_repo:
                        errors_deleting_log.append({"tag": tag_item, "error": "매니페스트 digest를 가져올 수 없습니다."})
                        overall_status = "PARTIAL_FAILURE"
                        continue
                    
                    if await registry_service.delete_manifest(image_name, manifest_digest_repo):
                        deleted_manifests_log.append({"tag": tag_item, "digest": manifest_digest_repo})
                    else:
                        errors_deleting_log.append({"tag": tag_item, "digest": manifest_digest_repo, "error": "매니페스트 삭제 실패 (서비스 응답)." })
                        overall_status = "PARTIAL_FAILURE"
                except RegistryImageNotFoundError:
                    errors_deleting_log.append({"tag": tag_item, "digest": manifest_digest_repo or 'N/A', "error": "매니페스트를 찾을 수 없음 (404)."})
                    overall_status = "PARTIAL_FAILURE"
                except RegistryPermissionError as e_perm: 
                    errors_deleting_log.append({"tag": tag_item, "digest": manifest_digest_repo or 'N/A', "error": f"권한 오류: {str(e_perm)}"})
                    overall_status = "PARTIAL_FAILURE" 
                except Exception as e_loop:
                    errors_deleting_log.append({"tag": tag_item, "digest": manifest_digest_repo or 'N/A', "error": f"태그 처리 중 예외: {str(e_loop)}"})
                    overall_status = "PARTIAL_FAILURE"
            
            if not errors_deleting_log and deleted_manifests_log: 
                 success_message = f"이미지 리포지토리 '{image_name}'의 모든 태그 ({len(deleted_manifests_log)}개)가 성공적으로 삭제되었습니다."
            elif deleted_manifests_log: 
                success_message = f"이미지 리포지토리 '{image_name}'의 일부 태그가 삭제되었습니다 ({len(deleted_manifests_log)}개 성공, {len(errors_deleting_log)}개 실패)."
            elif errors_deleting_log: 
                error_message = f"이미지 리포지토리 '{image_name}'의 태그를 삭제하는 중 오류가 발생했습니다 ({len(errors_deleting_log)}개 실패)."
                overall_status = "FAILURE"

            final_log_details = {
                **action_details,
                "deleted_count": len(deleted_manifests_log),
                "error_count": len(errors_deleting_log),
                "errors_summary": [e["error"] for e in errors_deleting_log[:3]]
            }
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.IMAGE_REPO_DELETE, client_ip=client_ip,
                resource_type="image_repository", resource_name=image_name, status=overall_status,
                details=final_log_details
            ))

    except RegistryImageNotFoundError:
        success_message = f"이미지 리포지토리 '{image_name}'을(를) 찾을 수 없어 삭제할 내용이 없습니다."
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.IMAGE_REPO_DELETE, client_ip=client_ip,
            resource_type="image_repository", resource_name=image_name, status="SUCCESS",
            details={**action_details, "reason": "Repository not found, nothing to delete."}
        ))
    except RegistryPermissionError as e: 
        logger.error(f"Admin UI: Permission error during repository deletion for '{image_name}' by '{admin_user}'. Error: {e}", exc_info=True)
        error_message = f"리포지토리 삭제 처리 중 권한 오류 발생: {e}"
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.IMAGE_REPO_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="image_repository", resource_name=image_name, status="FAILURE",
            details={**action_details, "reason": f"Permission error: {e}", "backend_status_code": e.status_code}
        ))
    except RegistryClientError as e:
        logger.error(f"Admin UI: Failed to process repository deletion for '{image_name}' by '{admin_user}'. Error: {e}", exc_info=True)
        error_message = f"리포지토리 삭제 처리 중 레지스트리 오류 발생: {e}"
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.IMAGE_REPO_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="image_repository", resource_name=image_name, status="FAILURE",
            details={**action_details, "reason": f"Registry client error: {e}", "backend_status_code": e.status_code}
        ))
    except Exception as e:
        logger.exception(f"Admin UI: Unexpected error deleting image repository '{image_name}' by '{admin_user}': {e}")
        error_message = f"리포지토리 삭제 중 예기치 않은 오류 발생: {e}"
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.IMAGE_REPO_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="image_repository", resource_name=image_name, status="FAILURE",
            details={**action_details, "reason": f"Unexpected error: {str(e)}"}
        ))

    final_redirect_url_obj: URL = request.url_for("list_images_web_ui")
    query_params = {}
    if success_message:
        query_params["message"] = success_message
    elif error_message:
        query_params["error"] = error_message
    
    if query_params:
        final_redirect_url_obj = final_redirect_url_obj.include_query_params(**query_params)
        
    return RedirectResponse(url=str(final_redirect_url_obj), status_code=status.HTTP_303_SEE_OTHER)

# --- 감사 로그 조회 페이지 라우트 (GET) ---
@router.get("/admin/audit", response_class=HTMLResponse, name="view_audit_logs_web_ui")
async def view_audit_logs_web_ui(
    request: Request,
    admin_user: str = Depends(get_current_admin_user), 
    filter_user: Optional[str] = Query(None, alias="user", description="로그를 필터링할 사용자 이름."),
    filter_image_name: Optional[str] = Query(None, alias="image", description="로그를 필터링할 이미지 이름 (부분 일치 가능)."),
    filter_action: Optional[str] = Query(None, alias="action", description="로그를 필터링할 작업 유형."),
    limit: int = Query(100, ge=1, le=1000, description="반환할 최대 로그 수."),
    offset: int = Query(0, ge=0, description="결과를 건너뛸 오프셋 (페이지네이션용).")
):
    client_ip = request.client.host if request.client else "Unknown"
    logs = []
    db_error = None
    
    current_filters = {
        "user": filter_user,
        "image": filter_image_name,
        "action": filter_action,
        "limit": limit,
        "offset": offset
    }
    audit_action_options = [action_enum.value for action_enum in AuditAction] # 변수명 변경

    try:
        query = select(audit_log_table)
        filter_conditions = []

        if filter_user:
            filter_conditions.append(audit_log_table.c.username == filter_user)
        if filter_image_name:
            filter_conditions.append(audit_log_table.c.resource_name.like(f"%{filter_image_name}%"))
        if filter_action:
            filter_conditions.append(audit_log_table.c.action == filter_action)

        if filter_conditions:
            query = query.where(and_(*filter_conditions))

        query = query.order_by(desc(audit_log_table.c.timestamp)).limit(limit).offset(offset)

        with engine.connect() as connection:
            result_proxy = connection.execute(query)
            for row in result_proxy.mappings():
                logs.append(AuditLogDB.model_validate(row)) 

        log_filters_details = {"filters": current_filters, "returned_count": len(logs), "viewed_via": "web_ui"}
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.AUDIT_LOG_VIEW, client_ip=client_ip,
            status="SUCCESS", details=log_filters_details
        ))

    except Exception as e:
        logger.error(f"Admin UI: Admin '{admin_user}' failed to query audit logs: {e}", exc_info=True)
        db_error = f"감사 로그를 조회하는 중 오류가 발생했습니다: {e}"
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.AUDIT_LOG_VIEW_ATTEMPT, client_ip=client_ip,
            status="FAILURE", details={"filters": current_filters, "reason": str(e), "viewed_via": "web_ui"}
        ))

    return templates.TemplateResponse("admin/audit_log.html", {
        "request": request,
        "title": "감사 로그 조회",
        "logs": logs,
        "current_user": admin_user,
        "error": db_error,
        "current_filters": current_filters, 
        "audit_action_options": audit_action_options, 
        "app_version": settings.API_VERSION,
        "settings": settings 
    })
