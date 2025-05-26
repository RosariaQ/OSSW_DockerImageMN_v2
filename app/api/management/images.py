# app/api/management/images.py
from fastapi import APIRouter, Depends, HTTPException, status, Path as FastAPIPath, Query, Request
from pydantic import BaseModel
import logging
from typing import Optional, List, Dict, Any

# from app.core.config import settings # RegistryClientService가 settings를 사용
# authenticate_user 또는 get_current_admin_user를 상황에 맞게 사용
from app.auth.security import get_current_admin_user
from app.db.database import log_audit_event
from app.models.audit import AuditLogDBCreate
from app.models.audit_actions import AuditAction # 신규 임포트
from app.services.registry_client_service import ( # 신규 임포트
    RegistryService,
    get_registry_service,
    RegistryImageNotFoundError,
    RegistryPermissionError,
    RegistryClientError,
    COMMON_MANIFEST_ACCEPT_HEADERS # 상수 임포트
)

router = APIRouter()
logger = logging.getLogger(__name__)

# --- API 응답 모델 (선택 사항이지만, API 문서를 위해 좋음) ---
class ImageTagsResponse(BaseModel): #
    name: str
    tags: List[str]

class ImageRepositoriesResponse(BaseModel): #
    repositories: List[str]
    pagination_info: Dict[str, Any] | str # next_last로 변경될 수 있음

class ImageDeletionResponse(BaseModel): #
    message: str
    deleted_manifests: Optional[List[Dict[str, Any]]] = None
    errors: Optional[List[Dict[str, Any]]] = None

class TagDeletionResponse(BaseModel): #
    message: str


@router.get(
    "/{image_name:path}/tags",
    response_model=ImageTagsResponse,
    summary="특정 이미지의 태그 목록 조회",
    description="백엔드 Docker Registry에서 지정된 이미지의 태그 목록을 가져옵니다.\n\n관리자 인증이 필요합니다."
)
async def list_image_tags(
    request: Request,
    image_name: str = FastAPIPath(
        ...,
        title="이미지 이름",
        description="이미지의 이름으로, 슬래시를 포함할 수 있습니다 (예: 'myorg/myimage')."
    ),
    current_user: str = Depends(get_current_admin_user),
    registry_service: RegistryService = Depends(get_registry_service) # 서비스 주입
):
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path, "target_image": image_name}

    logger.info(f"User '{current_user}' (IP: {client_ip}) fetching tags for image '{image_name}'")

    try:
        tags_data = await registry_service.list_image_tags(image_name)
        tag_count = len(tags_data.get("tags", []))

        await log_audit_event(AuditLogDBCreate(
            username=current_user, action=AuditAction.IMAGE_TAGS_LIST, client_ip=client_ip,
            resource_type="image_tags", resource_name=image_name, status="SUCCESS",
            details={**action_details, "tag_count": tag_count}
        ))
        logger.info(f"Successfully fetched {tag_count} tags for '{image_name}'.")
        return tags_data
    except RegistryImageNotFoundError as e:
        logger.warning(f"Image '{image_name}' not found by user '{current_user}'. Error: {e}")
        await log_audit_event(AuditLogDBCreate(
            username=current_user, action=AuditAction.IMAGE_TAGS_LIST_ATTEMPT, client_ip=client_ip,
            resource_type="image_tags", resource_name=image_name, status="FAILURE",
            details={**action_details, "reason": str(e), "backend_status_code": e.status_code}
        ))
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"이미지 '{image_name}'을(를) 찾을 수 없습니다.")
    except RegistryClientError as e:
        logger.error(f"Error fetching tags for '{image_name}' by user '{current_user}'. Error: {e}")
        await log_audit_event(AuditLogDBCreate(
            username=current_user, action=AuditAction.IMAGE_TAGS_LIST_ATTEMPT, client_ip=client_ip,
            resource_type="image_tags", resource_name=image_name, status="FAILURE",
            details={**action_details, "reason": str(e), "backend_status_code": e.status_code}
        ))
        raise HTTPException(status_code=e.status_code or status.HTTP_502_BAD_GATEWAY,
                            detail=f"백엔드 레지스트리와 통신 중 오류: {str(e)}")
    except Exception as exc: # 예상치 못한 오류
        logger.exception(f"Unexpected error fetching tags for '{image_name}': {exc}")
        await log_audit_event(AuditLogDBCreate(
            username=current_user, action=AuditAction.IMAGE_TAGS_LIST_ATTEMPT, client_ip=client_ip,
            resource_type="image_tags", resource_name=image_name, status="FAILURE",
            details={**action_details, "reason": f"Unexpected error: {str(exc)}"}
        ))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="예기치 않은 오류가 발생했습니다.")


@router.get(
    "",
    response_model=ImageRepositoriesResponse,
    summary="레지스트리의 모든 이미지 (리포지토리) 목록 조회",
    description="백엔드 Docker Registry에서 모든 이미지 리포지토리 목록을 가져옵니다.\n\n'n'과 'last' 쿼리 파라미터를 사용하여 페이지네이션을 지원합니다.\n관리자 인증이 필요합니다."
)
async def list_all_images(
    request: Request,
    current_user: str = Depends(get_current_admin_user),
    n: Optional[int] = Query(None, description="결과 수 제한."),
    last: Optional[str] = Query(None, description="이전 결과의 마지막 리포지토리 이름 (페이지네이션용)."),
    registry_service: RegistryService = Depends(get_registry_service) # 서비스 주입
):
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path, "params": {"n": n, "last": last}}

    logger.info(f"User '{current_user}' (IP: {client_ip}) fetching image catalog with params: n={n}, last={last}")

    try:
        repositories, next_last = await registry_service.list_repositories(n, last)
        repo_count = len(repositories)

        pagination_display = {"next_repository_token": next_last} if next_last else "No further pages indicated."

        await log_audit_event(AuditLogDBCreate(
            username=current_user, action=AuditAction.IMAGE_CATALOG_LIST, client_ip=client_ip,
            status="SUCCESS", details={**action_details, "repository_count": repo_count, "pagination": pagination_display}
        ))
        logger.info(f"Successfully fetched image catalog. Count: {repo_count}, Next Last: {next_last}")
        return {"repositories": repositories, "pagination_info": pagination_display}

    except RegistryClientError as e:
        logger.error(f"Error fetching image catalog by user '{current_user}'. Error: {e}")
        await log_audit_event(AuditLogDBCreate(
            username=current_user, action=AuditAction.IMAGE_CATALOG_LIST_ATTEMPT, client_ip=client_ip,
            status="FAILURE", details={**action_details, "reason": str(e), "backend_status_code": e.status_code}
        ))
        raise HTTPException(status_code=e.status_code or status.HTTP_502_BAD_GATEWAY,
                            detail=f"백엔드 레지스트리와 통신 중 오류: {str(e)}")
    except Exception as exc:
        logger.exception(f"Unexpected error fetching image catalog: {exc}")
        await log_audit_event(AuditLogDBCreate(
            username=current_user, action=AuditAction.IMAGE_CATALOG_LIST_ATTEMPT, client_ip=client_ip,
            status="FAILURE", details={**action_details, "reason": f"Unexpected error: {str(exc)}"}
        ))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="예기치 않은 오류가 발생했습니다.")


@router.delete(
    "/{image_name:path}",
    response_model=ImageDeletionResponse,
    status_code=status.HTTP_200_OK,
    summary="이미지 (모든 매니페스트) 삭제",
    description="이미지 리포지토리와 관련된 모든 매니페스트를 삭제 시도합니다..."
)
async def delete_image_repository(
    request: Request,
    image_name: str = FastAPIPath(..., title="이미지 이름", description="삭제할 이미지 리포지토리의 이름"),
    admin_user: str = Depends(get_current_admin_user),
    registry_service: RegistryService = Depends(get_registry_service) # 서비스 주입
):
    client_ip = request.client.host if request.client else "Unknown"
    action_details = {"path": request.url.path, "target_image": image_name}
    logger.info(f"Admin '{admin_user}' (IP: {client_ip}) attempting to delete image repository '{image_name}'.")

    deleted_manifests_log: List[Dict[str, Any]] = []
    errors_deleting_log: List[Dict[str, Any]] = []
    overall_status = "SUCCESS"

    try:
        tags_data = await registry_service.list_image_tags(image_name) #
        tags: List[str] = tags_data.get("tags", [])

        if not tags:
            logger.info(f"Image repository '{image_name}' has no tags. Nothing to delete for admin '{admin_user}'.")
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.IMAGE_REPO_DELETE, client_ip=client_ip,
                resource_type="image_repository", resource_name=image_name, status="SUCCESS", # 또는 "NOT_APPLICABLE"
                details={**action_details, "reason": "Repository has no tags."}
            ))
            return {"message": f"이미지 리포지토리 '{image_name}'에 태그가 없습니다.", "deleted_manifests": [], "errors": []}

        for tag in tags:
            manifest_digest = None
            try:
                manifest_digest = await registry_service.get_manifest_digest(image_name, tag)
                if not manifest_digest:
                    logger.warning(f"Could not get manifest digest for tag '{tag}' in '{image_name}'. Skipping.")
                    errors_deleting_log.append({"tag": tag, "error": "Could not retrieve manifest digest (possibly already deleted or tag points to nothing)."})
                    overall_status = "PARTIAL_FAILURE"
                    continue

                logger.info(f"Attempting to delete manifest '{manifest_digest}' (tag: '{tag}') for image '{image_name}'.")
                if await registry_service.delete_manifest(image_name, manifest_digest):
                    logger.info(f"Successfully deleted manifest '{manifest_digest}' (tag: '{tag}') for image '{image_name}'.")
                    deleted_manifests_log.append({"tag": tag, "digest": manifest_digest, "status": "deleted"})
                else:
                    # delete_manifest가 False를 반환하면 (예: 404 또는 다른 클라이언트 오류) 오류로 기록
                    # RegistryPermissionError는 여기서 잡히지 않고 외부 try-except로 감.
                    logger.error(f"Failed to delete manifest '{manifest_digest}' (tag: '{tag}') for image '{image_name}'. See service logs.")
                    errors_deleting_log.append({"tag": tag, "digest": manifest_digest, "error": "Deletion unsuccessful (check service logs, possibly already deleted or backend issue)." })
                    overall_status = "PARTIAL_FAILURE"

            except RegistryImageNotFoundError: # get_manifest_digest 또는 delete_manifest에서 발생
                logger.warning(f"Manifest for tag '{tag}' (or digest {manifest_digest}) in '{image_name}' not found during deletion. Skipping.")
                errors_deleting_log.append({"tag": tag, "digest": manifest_digest or 'N/A', "error": "Manifest not found (404)."})
                overall_status = "PARTIAL_FAILURE"
            except RegistryPermissionError as e_perm: # delete_manifest에서 발생
                logger.error(f"Permission error deleting manifest for tag '{tag}' (digest: {manifest_digest}) in '{image_name}': {e_perm}")
                errors_deleting_log.append({"tag": tag, "digest": manifest_digest or 'N/A', "error": f"Permission error: {e_perm}"})
                overall_status = "FAILURE" # 심각한 오류로 간주
            except RegistryClientError as e_client: # 기타 서비스 오류
                logger.error(f"Client error deleting manifest for tag '{tag}' (digest: {manifest_digest}) in '{image_name}': {e_client}")
                errors_deleting_log.append({"tag": tag, "digest": manifest_digest or 'N/A', "error": f"Client error: {e_client}"})
                overall_status = "PARTIAL_FAILURE"
            except Exception as e_loop: # 루프 내 기타 예외
                logger.exception(f"Unexpected error in loop for tag '{tag}' during delete of '{image_name}': {e_loop}")
                errors_deleting_log.append({"tag": tag, "digest": manifest_digest or 'N/A', "error": f"Unexpected error: {str(e_loop)}"})
                overall_status = "PARTIAL_FAILURE"


    except RegistryImageNotFoundError: # 초기 list_image_tags에서 발생
        logger.info(f"Image repository '{image_name}' not found or has no tags. Considering it effectively deleted for admin '{admin_user}'.")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.IMAGE_REPO_DELETE, client_ip=client_ip,
            resource_type="image_repository", resource_name=image_name, status="SUCCESS",
            details={**action_details, "reason": "Repository not found, nothing to delete."}
        ))
        return {"message": f"이미지 리포지토리 '{image_name}'을(를) 찾을 수 없거나 삭제할 태그가 없습니다.", "deleted_manifests": [], "errors": []}
    except RegistryClientError as e: # 초기 list_image_tags에서 발생
        logger.error(f"Failed to list tags for '{image_name}' during delete by admin '{admin_user}'. Error: {e}")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.IMAGE_REPO_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="image_repository", resource_name=image_name, status="FAILURE",
            details={**action_details, "reason": f"Failed to list tags before deletion: {e}", "backend_status_code": e.status_code}
        ))
        raise HTTPException(status_code=e.status_code or status.HTTP_502_BAD_GATEWAY, detail=f"삭제 전 태그 목록 조회 실패: {e}")
    except Exception as e_outer: # 전체 작업의 예기치 않은 오류
        logger.exception(f"Unexpected error deleting image repository '{image_name}': {e_outer}")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.IMAGE_REPO_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="image_repository", resource_name=image_name, status="FAILURE",
            details={**action_details, "reason": f"Unexpected error: {str(e_outer)}"}
        ))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="이미지 리포지토리 삭제 중 예기치 않은 오류 발생.")


    # 최종 감사 로그 기록
    if not errors_deleting_log and not deleted_manifests_log and overall_status == "SUCCESS": # 태그는 있었지만 처리된게 없는 경우 (get_manifest_digest가 계속 None 등)
         overall_status = "NOT_APPLICABLE" # 혹은 SUCCESS, 상황에 따라 조정
         action_details["info"] = "No manifests were processed, check if tags correctly point to manifests."


    final_log_details = {
        **action_details,
        "deleted_count": len(deleted_manifests_log),
        "error_count": len(errors_deleting_log),
        "errors_summary": [e["error"] for e in errors_deleting_log[:3]] # 처음 3개 오류 요약
    }
    await log_audit_event(AuditLogDBCreate(
        username=admin_user, action=AuditAction.IMAGE_REPO_DELETE, client_ip=client_ip,
        resource_type="image_repository", resource_name=image_name, status=overall_status,
        details=final_log_details
    ))

    return {
        "message": f"이미지 리포지토리 '{image_name}'에 대한 삭제 작업이 완료되었습니다. Status: {overall_status}",
        "deleted_manifests": deleted_manifests_log,
        "errors": errors_deleting_log
    }


@router.delete(
    "/{image_name:path}/tags/{tag_name}",
    response_model=TagDeletionResponse,
    status_code=status.HTTP_200_OK,
    summary="이미지에서 특정 태그 삭제",
    description="이미지 리포지토리에서 특정 태그(해당 태그의 매니페스트 삭제)를 삭제합니다.\n\n관리자 인증이 필요합니다."
)
async def delete_image_tag(
    request: Request,
    image_name: str = FastAPIPath(..., title="이미지 이름"),
    tag_name: str = FastAPIPath(..., title="태그 이름"),
    admin_user: str = Depends(get_current_admin_user),
    registry_service: RegistryService = Depends(get_registry_service) # 서비스 주입
):
    client_ip = request.client.host if request.client else "Unknown"
    resource_id = f"{image_name}:{tag_name}"
    action_details = {"path": request.url.path, "target_image": image_name, "target_tag": tag_name}
    logger.info(f"Admin '{admin_user}' (IP: {client_ip}) attempting to delete tag '{tag_name}' from image '{image_name}'.")

    manifest_digest = None
    try:
        manifest_digest = await registry_service.get_manifest_digest(image_name, tag_name)
        if not manifest_digest:
            # get_manifest_digest가 None을 반환하면 (내부에서 404 등 처리) RegistryImageNotFoundError가 아님
            logger.warning(f"Tag '{tag_name}' on image '{image_name}' does not point to a retrievable manifest digest. Admin: '{admin_user}'.")
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.IMAGE_TAG_DELETE_ATTEMPT, client_ip=client_ip,
                resource_type="image_tag", resource_name=resource_id, status="FAILURE",
                details={**action_details, "reason": "Manifest digest for tag not found or tag does not exist."}
            ))
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"이미지 '{image_name}'의 태그 '{tag_name}'에 대한 매니페스트를 찾을 수 없습니다.")

        logger.info(f"Found manifest digest '{manifest_digest}' for tag '{tag_name}'. Attempting deletion by admin '{admin_user}'.")

        if await registry_service.delete_manifest(image_name, manifest_digest):
            logger.info(f"Successfully deleted manifest '{manifest_digest}' (associated with tag '{tag_name}') for admin '{admin_user}'.")
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.IMAGE_TAG_DELETE, client_ip=client_ip,
                resource_type="image_tag", resource_name=resource_id,
                status="SUCCESS", details={**action_details, "deleted_manifest_digest": manifest_digest}
            ))
            return {"message": f"이미지 '{image_name}'의 태그 '{tag_name}' (매니페스트 {manifest_digest})이(가) 성공적으로 삭제되었습니다."}
        else:
            # delete_manifest가 False를 반환했지만 예외는 아닌 경우 (예: 삭제 시 404)
            # RegistryService의 delete_manifest에서 False 반환은 "이미 없음" 또는 "클라이언트 측 오류" 일 수 있음.
            # 여기서는 더 구체적인 예외를 기대하므로, False 반환 시 로직 재검토 필요.
            # 현재 RegistryService.delete_manifest는 예외를 발생시키거나 성공 시 True.
            # 따라서 이 else 블록은 도달하기 어려울 수 있음.
            logger.error(f"Deletion of manifest '{manifest_digest}' for tag '{tag_name}' was reported as unsuccessful by the service for admin '{admin_user}'.")
            await log_audit_event(AuditLogDBCreate(
                username=admin_user, action=AuditAction.IMAGE_TAG_DELETE_ATTEMPT, client_ip=client_ip,
                resource_type="image_tag", resource_name=resource_id, status="FAILURE",
                details={**action_details, "reason": "Manifest deletion unsuccessful by service.", "manifest_digest_attempted": manifest_digest}
            ))
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="매니페스트 삭제에 실패했으나 구체적인 오류는 없습니다.")


    except RegistryImageNotFoundError as e: # get_manifest_digest 또는 delete_manifest에서 발생
        logger.warning(f"Tag '{tag_name}' or image '{image_name}' not found, or manifest {manifest_digest} not found during delete. Admin: '{admin_user}'. Error: {e}")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.IMAGE_TAG_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="image_tag", resource_name=resource_id, status="FAILURE",
            details={**action_details, "reason": f"Tag or manifest not found: {e}", "backend_status_code": e.status_code, "manifest_digest_attempted": manifest_digest}
        ))
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"삭제할 태그 또는 매니페스트를 찾을 수 없습니다: {e}")
    except RegistryPermissionError as e:
        logger.error(f"Permission error deleting manifest for tag '{tag_name}'. Admin: '{admin_user}'. Error: {e}")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.IMAGE_TAG_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="image_tag", resource_name=resource_id, status="FAILURE",
            details={**action_details, "reason": f"Permission error: {e}", "backend_status_code": e.status_code, "manifest_digest_attempted": manifest_digest}
        ))
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"매니페스트 삭제 권한 오류: {e}") # 또는 500
    except RegistryClientError as e: # 기타 클라이언트 오류
        logger.error(f"Registry client error deleting tag '{tag_name}'. Admin: '{admin_user}'. Error: {e}")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.IMAGE_TAG_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="image_tag", resource_name=resource_id, status="FAILURE",
            details={**action_details, "reason": str(e), "backend_status_code": e.status_code, "manifest_digest_attempted": manifest_digest}
        ))
        raise HTTPException(status_code=e.status_code or status.HTTP_502_BAD_GATEWAY, detail=f"레지스트리 통신 오류: {e}")
    except Exception as e_other:
        logger.exception(f"Unexpected error during tag deletion for '{resource_id}' by admin '{admin_user}': {e_other}")
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.IMAGE_TAG_DELETE_ATTEMPT, client_ip=client_ip,
            resource_type="image_tag", resource_name=resource_id, status="FAILURE",
            details={**action_details, "reason": f"Unexpected error: {str(e_other)}", "manifest_digest_attempted": manifest_digest}
        ))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="태그 삭제 중 예기치 않은 오류 발생.")