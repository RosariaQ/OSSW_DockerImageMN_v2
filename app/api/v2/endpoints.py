# app/api/v2/endpoints.py
from fastapi import APIRouter, Request, HTTPException, Depends, status
from fastapi.responses import StreamingResponse
import httpx
import logging
import re

from app.core.config import settings
from app.auth.security import authenticate_user
from app.db.database import log_audit_event
from app.models.audit import AuditLogDBCreate
from app.models.audit_actions import AuditAction # 신규 임포트
from typing import Optional

router = APIRouter()
logger = logging.getLogger(__name__)

# 매니페스트 경로를 식별하기 위한 정규표현식
MANIFEST_PATH_REGEX = re.compile(r"^(?P<image_name>.+)/manifests/(?P<reference>[^/]+)$") #

@router.api_route("/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_v2_requests(
    request: Request,
    path: str,
    current_user: str = Depends(authenticate_user)
):
    target_url = f"{settings.DISTRIBUTION_REGISTRY_URL}/v2/{path}" #
    client_ip = request.client.host if request.client else "Unknown"

    audit_action_base: Optional[AuditAction] = None
    audit_resource_type: Optional[str] = None
    audit_resource_name: Optional[str] = None
    audit_details = {"path": f"/v2/{path}", "method": request.method, "proxied_to": target_url}

    manifest_match = MANIFEST_PATH_REGEX.match(path) #
    if manifest_match:
        image_name_from_path = manifest_match.group("image_name") #
        reference_from_path = manifest_match.group("reference") #
        audit_resource_name = f"{image_name_from_path}:{reference_from_path}" #
        audit_resource_type = "image_manifest" #
        audit_details["target_image"] = image_name_from_path
        audit_details["target_reference"] = reference_from_path

        if request.method == "GET":
            audit_action_base = AuditAction.IMAGE_PULL_MANIFEST_ATTEMPT #
        elif request.method == "PUT":
            audit_action_base = AuditAction.IMAGE_PUSH_MANIFEST_ATTEMPT #
        elif request.method == "HEAD":
            audit_action_base = AuditAction.IMAGE_MANIFEST_CHECK_ATTEMPT #
        elif request.method == "DELETE": # Manifest 직접 삭제 (management API와 구분)
            audit_action_base = AuditAction.IMAGE_MANIFEST_DELETE_VIA_PROXY_ATTEMPT #

    # 상세 로깅 (필요시 활성화)
    # logger.debug(f"Authenticated user: {current_user} (IP: {client_ip})")
    # logger.debug(f"--> Incoming Request to Proxy: {request.method} {request.url} HEADERS: {dict(request.headers)}")

    async with httpx.AsyncClient(timeout=settings.API_TIMEOUT_SECONDS) as client: #
        proxy_request_headers = {
            key: value for key, value in request.headers.items()
            if key.lower() not in ['host', 'authorization', 'user-agent'] # user-agent도 프록시에서 새로 설정 가능
        }
        proxy_request_headers['user-agent'] = f"DockerRegistryProxy/{settings.API_VERSION or '0.1.0'}" # 예시

        # logger.debug(f"--> Sending Request to Backend: {request.method} {target_url} HEADERS: {proxy_request_headers}")

        request_body_iterator = request.stream()

        try:
            upstream_response = await client.request( #
                method=request.method,
                url=target_url,
                headers=proxy_request_headers,
                params=request.query_params,
                content=request_body_iterator, #
                follow_redirects=False
            )

            # logger.debug(f"<-- Received Response from Backend: STATUS={upstream_response.status_code} HEADERS: {dict(upstream_response.headers)}")

            response_headers_to_client = {
                key: value for key, value in upstream_response.headers.items()
                if key.lower() not in ['content-encoding', 'transfer-encoding', 'connection', 'server']
            }
            # logger.debug(f"<-- Sending Response to Client: STATUS={upstream_response.status_code} HEADERS: {response_headers_to_client}")

            # 감사 로그 기록
            current_audit_action = audit_action_base
            log_status = "UNKNOWN"

            if audit_action_base: # 특정 작업으로 식별된 경우
                if upstream_response.is_success: # 2xx 응답 코드
                    log_status = "SUCCESS"
                    if audit_action_base == AuditAction.IMAGE_PULL_MANIFEST_ATTEMPT:
                        current_audit_action = AuditAction.IMAGE_PULL_MANIFEST
                    elif audit_action_base == AuditAction.IMAGE_PUSH_MANIFEST_ATTEMPT:
                        current_audit_action = AuditAction.IMAGE_PUSH_MANIFEST
                        # PUSH 성공 시 (PUT manifest)는 201 Created
                        if upstream_response.status_code == status.HTTP_201_CREATED:
                            manifest_digest_from_header = upstream_response.headers.get("Docker-Content-Digest") #
                            if manifest_digest_from_header:
                                audit_details["manifest_digest"] = manifest_digest_from_header
                    elif audit_action_base == AuditAction.IMAGE_MANIFEST_CHECK_ATTEMPT:
                        current_audit_action = AuditAction.IMAGE_MANIFEST_CHECK
                    # DELETE 성공은 여기서 별도 처리 안함 (202 Accepted 등)
                    # IMAGE_MANIFEST_DELETE_VIA_PROXY_ATTEMPT는 ATTEMPT 그대로 기록하거나 성공 시 별도 Action 정의

                    # PULL 성공 시 (GET manifest)는 200 OK
                    if request.method == "GET" and upstream_response.status_code == status.HTTP_200_OK:
                         manifest_digest_from_header = upstream_response.headers.get("Docker-Content-Digest")
                         if manifest_digest_from_header:
                             audit_details["manifest_digest"] = manifest_digest_from_header

                else: # 성공하지 않은 응답 (4xx, 5xx)
                    log_status = "FAILURE"
                    audit_details["reason"] = f"Backend responded with {upstream_response.status_code}"
                    audit_details["backend_status_code"] = upstream_response.status_code
                    # current_audit_action은 _ATTEMPT 그대로 유지

                await log_audit_event(AuditLogDBCreate(
                    username=current_user, action=current_audit_action, client_ip=client_ip,
                    resource_type=audit_resource_type, resource_name=audit_resource_name,
                    status=log_status, details=audit_details
                ))

            return StreamingResponse( #
                upstream_response.aiter_bytes(),
                status_code=upstream_response.status_code,
                headers=response_headers_to_client,
                media_type=upstream_response.headers.get("content-type")
            )

        except httpx.RequestError as exc:
            logger.error(f"Error proxying v2 request to {target_url} by user '{current_user}' (IP: {client_ip}): {exc}", exc_info=True)
            if audit_action_base:
                audit_details["reason"] = f"Network error or connection refused: {exc}"
                await log_audit_event(AuditLogDBCreate(
                    username=current_user, action=audit_action_base, client_ip=client_ip, # 실패 시 _ATTEMPT 사용
                    resource_type=audit_resource_type, resource_name=audit_resource_name,
                    status="FAILURE", details=audit_details
                ))
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Bad Gateway: Error connecting to upstream registry: {exc}")
        except Exception as e:
            logger.error(f"Unexpected error in proxy_v2_requests for {target_url} by user '{current_user}' (IP: {client_ip}): {e}", exc_info=True)
            if audit_action_base:
                audit_details["reason"] = f"Unexpected proxy error: {e}"
                await log_audit_event(AuditLogDBCreate(
                    username=current_user, action=audit_action_base, client_ip=client_ip, # 실패 시 _ATTEMPT 사용
                    resource_type=audit_resource_type, resource_name=audit_resource_name,
                    status="FAILURE", details=audit_details
                ))
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred in the proxy: {e}")