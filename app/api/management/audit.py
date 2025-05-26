# app/api/management/audit.py
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy import select, desc, and_ # SQLAlchemy의 select, desc, and_ 사용
from typing import List, Optional

from app.auth.security import get_current_admin_user
from app.db.database import engine, audit_log_table, log_audit_event # log_audit_event 추가
from app.models.audit import AuditLogDB, AuditLogDBCreate # DB 조회 결과용 Pydantic 모델 및 생성용
from app.models.audit_actions import AuditAction # 신규 임포트
# from app.core.config import settings # 설정 (필요시)

import logging

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get(
    "",
    response_model=List[AuditLogDB],
    summary="감사 로그 조회",
    description="지정된 조건(사용자, 이미지 이름, 액션)에 따라 감사 로그를 조회합니다.\n\n관리자만 접근 가능합니다."
)
async def get_audit_logs(
    request: Request,
    admin_user: str = Depends(get_current_admin_user),
    user: Optional[str] = Query(None, description="로그를 필터링할 사용자 이름."),
    image_name: Optional[str] = Query(None, alias="image", description="로그를 필터링할 이미지 이름 (부분 일치 가능)."),
    action: Optional[str] = Query(None, description="로그를 필터링할 작업 유형 (예: USER_LOGIN, IMAGE_PUSH_MANIFEST)."), # AuditAction Enum 값으로 필터링 가능
    limit: int = Query(100, ge=1, le=1000, description="반환할 최대 로그 수."),
    offset: int = Query(0, ge=0, description="결과를 건너뛸 오프셋 (페이지네이션용).")
):
    client_ip = request.client.host if request.client else "Unknown"
    log_filters = {"user": user, "image_name": image_name, "action": action, "limit": limit, "offset": offset}
    logger.info(f"Admin '{admin_user}' (IP: {client_ip}) requested audit logs with filters: {log_filters}")

    query = select(audit_log_table) #
    filter_conditions = []

    if user:
        filter_conditions.append(audit_log_table.c.username == user) #
    if image_name:
        filter_conditions.append(audit_log_table.c.resource_name.like(f"%{image_name}%")) #
    if action:
        filter_conditions.append(audit_log_table.c.action == action) #

    if filter_conditions:
        query = query.where(and_(*filter_conditions)) #

    query = query.order_by(desc(audit_log_table.c.timestamp)).limit(limit).offset(offset) #

    logs = []
    try:
        with engine.connect() as connection: #
            result_proxy = connection.execute(query)
            for row in result_proxy.mappings(): # .mappings()를 사용하면 딕셔너리처럼 접근 가능
                logs.append(AuditLogDB.model_validate(row)) # Pydantic v2: model_validate (이전: from_orm)

        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.AUDIT_LOG_VIEW, client_ip=client_ip,
            status="SUCCESS", details={"filters": log_filters, "returned_count": len(logs)}
        ))
        logger.info(f"Returning {len(logs)} audit log entries for admin '{admin_user}'.")
        return logs

    except Exception as e:
        logger.error(f"Error querying audit logs for admin '{admin_user}': {e}", exc_info=True)
        # 실패 시에도 감사 로그를 남길 수 있음
        await log_audit_event(AuditLogDBCreate(
            username=admin_user, action=AuditAction.AUDIT_LOG_VIEW_ATTEMPT, client_ip=client_ip,
            status="FAILURE", details={"filters": log_filters, "reason": str(e)}
        ))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="감사 로그를 조회하는 중 오류가 발생했습니다."
        )