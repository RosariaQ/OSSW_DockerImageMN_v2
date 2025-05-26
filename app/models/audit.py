# app/models/audit.py
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any

# AuditAction Enum을 여기서 직접 참조하기보다는,
# 로그 생성 시점에서 AuditAction 값을 문자열로 변환하여 사용합니다.
# from .audit_actions import AuditAction # 필요한 경우

class AuditLogEntry(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Timestamp of the event (UTC)") #
    username: Optional[str] = Field(None, description="Authenticated username, if available") #
    action: str = Field(..., description="Type of action performed (e.g., USER_LOGIN, IMAGE_PUSH)") #
    # action: AuditAction = Field(..., description="Type of action performed") # Enum 직접 사용도 가능
    client_ip: Optional[str] = Field(None, description="Client IP address, if available") #
    resource_type: Optional[str] = Field(None, description="Type of the resource affected (e.g., user, image, tag)") #
    resource_name: Optional[str] = Field(None, description="Name or identifier of the resource affected") #
    status: str = Field(..., description="Status of the action (e.g., SUCCESS, FAILURE)") #
    details: Optional[Dict[str, Any]] = Field(None, description="Additional details about the event") #

# 데이터베이스 저장을 위한 모델 (ID 포함)
class AuditLogDBCreate(AuditLogEntry): #
    pass # AuditLogEntry와 동일한 필드, DB 저장 시 사용

class AuditLogDB(AuditLogEntry): #
    id: int = Field(..., description="Unique ID of the audit log entry") #

    class Config:
        from_attributes = True # Pydantic v2 (이전 버전에서는 orm_mode = True)