from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional, List
from enum import Enum


# ============ Enums ============
class RoleEnum(str, Enum):
    admin = "admin"
    viewer = "viewer"


class LogTypeEnum(str, Enum):
    sudo = "sudo"
    auth = "auth"
    audit = "audit"


class StatusEnum(str, Enum):
    ingested = "ingested"
    parsed = "parsed"
    analyzed = "analyzed"
    error = "error"


class SeverityEnum(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


# ============ User Schemas ============
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=255)
    email: EmailStr
    password: str = Field(..., min_length=6)


class UserLogin(BaseModel):
    username: str = Field(..., min_length=3)
    password: str = Field(..., min_length=6)


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: RoleEnum
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class UserInDB(UserResponse):
    hashed_password: str


# ============ Session Schemas ============
class SessionCreate(BaseModel):
    user_id: int
    session_token: str
    expires_at: datetime


class SessionResponse(BaseModel):
    id: int
    user_id: int
    session_token: str
    expires_at: datetime
    created_at: datetime
    
    class Config:
        from_attributes = True


# ============ Evidence Schemas ============
class EvidenceUpload(BaseModel):
    log_type: LogTypeEnum


class EvidenceResponse(BaseModel):
    id: int
    filename: str
    log_type: LogTypeEnum
    file_size: Optional[int]
    status: StatusEnum
    sha256_hash: str
    created_at: datetime
    parsed_at: Optional[datetime]
    analyzed_at: Optional[datetime]
    error_message: Optional[str]
    
    class Config:
        from_attributes = True


class EvidenceDetail(EvidenceResponse):
    upload_user_id: int
    original_path: Optional[str]
    stored_path: str


# ============ Parsed Log Schemas ============
class ParsedLogCreate(BaseModel):
    evidence_id: int
    chunk_number: Optional[int]
    timestamp: Optional[datetime]
    hostname: Optional[str]
    service: Optional[str]
    pid: Optional[int]
    raw_log: Optional[str]
    parsed_user: Optional[str]
    parsed_action: Optional[str]
    parsed_target: Optional[str]


class ParsedLogResponse(BaseModel):
    id: int
    evidence_id: int
    chunk_number: Optional[int]
    timestamp: Optional[datetime]
    hostname: Optional[str]
    service: Optional[str]
    pid: Optional[int]
    parsed_user: Optional[str]
    parsed_action: Optional[str]
    parsed_target: Optional[str]
    raw_log: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True


# ============ Analysis Result Schemas ============
class AnalysisResultCreate(BaseModel):
    evidence_id: int
    parsed_log_id: Optional[int]
    severity: SeverityEnum
    threat_type: Optional[str]
    threat_description: Optional[str]
    indicators: Optional[str]  # JSON string
    ai_explanation: Optional[str]
    confidence_score: Optional[float]


class AnalysisResultResponse(BaseModel):
    id: int
    evidence_id: int
    parsed_log_id: Optional[int]
    severity: SeverityEnum
    threat_type: Optional[str]
    threat_description: Optional[str]
    indicators: Optional[str]
    ai_explanation: Optional[str]
    confidence_score: Optional[float]
    created_at: datetime
    
    class Config:
        from_attributes = True


# ============ Dashboard Schemas ============
class DashboardOverview(BaseModel):
    total_evidences: int
    total_critical_threats: int
    total_high_threats: int
    total_medium_threats: int
    total_low_threats: int
    

class SeverityDistribution(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


# ============ Auth Response ============
class AuthToken(BaseModel):
    token: str
    user: UserResponse


class AuthMessage(BaseModel):
    message: str
