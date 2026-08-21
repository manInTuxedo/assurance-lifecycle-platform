"""Pydantic request/response schemas for the Assurance platform."""
from datetime import date
from typing import List, Optional

from pydantic import BaseModel, Field


class LoginIn(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str
    password: str = Field(min_length=4)
    role: str = "read_only"


class AssignOwnerIn(BaseModel):
    owner: str


class RetestResultIn(BaseModel):
    result: str  # passed | failed


class ExceptionIn(BaseModel):
    reason: str = "Risk Accepted"
    expires_at: Optional[date] = None


class LinkRiskIn(BaseModel):
    risk_id: str


class StatusIn(BaseModel):
    status: str


class SLARuleIn(BaseModel):
    priority_order: Optional[int] = None
    source: str = "Any"
    severity: str = "Any"
    asset_scope: str = "Any"
    asset_type: str = "Any"
    environment: str = "Any"
    sla_days: int = 90
    approaching_pct: int = 70
    retest_pct: int = 80
    is_active: bool = True


class SLARuleUpdate(BaseModel):
    priority_order: Optional[int] = None
    source: Optional[str] = None
    severity: Optional[str] = None
    asset_scope: Optional[str] = None
    asset_type: Optional[str] = None
    environment: Optional[str] = None
    sla_days: Optional[int] = None
    approaching_pct: Optional[int] = None
    retest_pct: Optional[int] = None
    is_active: Optional[bool] = None


class SimulateIn(BaseModel):
    source: str = "VA"
    severity: str = "Critical"
    asset_scope: str = "Infrastructure"
    asset_type: str = "Server"
    environment: str = "Production"


class ReorderIn(BaseModel):
    ids: List[int]
