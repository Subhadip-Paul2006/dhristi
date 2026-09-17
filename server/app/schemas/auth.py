# Drishti v0.1 — auth request/response schemas | 11-Jul-2026
from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    org_name: str = Field(min_length=1, max_length=200)


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: str
    name: str | None
    email: str
    role: str


class OrgOut(BaseModel):
    id: str
    name: str
    slug: str


class RegisterOut(TokenPair):
    user: UserOut
    org: OrgOut


class MeOut(BaseModel):
    id: str
    name: str | None = None
    email: str
    role: str
    org_id: str
    org_name: str
    org_slug: str | None = None


class MePatch(BaseModel):
    """Update profile name and/or change password (requires current_password)."""

    name: str | None = Field(default=None, min_length=1, max_length=120)
    current_password: str | None = None
    new_password: str | None = Field(default=None, min_length=8, max_length=128)


class OrgInfoOut(BaseModel):
    id: str
    name: str
    slug: str
    asset_count: int
    open_findings: int
    path_count: int
    member_count: int


class MemberOut(BaseModel):
    id: str
    name: str | None
    email: str
    role: str


class AgentTokenOut(BaseModel):
    """Plaintext agent token — shown once; only the hash is stored."""

    agent_key: str
    token: str
    org_slug: str
