"""Authentication and user account routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.api.deps import get_current_user
from app.models import User
from app.schemas.auth import RegisterRequest, LoginRequest, TokenResponse, UserOut
from app.services.accounts import register, login, create_tokens
from app.core.errors import ConflictError, NotFoundError

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse)
def register_endpoint(payload: RegisterRequest, db: Session = Depends(get_db)):
 try:
 org, user = register(db, payload.name, payload.email, payload.password, payload.org_name)
 return create_tokens(user)
 except ConflictError as e:
 raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post("/login", response_model=TokenResponse)
def login_endpoint(payload: LoginRequest, db: Session = Depends(get_db)):
 try:
 user = login(db, payload.email, payload.password)
 return create_tokens(user)
 except NotFoundError:
 raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


@router.get("/me", response_model=UserOut)
def me(current: User = Depends(get_current_user)):
 return UserOut(
 id=current.id,
 email=current.email,
 name=current.name,
 role=current.role,
 org_id=current.org_id,
 created_at=current.created_at,
 )


@router.patch("/me", response_model=UserOut)
def update_me(
 name: str | None = None,
 password: str | None = None,
 db: Session = Depends(get_db),
 current: User = Depends(get_current_user),
):
 from app.services.accounts import update_profile
 user = update_profile(db, current, name=name, password=password)
 return UserOut(
 id=user.id,
 email=user.email,
 name=user.name,
 role=user.role,
 org_id=user.org_id,
 created_at=user.created_at,
 )
