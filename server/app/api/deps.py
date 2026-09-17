"""Dependency injection for FastAPI routes."""
from __future__ import annotations

from fastapi import Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from app.db.session import get_db
from app.models import User
from app.config import settings

security = HTTPBearer()


def get_current_user(
 credentials: HTTPAuthorizationCredentials = Depends(security),
 db: Session = Depends(get_db),
) -> User:
 token = credentials.credentials
 try:
 payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
 user_id: str = payload.get("sub")
 org_id: str = payload.get("org_id")
 role: str = payload.get("role")
 token_version: int = payload.get("tv", 0)
 if not user_id or not org_id:
 raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
 except JWTError:
 raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

 user = db.query(User).filter(User.id == user_id, User.org_id == org_id).first()
 if not user:
 raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
 if user.token_version != token_version:
 raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")

 return user


def require_admin(current: User = Depends(get_current_user)) -> User:
 if current.role != "admin":
 raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin required")
 return current


def org_header(current: User = Depends(get_current_user)) -> str:
 return current.org_id
