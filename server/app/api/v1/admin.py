"""Admin-only routes: org management, user management."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.api.deps import get_current_user, require_admin
from app.models import User, Org

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users")
def list_users(
 db: Session = Depends(get_db),
 admin: User = Depends(require_admin),
 org_id: str = Depends(get_current_user),
):
 users = db.query(User).filter(User.org_id == admin.org_id).all()
 return [{
 "id": u.id, "email": u.email, "name": u.name,
 "role": u.role, "active": u.active, "created_at": u.created_at.isoformat() if u.created_at else None,
 } for u in users]


@router.get("/org")
def get_org(
 db: Session = Depends(get_db),
 admin: User = Depends(require_admin),
):
 org = db.query(Org).filter(Org.id == admin.org_id).first()
 if not org:
 raise HTTPException(status_code=404, detail="Org not found")
 return {"id": org.id, "name": org.name}
