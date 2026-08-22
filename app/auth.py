"""Authentication & RBAC: bcrypt hashing + JWT (cookie & bearer) dependencies."""
import os
from datetime import datetime, timedelta

import bcrypt
from fastapi import Depends, HTTPException, Request
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from . import models, scoping
from .database import get_db

SECRET_KEY = os.environ.get("ASSURANCE_SECRET_KEY", "assurance-secret-key-change-me-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ASSURANCE_TOKEN_MINUTES", "720"))
COOKIE_NAME = "assurance_token"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(username: str, role: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=expires_minutes),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


def get_current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(models.User).filter(models.User.username == payload.get("sub")).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="This account is disabled")
    return user


def ui_user(request: Request, db: Session) -> models.User | None:
    """Non-raising variant used by server-rendered pages (redirects to login)."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    user = db.query(models.User).filter(models.User.username == payload.get("sub")).first()
    return user if (user and user.is_active) else None


# RBAC dependencies -----------------------------------------------------------
def require_read(user: models.User = Depends(get_current_user)) -> models.User:
    return user


def require_write(user: models.User = Depends(get_current_user)) -> models.User:
    """Write access to anything at all.

    Kept for the few endpoints that are not tied to one page. Page-scoped
    endpoints use module_write(...) instead, so a user can be allowed to
    validate retests without also being allowed to edit the SLA policy.
    """
    if not any(user.can_write(key) for key in models.MODULE_KEYS):
        raise HTTPException(status_code=403, detail="Write access required")
    return user


def require_admin(user: models.User = Depends(get_current_user)) -> models.User:
    if user.role != models.ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def module_read(module: str):
    """Dependency factory: the caller must be able to read this page."""
    def dependency(user: models.User = Depends(get_current_user)) -> models.User:
        if not user.can_read(module):
            raise HTTPException(status_code=403,
                                detail=f"No access to {module.replace('_', ' ')}")
        return user
    return dependency


def module_write(module: str):
    """Dependency factory: the caller must be able to change this page."""
    def dependency(user: models.User = Depends(get_current_user)) -> models.User:
        if not user.can_write(module):
            raise HTTPException(status_code=403,
                                detail=f"Write access to {module.replace('_', ' ')} is required")
        return user
    return dependency

# The view filter -------------------------------------------------------------
def available_scopes(db: Session) -> list:
    """Every business scope the inventory actually contains, in a stable order.

    Read from the data rather than hard-coded, so a new scope in a future
    inventory turns up in the header and in the user editor on its own. The
    unscoped bucket is deliberately not in this list - it is not a scope, it
    is the absence of one, and it carries its own grant.
    """
    seen = set()
    for (raw,) in db.query(models.Asset.scope).distinct().all():
        seen |= scoping.scope_tokens(raw)
    seen.discard(models.NO_ASSET_SCOPE)
    return sorted(seen)


def get_view(request: Request,
             user: models.User = Depends(get_current_user),
             db: Session = Depends(get_db)) -> scoping.ViewFilter:
    """The scope/assessment view for this request.

    The selection travels in a cookie so that every page and every chart is
    narrowed by the same value without each one having to remember to pass a
    parameter. Forging the cookie buys nothing: the selection is intersected
    with the account's grant before it is used, and a value outside the grant
    is discarded.
    """
    return scoping.ViewFilter(
        user,
        scope_choice=request.cookies.get(scoping.SCOPE_COOKIE, ""),
        source_choice=request.cookies.get(scoping.SOURCE_COOKIE, ""),
        available_scopes=available_scopes(db),
    )


def view_for(request: Request, user: models.User, db: Session) -> scoping.ViewFilter:
    """Same thing, for the server-rendered pages that resolve the user by hand."""
    return scoping.ViewFilter(
        user,
        scope_choice=request.cookies.get(scoping.SCOPE_COOKIE, ""),
        source_choice=request.cookies.get(scoping.SOURCE_COOKIE, ""),
        available_scopes=available_scopes(db),
    )


def write_reach(user: models.User = Depends(get_current_user)) -> scoping.WriteReach:
    return scoping.WriteReach(user)
