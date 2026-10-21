from fastapi import APIRouter, Cookie, HTTPException
from pydantic import BaseModel, Field
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import os

from services.unified_scan_service import run_unified_scan

router = APIRouter()
serializer = URLSafeTimedSerializer(os.environ.get("SECRET_KEY", "change-this-in-production"))


def _valid_session(token: str | None) -> bool:
    if not token:
        return False
    try:
        serializer.loads(token, max_age=86400)
        return True
    except (BadSignature, SignatureExpired):
        return False


class UnifiedScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


@router.post("/")
def unified_scan(
    request: UnifiedScanRequest,
    session: str | None = Cookie(default=None),
):
    if not _valid_session(session):
        raise HTTPException(status_code=401, detail="Your session has expired. Please log in again.")

    try:
        return run_unified_scan(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
