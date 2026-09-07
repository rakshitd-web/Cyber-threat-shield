from fastapi import APIRouter, Request, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import os

router = APIRouter()
templates = Jinja2Templates(directory="../frontend")

SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-in-production")
serializer = URLSafeTimedSerializer(SECRET_KEY)


def verify_session(token: str):
    try:
        return serializer.loads(token, max_age=86400)
    except (BadSignature, SignatureExpired):
        return None


@router.get("/", response_class=HTMLResponse)
def hardware_page(
    request: Request,
    session: str = Cookie(default=None)
):
    if not session or not verify_session(session):
        return RedirectResponse(url="/", status_code=303)

    return templates.TemplateResponse(
        request,
        "hardware.html"
    )


@router.post("/scan")
async def hardware_scan(
    request: Request,
    session: str = Cookie(default=None)
):
    """
    Receives hardware inventory collected by the local
    Windows hardware scanner.

    The scanner runs on the user's machine.
    This endpoint runs on Render.
    """

    if not session or not verify_session(session):
        return JSONResponse(
            status_code=401,
            content={
                "success": False,
                "error": "Unauthorized"
            }
        )

    try:
        payload = await request.json()

        if not isinstance(payload, dict):
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "error": "Invalid hardware data format"
                }
            )

        hardware = payload.get("hardware")

        if not isinstance(hardware, dict):
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "error": "Missing hardware data"
                }
            )

        return JSONResponse(
            content={
                "success": True,
                "hardware": hardware
            }
        )

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": str(e)
            }
        )