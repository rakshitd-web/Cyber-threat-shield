from fastapi import APIRouter, Request, Form, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from services.vuln_scanner import run_scan, generate_txt_report
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


ALL_CHECKS = ["headers", "ssl", "ports", "paths", "cookies", "server", "whois"]


@router.get("/", response_class=HTMLResponse)
def vuln_page(request: Request, session: str = Cookie(default=None)):
    if not session or not verify_session(session):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "vulnerability.html")


@router.post("/", response_class=HTMLResponse)
def vuln_scan(
    request: Request,
    url: str = Form(...),
    scan_all: str = Form(default=None),
    checks: list = Form(default=[]),
    session: str = Cookie(default=None)
):
    if not session or not verify_session(session):
        return RedirectResponse(url="/", status_code=303)

    selected_checks = ALL_CHECKS if scan_all == "true" else checks

    if not selected_checks:
        return templates.TemplateResponse(request, "vulnerability.html", {
            "error": "Please select at least one check or use Scan All."
        })

    try:
        scan_results = run_scan(url, selected_checks)
        report_text = generate_txt_report(url, scan_results)
        return templates.TemplateResponse(request, "vulnerability.html", {
            "url": url,
            "scan_results": scan_results,
            "report_text": report_text
        })
    except ValueError as e:
        return templates.TemplateResponse(request, "vulnerability.html", {
            "error": str(e)
        })


@router.post("/download", response_class=PlainTextResponse)
def download_report(
    url: str = Form(...),
    report_text: str = Form(...),
    session: str = Cookie(default=None)
):
    if not session or not verify_session(session):
        return RedirectResponse(url="/", status_code=303)
    return PlainTextResponse(
        content=report_text,
        headers={"Content-Disposition": f"attachment; filename=vuln_report.txt"}
    )