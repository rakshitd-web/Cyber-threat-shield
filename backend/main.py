from fastapi import FastAPI, Request, Form, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from utils.brand_check import check_brand_impersonation, KNOWN_BRANDS as KNOWN_BRANDS_MAP
from utils.url_features import extract_features, get_feature_reasons
import bcrypt
import os

from routers import fraud, vulnerability
from services.ml_model import predict
from database.db import init_db, create_user, get_user

app = FastAPI(title="CyberThreat Shield")

SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-in-production")
serializer = URLSafeTimedSerializer(SECRET_KEY)

init_db()

app.mount("/static", StaticFiles(directory="../frontend"), name="static")
templates = Jinja2Templates(directory="../frontend")

app.include_router(fraud.router, prefix="/fraud", tags=["Fraud Detection"])
app.include_router(vulnerability.router, prefix="/vuln", tags=["Vulnerability Scanner"])


def create_session(email: str):
    return serializer.dumps(email)


def verify_session(token: str):
    try:
        email = serializer.loads(token, max_age=86400)
        return email
    except (BadSignature, SignatureExpired):
        return None


@app.get("/", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html", {"error": None})


@app.post("/register")
def register(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    success = create_user(name, email, password)
    if not success:
        return templates.TemplateResponse(request, "register.html", {
            "error": "Email already registered. Please login."
        })
    return RedirectResponse(url="/", status_code=303)


@app.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...)
):
    user = get_user(email)
    if user and bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
        token = create_session(email)
        response = RedirectResponse(url="/home", status_code=303)
        response.set_cookie(key="session", value=token, httponly=True, samesite="lax")
        return response
    return templates.TemplateResponse(request, "login.html", {
        "error": "Invalid email or password."
    })


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("session")
    return response


@app.get("/home", response_class=HTMLResponse)
def home(request: Request, session: str = Cookie(default=None)):
    if not session or not verify_session(session):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "home.html")


@app.get("/scanner", response_class=HTMLResponse)
def scanner(request: Request, session: str = Cookie(default=None)):
    if not session or not verify_session(session):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "detection.html")


@app.post("/scan", response_class=HTMLResponse)
def scan(request: Request, url: str = Form(...), session: str = Cookie(default=None)):
    if not session or not verify_session(session):
        return RedirectResponse(url="/", status_code=303)
    try:
        is_impersonating, brand = check_brand_impersonation(url)

        features = extract_features(url)
        prediction, confidence = predict(features)
        result = "Phishing" if prediction == 1 else "Legitimate"

        warning = None
        if is_impersonating:
            result = "Phishing"
            confidence = max(confidence, 0.90)
            warning = f"Warning: This URL contains '{brand}' but is not the official {KNOWN_BRANDS_MAP.get(brand, brand)} domain."

        reasons = get_feature_reasons(url)

        if is_impersonating:
            reasons.insert(0, {
                "flag": "danger",
                "text": f"Domain impersonates '{brand}' — not the official {KNOWN_BRANDS_MAP.get(brand, brand)} domain"
            })

        return templates.TemplateResponse(request, "detection.html", {
            "url": url,
            "prediction": result,
            "confidence": round(float(confidence), 4),
            "warning": warning,
            "reasons": reasons
        })
    except ValueError as e:
        return templates.TemplateResponse(request, "detection.html", {
            "error": str(e)
        })


@app.get("/vuln", response_class=HTMLResponse)
def vuln_page(request: Request, session: str = Cookie(default=None)):
    if not session or not verify_session(session):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "vulnerability.html")