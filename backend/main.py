from fastapi import FastAPI, Request, Form, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from utils.brand_check import check_brand_impersonation, KNOWN_BRANDS as KNOWN_BRANDS_MAP
from utils.url_features import extract_features, get_feature_reasons
from services.threat_intel import check_virustotal, check_domain_age, follow_redirects
from urllib.parse import urlparse
import tldextract
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

TRUSTED_BRANDS = {
    "google", "youtube", "amazon", "facebook", "instagram",
    "twitter", "x", "microsoft", "apple", "netflix", "github",
    "wikipedia", "linkedin", "reddit", "stackoverflow", "whatsapp",
    "telegram", "dropbox", "zoom", "slack", "spotify", "adobe",
    "paypal", "ebay", "yahoo", "bing", "twitch", "pinterest",
    "flipkart", "myntra", "zomato", "swiggy", "paytm", "naukri",
    "indiamart", "makemytrip", "irctc", "sbi", "hdfcbank", "icicibank",
    "axisbank", "kotak", "npci", "upi", "bhim"
}

TRUSTED_TLDS = ["edu", "gov", "ac", "edu.in", "ac.in", "gov.in", "edu.au", "ac.uk", "mil"]


def is_trusted_url(url: str) -> bool:
    try:
        ext = tldextract.extract(url)
        if ext.domain.lower() in TRUSTED_BRANDS:
            return True
        full_domain = ext.registered_domain.lower()
        if any(full_domain.endswith(t) for t in TRUSTED_TLDS):
            return True
    except:
        pass
    return False


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
        full_url = url if url.startswith("http") else "https://" + url
        parsed = urlparse(full_url)
        domain = parsed.netloc.lower()

        # Trusted brand/institution bypass
        if is_trusted_url(full_url):
            reasons = get_feature_reasons(full_url)
            return templates.TemplateResponse(request, "detection.html", {
                "url": url,
                "prediction": "Legitimate",
                "confidence": 0.99,
                "warning": None,
                "reasons": reasons
            })

        # --- Threat Intel Checks ---
        vt_result = check_virustotal(full_url)
        domain_age = check_domain_age(domain)
        redirect_result = follow_redirects(full_url)

        # Build extra reasons from threat intel
        threat_reasons = []

        # VirusTotal
        if vt_result.get("available") and vt_result.get("flagged"):
            threat_reasons.append({
                "flag": "danger",
                "text": f"VirusTotal: flagged by {vt_result['malicious']} engines as malicious, {vt_result['suspicious']} as suspicious (out of {vt_result['total']})"
            })
        elif vt_result.get("available") and not vt_result.get("flagged"):
            threat_reasons.append({
                "flag": "safe",
                "text": f"VirusTotal: not flagged by any engine (out of {vt_result.get('total', 0)})"
            })

        # Domain age
        if domain_age.get("available") and domain_age.get("is_new") and result == "Legitimate":
            confidence = max(confidence, 0.70)

        # Redirect chain
        if redirect_result.get("available"):
            if redirect_result.get("suspicious"):
                threat_reasons.append({
                    "flag": "danger",
                    "text": f"URL redirects to a different domain: {redirect_result['final_url']}"
                })
            elif redirect_result.get("redirected"):
                threat_reasons.append({
                    "flag": "warning",
                    "text": f"URL redirects {redirect_result['hops']} time(s) — final destination: {redirect_result['final_url']}"
                })

        # --- ML + Brand Check ---
        is_impersonating, brand = check_brand_impersonation(full_url)
        features = extract_features(full_url)
        prediction, confidence = predict(features)
        result = "Phishing" if prediction == 0 else "Legitimate"

        warning = None
        if is_impersonating:
            result = "Phishing"
            confidence = max(confidence, 0.90)
            warning = f"Warning: This URL contains '{brand}' but is not the official {KNOWN_BRANDS_MAP.get(brand, brand)} domain."

        # Force phishing if VT flagged it
        if vt_result.get("available") and vt_result.get("flagged"):
            result = "Phishing"
            confidence = max(confidence, 0.95)

        # Force phishing if domain is very new + other red flags
        if domain_age.get("available") and domain_age.get("is_new") and result == "Legitimate":
            confidence = max(confidence, 0.70)

        reasons = get_feature_reasons(full_url)

        if is_impersonating:
            reasons.insert(0, {
                "flag": "danger",
                "text": f"Domain impersonates '{brand}' — not the official {KNOWN_BRANDS_MAP.get(brand, brand)} domain"
            })

        # Prepend threat intel reasons
        reasons = threat_reasons + reasons

        # Count red flags
        red_flags = sum(1 for r in reasons if r["flag"] == "danger")
        path = parsed.path.lower()

        suspicious_paths = [
            ".php", "support", "login", "verify", "secure",
            "update", "account", "banking", "confirm", "signin"
        ]
        path_flags = sum(1 for p in suspicious_paths if p in path)

        if result == "Legitimate":
            if red_flags >= 3:
                result = "Phishing"
                confidence = max(confidence, 0.80)
                warning = (warning or "") + " Multiple risk factors detected by analysis."
            elif red_flags >= 2 and path_flags >= 1:
                result = "Phishing"
                confidence = max(confidence, 0.75)
                warning = (warning or "") + " Suspicious URL pattern combined with risk factors detected."

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