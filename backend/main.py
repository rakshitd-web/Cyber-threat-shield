from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from routers import fraud
from services.ml_model import predict
from utils.url_features import extract_features


app = FastAPI(title="Phishing Detection System")


# ------------------------------------------------
# Static files
# ------------------------------------------------

app.mount("/static", StaticFiles(directory="../frontend"), name="static")

# ------------------------------------------------
# Templates
# ------------------------------------------------

templates = Jinja2Templates(directory="../frontend")


# ------------------------------------------------
# Routers
# ------------------------------------------------

app.include_router(fraud.router, prefix="/fraud", tags=["Fraud Detection"])


# ------------------------------------------------
# Temporary user storage
# ------------------------------------------------

users = {}


# ------------------------------------------------
# Login page
# ------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {"request": request}
    )


# ------------------------------------------------
# Register page
# ------------------------------------------------

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(
        "register.html",
        {"request": request}
    )


# ------------------------------------------------
# Register user
# ------------------------------------------------

@app.post("/register")
def register(
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):

    users[email] = {
        "name": name,
        "password": password
    }

    return RedirectResponse(
        url="/",
        status_code=303
    )


# ------------------------------------------------
# Login authentication
# ------------------------------------------------

@app.post("/login")
def login(
    email: str = Form(...),
    password: str = Form(...)
):

    if email in users and users[email]["password"] == password:
        return RedirectResponse(
            url="/home",
            status_code=303
        )

    return RedirectResponse(
        url="/",
        status_code=303
    )


# ------------------------------------------------
# Home page
# ------------------------------------------------

@app.get("/home", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        "home.html",
        {"request": request}
    )


# ------------------------------------------------
# Scanner page
# ------------------------------------------------

@app.get("/scanner", response_class=HTMLResponse)
def scanner(request: Request):
    return templates.TemplateResponse(
        "detection.html",
        {"request": request}
    )


# ------------------------------------------------
# URL Scan
# ------------------------------------------------

@app.post("/scan", response_class=HTMLResponse)
def scan(
    request: Request,
    url: str = Form(...)
):

    try:

        features = extract_features(url)
        prediction, confidence = predict(features)

        result = "Phishing" if prediction == 1 else "Legitimate"

        return templates.TemplateResponse(
            "detection.html",
            {
                "request": request,
                "url": url,
                "prediction": result,
                "confidence": round(float(confidence), 4)
            }
        )

    except ValueError as e:

        return templates.TemplateResponse(
            "detection.html",
            {
                "request": request,
                "error": str(e)
            }
        )