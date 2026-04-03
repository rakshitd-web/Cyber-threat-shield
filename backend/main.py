from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from routers import fraud
from services.ml_model import predict
from utils.url_features import extract_features
from database.db import init_db, create_user, get_user


app = FastAPI(title="Phishing Detection System")

init_db()

app.mount("/static", StaticFiles(directory="../frontend"), name="static")
templates = Jinja2Templates(directory="../frontend")

app.include_router(fraud.router, prefix="/fraud", tags=["Fraud Detection"])

@app.get("/", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html")


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html")


@app.post("/register")
def register(
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    create_user(name, email, password)
    return RedirectResponse(url="/", status_code=303)


@app.post("/login")
def login(
    email: str = Form(...),
    password: str = Form(...)
):
    user = get_user(email)
    if user and user["password"] == password:
        return RedirectResponse(url="/home", status_code=303)
    return RedirectResponse(url="/", status_code=303)


@app.get("/home", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "home.html")


@app.get("/scanner", response_class=HTMLResponse)
def scanner(request: Request):
    return templates.TemplateResponse(request, "detection.html")


@app.post("/scan", response_class=HTMLResponse)
def scan(request: Request, url: str = Form(...)):
    try:
        features = extract_features(url)
        prediction, confidence = predict(features)
        result = "Phishing" if prediction == 1 else "Legitimate"
        return templates.TemplateResponse(request, "detection.html", {
            "url": url,
            "prediction": result,
            "confidence": round(float(confidence), 4)
        })
    except ValueError as e:
        return templates.TemplateResponse(request, "detection.html", {
            "error": str(e)
        })
