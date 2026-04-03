from fastapi import APIRouter
from pydantic import BaseModel
from utils.url_features import extract_features
from services.ml_model import predict

router = APIRouter()

class URLRequest(BaseModel):
    url: str


@router.post("/")
def detect_fraud(request: URLRequest):

    try:
        features = extract_features(request.url)

        prediction, confidence = predict(features)

        if prediction == 1:
            result = "Legitimate"
        else:
            result = "Phishing"

        return {
            "url": request.url,
            "prediction": result,
            "confidence": round(float(confidence), 4)
        }

    except Exception as e:
        return {
            "error": str(e)
        }