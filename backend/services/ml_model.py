import joblib
import numpy as np
import pandas as pd

model = joblib.load("models/model.pkl")
feature_order = joblib.load("models/feature_order.pkl")

def predict(features):

    # convert list → dataframe with correct column names
    X = pd.DataFrame([features], columns=feature_order)

    prediction = model.predict(X)[0]

    if hasattr(model, "predict_proba"):
        confidence = max(model.predict_proba(X)[0])
    else:
        confidence = 0.5

    return prediction, confidence