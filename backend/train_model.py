import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import os

os.makedirs("models", exist_ok=True)

df = pd.read_csv("CustomPhishingDataset.csv")

X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    max_features="sqrt",
    min_samples_leaf=5,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

joblib.dump(model, "models/model.pkl")
joblib.dump(X.columns.tolist(), "models/feature_order.pkl")

print("Accuracy:", model.score(X_test, y_test))
print()
print(classification_report(y_test, model.predict(X_test)))
print("Model saved.")