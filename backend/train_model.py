import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

df = pd.read_csv("PhishingData.csv")

# Drop non-feature columns
drop_cols = ["FILENAME", "URL", "Domain", "TLD", "Title", "label"]
X = df.drop(columns=[c for c in drop_cols if c in df.columns])
y = df["label"]

print("Features:", X.columns.tolist())
print("Label counts:", y.value_counts().to_dict())

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(
    n_estimators=100,
    max_features="sqrt",
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

joblib.dump(model, "models/model.pkl")
joblib.dump(X.columns.tolist(), "models/feature_order.pkl")

print("Accuracy:", model.score(X_test, y_test))
print("Model saved.")