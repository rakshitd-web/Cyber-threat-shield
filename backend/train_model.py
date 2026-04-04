import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Load dataset
df = pd.read_csv("PhishingData.csv")
df.columns = df.columns.str.strip()
df = df.drop(columns=["index"], errors="ignore")

# Fix corrupted column names
df = df.rename(columns={
    "having_IPhaving_IP_Address": "having_IP_Address",
    "URLURL_Length": "URL_Length"
})

# Convert labels: -1 = phishing → 1, 1 = legitimate → 0
df["Result"] = df["Result"].apply(lambda x: 1 if x == -1 else 0)

X = df.drop("Result", axis=1)
y = df["Result"]

# Save feature order
feature_columns = X.columns.tolist()
joblib.dump(feature_columns, "models/feature_order.pkl")

# Train
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

joblib.dump(model, "models/model.pkl")

print("Model trained successfully.")
print("Accuracy:", model.score(X_test, y_test))