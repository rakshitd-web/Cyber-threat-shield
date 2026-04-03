import pandas as pd
import joblib
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split


seed = random.randint(0, 100000)
# Load dataset
df = pd.read_csv("PhishingData.csv")
df.columns = df.columns.str.strip()
df = df.drop(columns=["index"], errors="ignore")

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

model = RandomForestClassifier()
model.fit(X_train, y_train)

joblib.dump(model, "models/model.pkl")

print("Model trained successfully.")
print("Accuracy:", model.score(X_test, y_test))