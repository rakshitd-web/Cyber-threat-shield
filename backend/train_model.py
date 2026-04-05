import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

df = pd.read_csv("PhishingData.csv")

# Only use URL-based features we can reliably extract live
# Drop page-content features that require fetching the page perfectly
url_only_features = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLegitimateProb",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
    "CharContinuationRate",
    "URLCharProb",
]

X = df[url_only_features]
y = df["label"]

print("Features used:", X.columns.tolist())
print("Label counts:", y.value_counts().to_dict())

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    max_features="sqrt",
    min_samples_leaf=10,
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