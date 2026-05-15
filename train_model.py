import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib

# LOAD DATASET
data = pd.read_csv("dataset.csv")

print(f"Dataset loaded: {len(data)} URLs")
print(f"Label distribution:\n{data['label'].value_counts()}")

# INPUT + OUTPUT
X = data["url"]
y = data["label"]

# CONVERT TEXT TO NUMBERS — character n-grams capture phishing patterns better
vectorizer = TfidfVectorizer(
    analyzer="char_wb",
    ngram_range=(3, 5),
    max_features=5000,
    sublinear_tf=True
)

X_vectorized = vectorizer.fit_transform(X)

# SPLIT DATA
X_train, X_test, y_train, y_test = train_test_split(
    X_vectorized,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# TRAIN — RandomForest outperforms LogisticRegression on URL pattern detection
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# EVALUATE
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print(f"\nModel Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
print("\nClassification Report:")
print(classification_report(y_test, predictions))

# SAVE MODEL
joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("\nAI Model Trained and Saved Successfully!")
