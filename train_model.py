import os
import pandas as pd
import numpy as np
import re
import tldextract
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from xgboost import XGBClassifier
import joblib
from tqdm import tqdm

# Fix pandas future warning
pd.set_option('future.no_silent_downcasting', True)

# -------------------------
# Locate dataset folder
# -------------------------

DATASET_FOLDER = "datasets"

def load_all_datasets(folder):

    dfs = []

    for file in os.listdir(folder):
        if file.endswith(".csv"):
            path = os.path.join(folder, file)
            print("Loading:", path)

            df = pd.read_csv(path)
            dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)
    return combined


# -------------------------
# Detect URL column automatically
# -------------------------

def detect_url_column(df):

    possible = ["url","URL","link","Link","domain","Domain"]

    for col in df.columns:
        if col in possible:
            return col

    for col in df.columns:
        if "url" in col.lower():
            return col

    raise Exception("URL column not found")


# -------------------------
# Detect label column automatically
# -------------------------

def detect_label_column(df):

    possible = ["label","Label","class","Class","result","Result","type"]

    for col in df.columns:
        if col in possible:
            return col

    raise Exception("Label column not found")


# -------------------------
# Feature extraction
# -------------------------

def extract_features(url):

    parsed = urlparse(url)
    ext = tldextract.extract(url)

    features = []

    # Length features
    features.append(len(url))
    features.append(len(parsed.netloc))
    features.append(len(parsed.path))
    features.append(len(parsed.query))

    # Character counts
    features.append(url.count('.'))
    features.append(url.count('-'))
    features.append(url.count('@'))
    features.append(url.count('?'))
    features.append(url.count('%'))
    features.append(url.count('='))
    features.append(url.count('/'))
    features.append(url.count('&'))
    features.append(url.count('_'))
    features.append(url.count('~'))

    # Digit count
    features.append(sum(c.isdigit() for c in url))

    # Subdomain length
    features.append(len(ext.subdomain))

    # Domain length
    features.append(len(ext.domain))

    # HTTPS
    features.append(1 if parsed.scheme == "https" else 0)

    # IP address in URL
    features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0)

    # Suspicious words
    suspicious_words = [
        "login","secure","account","update","bank","verify",
        "confirm","password","paypal","signin","wp","admin",
        "cmd","token","auth","access","validate"
    ]

    url_lower = url.lower()

    for word in suspicious_words:
        features.append(1 if word in url_lower else 0)

    # Special patterns
    features.append(1 if "//" in url[8:] else 0)
    features.append(1 if "-" in ext.domain else 0)
    features.append(1 if len(ext.subdomain.split(".")) > 2 else 0)

    return features


# -------------------------
# Load datasets
# -------------------------

df = load_all_datasets(DATASET_FOLDER)

print("Total rows:", len(df))

url_col = detect_url_column(df)
label_col = detect_label_column(df)

print("URL column:", url_col)
print("Label column:", label_col)

# Remove missing rows
df = df.dropna(subset=[url_col, label_col])

urls = df[url_col].astype(str)
labels = df[label_col]

# Normalize labels
labels = labels.replace({
    "legitimate":0,
    "benign":0,
    "safe":0,
    "good":0,
    "phishing":1,
    "malicious":1,
    "bad":1
})

# Remove unknown labels
mask = labels.notna()

urls = urls[mask]
labels = labels[mask]

y = labels.astype(int)

print("Valid rows:", len(urls))


# -------------------------
# Extract Features
# -------------------------

print("Extracting features...")

X = np.array([extract_features(u) for u in tqdm(urls)])

print("Feature shape:", X.shape)


# -------------------------
# Train Test Split
# -------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42
)


# -------------------------
# Train XGBoost Model
# -------------------------

print("Training model...")

model = XGBClassifier(
    n_estimators=300,
    max_depth=7,
    learning_rate=0.08,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss",
    tree_method="hist"
)

model.fit(X_train, y_train)


# -------------------------
# Evaluate
# -------------------------

pred = model.predict(X_test)

acc = accuracy_score(y_test, pred)

print("Accuracy:", acc)


# -------------------------
# Save model
# -------------------------

joblib.dump(model, "phishing_xgboost_model.pkl")

print("Model saved: phishing_xgboost_model.pkl")