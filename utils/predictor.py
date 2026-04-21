import joblib
import numpy as np
from utils.feature_extraction import extract_features

model = joblib.load("url_phishing_model.pkl")

def predict_url(url):
    features = np.array(extract_features(url)).reshape(1, -1)

    prob = model.predict_proba(features)[0][1]
    threat_score = int(prob * 100)

    if threat_score > 75:
        status = "Highly Malicious"
    elif threat_score > 50:
        status = "Suspicious"
    else:
        status = "Safe"

    return status, threat_score
