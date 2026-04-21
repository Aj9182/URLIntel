import re
import tldextract
from urllib.parse import urlparse

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