from flask import Flask, render_template, request, session
import psycopg2
import psycopg2.extras
import joblib
import re
import ssl
import whois
import socket
import requests
from flask import send_file, make_response
import csv
import io
from fpdf import FPDF  # pip install fpdf
from urllib.parse import urlparse, urlunparse
from flask import session, redirect, url_for
from datetime import datetime
import os
from dotenv import load_dotenv

from utils.feature_extraction import extract_features

# Load environment variables
load_dotenv()

def get_db_connection():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise ValueError("DATABASE_URL environment variable is not set")
    return psycopg2.connect(db_url)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback_secret")   # required for session

model = joblib.load("phishing_xgboost_model.pkl")

# ===============================
# DATABASE
# ===============================
def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            url TEXT,
            result TEXT,
            threat_score INTEGER,
            is_manual INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()

init_db()

# ===============================
# USERS DATABASE
# ===============================
def init_users_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    # Add default admin if not exists
    c.execute("""
        INSERT INTO users (username, password, role) 
        VALUES (%s, %s, %s)
        ON CONFLICT (username) DO NOTHING
    """, ("admin", "admin123", "admin"))
    conn.commit()
    conn.close()

init_users_db()
# ===============================
# TRUSTED BANKING DOMAINS
# ===============================
TRUSTED_DOMAINS = [
    "https://www.canarabank.bank.in",
    "https://sbi.co.in",
    "https://onlinesbi.sbi.bank.in/",
    "https://icicibank.com",
    "https://hdfcbank.com",
    "https://axisbank.com",
    "https://kotak.com",
    "https://pnbindia.in",
    "https://google.com"
]

# ===============================
# VERIFIED PHISHING URLS
# ===============================
PHISH_DOMAINS = [
    "raiodesolbrilhante1.com.br",
    "malicious-example.com",
    "https://joxoh.life/onlinebanking.libertyfcu",
    "https://raiodesolbrilhante1.com.br/plala/jpn/webmai1/index.php",
    "https://kleinanzeigen.mx51088081.com/receive/9653421"
]
# ===============================
# NORMALIZE URL
# ===============================
def normalize_url(url):

    url = url.strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urlparse(url)

    scheme = parsed.scheme  # 👈 keep original http/https
    netloc = parsed.netloc.lower().replace("www.", "")
    path = parsed.path.rstrip("/")

    return urlunparse((scheme, netloc, path, "", "", ""))

# ===============================
# VIRUSTOTAL CHECK
# ===============================

def check_virustotal(url):
    API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

    headers = {"x-apikey": API_KEY}

    try:
        r = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        analysis_id = r.json()["data"]["id"]

        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )

        return report.json()["data"]["attributes"]["stats"]

    except:
        return None
    
# ===============================
# GOOGLE SAFE BROWSING CHECK
# ===============================

def check_google_safe(url):
    API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")

    body = {
        "client": {"clientId": "url-intel", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}",
            json=body
        )

        return "matches" in r.json()

    except:
        return False

# ===============================
# SSL CERTIFICATE CHECK
# ===============================
def check_ssl(domain):

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return True

    except:
        return False

def get_ssl_info(hostname):
    context = ssl.create_default_context()
    
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            
            # Get binary cert for fingerprint
            cert_bin = ssock.getpeercert(binary_form=True)

            # Get readable cert
            cert = ssock.getpeercert()

            import hashlib
            sha256 = hashlib.sha256(cert_bin).hexdigest()

    return {
        "issuer": dict(x[0] for x in cert['issuer']),
        "issued_on": cert['notBefore'],
        "expires_on": cert['notAfter'],
        "fingerprint": sha256
    }

def format_date(date_str):
    return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").strftime("%b %d, %Y")

def check_ssl_risk(cert):
    expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
    
    if expiry_date < datetime.now():
        return "❌ Certificate Expired"
    
    return "✅ SSL connection is secure"

# ===============================
# WHOIS INFO
# =============================== 

def get_whois_info(domain):
    try:
        w = whois.whois(domain)

        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiry_date": str(w.expiration_date)
        }

    except:
        return {
            "domain": domain,
            "registrar": "Unknown",
            "creation_date": "Unknown",
            "expiry_date": "Unknown"
        }
    
# ===============================
# GET IP ADDRESS
# ===============================
def get_ip_address(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]

        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None


# ===============================
# GET IP INFO (LOCATION + ISP)
# ===============================
def get_ip_info(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = res.json()

        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp")
        }
    except:
        return {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown"
        }
    
# ===============================
# EXTRACT SUBDOMAIN INFO
# ===============================

def extract_subdomain_info(url):
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()

    parts = hostname.split(".")

    if len(parts) > 2:
        subdomain = ".".join(parts[:-2])
        main_domain = ".".join(parts[-2:])
    else:
        subdomain = ""
        main_domain = hostname

    return subdomain, main_domain


# ===============================
# HOMOGRAPH ATTACK CHECK
# ===============================

def detect_homograph(domain):

    suspicious_patterns = [
        ("0", "o"),
        ("1", "l"),
        ("@", "a"),
        ("$", "s"),
        ("rn", "m")
    ]

    for fake, real in suspicious_patterns:
        if fake in domain:
            return True

    return False

# ===============================
# REDIRECT ANALYSIS
# ===============================
def redirect_analysis(url):

    redirect_count = 0
    domain_changed = False

    try:
        response = requests.get(url, timeout=5, allow_redirects=True)

        redirect_count = len(response.history)

        original_domain = urlparse(url).netloc
        final_domain = urlparse(response.url).netloc

        if original_domain != final_domain:
            domain_changed = True

    except:
        pass

    return redirect_count, domain_changed

# ===============================
# SIMPLE AI-LIKE URL ANALYSIS
# ===============================
def analyze_url(url):

    score = 0

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # SSL Check
    if not check_ssl(domain):
        score += 30

    # HTTPS check
    if not url.startswith("https://"):
        score += 20

    # Long URL
    if len(url) > 75:
        score += 15

    # IP address in domain
    if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
        score += 25

    # Suspicious keywords
    suspicious_words = [
        "login", "verify", "update", "secure",
        "account", "banking", "confirm",
        "password", "otp", "signin"
    ]

    for word in suspicious_words:
        if word in url.lower():
            score += 10

    # Too many dots
    if domain.count(".") > 3:
        score += 15

    
    # Phishing domains check
    for phish in PHISH_DOMAINS:
        if phish in domain:
            score = 100
            break   # immediately return
        
    # Extract subdomain
    subdomain, main_domain = extract_subdomain_info(url)

    # Suspicious: too many subdomains
    if subdomain.count(".") >= 2:
        score += 20

    # Suspicious keywords in subdomain
    for word in ["login", "secure", "bank", "verify"]:
        if word in subdomain:
            score += 15

    # Limit score
    if score > 100:
        score = 100

    # Result classification
    if score < 30:
        result = "Safe Website"
    elif score < 70:
        result = "Suspicious Website"
    else:
        result = "Phishing Website"

    return result, score


# ===============================
# ROUTES
# ===============================

@app.route("/")
def landing():
    return render_template("index.html")

# ===============================
# SCAN URL
# ===============================
@app.route("/scan", methods=["POST"])
def scan():

    user_url = request.form["url"]
    user_url = normalize_url(user_url)

    # 🔥 CHECK IF URL ALREADY LABELED BY ADMIN
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
    SELECT result, threat_score 
    FROM scans 
    WHERE url=%s AND is_manual=1
    ORDER BY id DESC
    """, (user_url,))

    existing = c.fetchone()
    manual_result = None
    manual_score = None
    if existing:
        manual_result, manual_score = existing

    result, threat_score = analyze_url(user_url)
    features = extract_features(user_url)
    ml_prediction = model.predict([features])[0]

    if ml_prediction == 1:
        threat_score += 40

    for trusted in TRUSTED_DOMAINS:
        if trusted in user_url:
            threat_score = 0
            result = "Safe Website"

    redirect_count, domain_changed = redirect_analysis(user_url)
    subdomain, main_domain = extract_subdomain_info(user_url)
    whois_data = get_whois_info(main_domain)
    vt_result = check_virustotal(user_url)
    google_flag = check_google_safe(user_url)
    ip_address = get_ip_address(user_url)
    
    # ===============================
    # IP ANALYSIS
    # ===============================
    if ip_address:
        ip_info = get_ip_info(ip_address)
    else:
        ip_info = {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown"
        }
    # ===============================
    # EXTERNAL API RISK
    # ===============================

    if vt_result:
        if vt_result["malicious"] > 0:
            threat_score += 40
        elif vt_result["suspicious"] > 0:
            threat_score += 20

    if google_flag:
        threat_score += 50
    
    # ===============================
    # FINAL RESULT CALCULATION
    # ===============================

    if manual_result:
        result = manual_result
        threat_score = manual_score
    else:
        if threat_score > 100:
            threat_score = 100

        if threat_score >= 70:
            result = "Phishing Website"
        elif threat_score >= 30:
            result = "Suspicious Website"
        else:
            result = "Safe Website"

    # ===============================
    # SSL INFO
    # ===============================
    parsed = urlparse(user_url)
    domain = parsed.netloc

    try:
        ssl_data = get_ssl_info(domain)

        ssl_issuer = ssl_data["issuer"].get("organizationName", "Unknown")
        ssl_issued = format_date(ssl_data["issued_on"])
        ssl_expiry = format_date(ssl_data["expires_on"])
        ssl_fingerprint = ssl_data["fingerprint"]

        expiry_date = datetime.strptime(ssl_data["expires_on"], "%b %d %H:%M:%S %Y %Z")

        if expiry_date < datetime.now():
            ssl_status = "❌ Certificate Expired"
        else:
            ssl_status = "✅ SSL connection is secure"

    except:
        ssl_issuer = "Unknown"
        ssl_issued = "N/A"
        ssl_expiry = "N/A"
        ssl_status = "⚠ Unable to fetch SSL info"
        ssl_fingerprint = "N/A"

    # ===============================
    # REDIRECT RISK
    # ===============================
    if redirect_count > 3 or domain_changed:
        threat_score += 20

        if threat_score > 100:
            threat_score = 100

        if threat_score >= 70:
            result = "Phishing Website"
        else:
            result = "Suspicious Website"

    # ===============================
    # SAVE DB
    # ==============================
    conn = get_db_connection()
    c = conn.cursor()

    c.execute(
        "INSERT INTO scans (url, result, threat_score) VALUES (%s, %s, %s)",
        (user_url, result, threat_score)
    )

    conn.commit()
    conn.close()

    # ===============================
    # RETURN 
    # ===============================
    return render_template(
        "result.html",
        url=user_url,
        result=result,
        threat_score=threat_score,
        redirect_count=redirect_count,
        domain_changed=domain_changed,
        subdomain=subdomain,
        main_domain=main_domain,
        whois=whois_data,
        ip_address=ip_address,
        ip_info=ip_info,
        
        # SSL DATA
        domain=domain,
        ssl_issuer=ssl_issuer,
        ssl_issued=ssl_issued,
        ssl_expiry=ssl_expiry,
        ssl_status=ssl_status,
        ssl_fingerprint=ssl_fingerprint
    )

# ===============================
# LOGIN PANEL
# ===============================
@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    password = request.form['password']
    confirm = request.form['confirm']

    if password != confirm:
        return render_template("login.html", error="Passwords do not match", show_signup=True)

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                  (username, password, "user"))
        conn.commit()
        return render_template("login.html", show_signup=False, success="Sign up successful! Please login.")
    except psycopg2.IntegrityError:
        return render_template("login.html", error="Username already exists", show_signup=True)
    finally:
        conn.close()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT role FROM users WHERE username=%s AND password=%s", (username, password))
        result = c.fetchone()
        conn.close()

        if result:
            role = result[0]
            session["username"] = username
            session["role"] = role

            if role == "admin":
                return redirect(url_for("admin"))
            else:
                return redirect(url_for("home"))

        else:
            return render_template("login.html", error="Invalid Username or Password", show_signup=False)

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("username", None)
    session.pop("role", None)
    return redirect(url_for("home"))

# ===============================
# HISTORY PANEL
# ===============================
@app.route("/history")
def history():

    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM scans ORDER BY id DESC")

    scans = c.fetchall()

    conn.close()

    return render_template("history.html", scans=scans)

# ===============================
# ADMIN PANEL
# ===============================

@app.route("/admin")
def admin():
    if session.get("role") != "admin":  # must be admin
        return redirect(url_for("login"))

    # existing admin code
    conn = get_db_connection()
    c = conn.cursor()
    # get scans and stats
    c.execute("SELECT * FROM scans ORDER BY id DESC")
    scans = c.fetchall()
    c.execute("SELECT COUNT(*) FROM scans")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scans WHERE result='Safe Website'")
    safe = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scans WHERE result='Suspicious Website'")
    suspicious = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scans WHERE result='Phishing Website'")
    phishing = c.fetchone()[0]
    conn.close()

    return render_template("admin.html",
        scans=scans,
        total=total,
        safe=safe,
        suspicious=suspicious,
        phishing=phishing
    )
@app.route("/")
@app.route("/home")
def home():
    if session.get("role") not in ["user", "admin"]:
        return redirect(url_for("login"))
    return render_template("index.html")

@app.route("/mark", methods=["POST"])
def mark():

    scan_id = request.form["id"]
    label = request.form["label"]

    conn = get_db_connection()
    c = conn.cursor()

    # set score based on label
    if label == "Safe Website":
        score = 10
    elif label == "Suspicious Website":
        score = 50
    else:  # Phishing Website
        score = 90

    c.execute("""
    UPDATE scans 
    SET result=%s, threat_score=%s, is_manual=1 
    WHERE id=%s
    """, (label, score, scan_id))

    conn.commit()
    conn.close()
    return redirect(url_for("admin"))

# ===============================
# DOWNLOAD SCANS AS CSV / PDF
# ===============================
@app.route("/download/csv")
def download_csv():
    # Fetch latest scans from database
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, url, result FROM scans ORDER BY id DESC")
    scans = c.fetchall()
    conn.close()

    # Create in-memory CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "URL", "Status"])
    for scan in scans:
        writer.writerow(scan)

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=scans.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route("/download/pdf")
def download_pdf():
    import io
    from fpdf import FPDF
    from flask import send_file

    # Fetch scans from database
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, url, result FROM scans ORDER BY id DESC")
    scans = c.fetchall()
    conn.close()

    # Create PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Table header
    pdf.cell(10, 10, "ID", 1)
    pdf.cell(100, 10, "URL", 1)
    pdf.cell(40, 10, "Status", 1)
    pdf.ln()

    # Table rows
    for scan in scans:
        pdf.cell(10, 10, str(scan[0]), 1)
        pdf.cell(100, 10, scan[1], 1)
        pdf.cell(40, 10, scan[2], 1)
        pdf.ln()

    # Convert PDF to bytes
    pdf_bytes = pdf.output(dest="S").encode("latin1")

    return send_file(
        io.BytesIO(pdf_bytes),
        download_name="scans.pdf",
        as_attachment=True,
        mimetype="application/pdf"
    )

# ===============================
# RUN SERVER
# ===============================
if __name__ == "__main__":
    app.run(debug=True)