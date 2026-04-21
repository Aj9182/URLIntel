# URLIntel - AI Security Scanner

URLIntel is an AI-powered security dashboard that analyzes URLs for phishing, malware, and other threats. It leverages a combination of Machine Learning (XGBoost) and external intelligence APIs to provide a comprehensive threat score and detailed analysis for any given URL.

## Features

- **Machine Learning Analysis**: Uses a trained XGBoost model to predict phishing probabilities based on extracted URL features.
- **External Threat Intelligence**:
  - VirusTotal API integration
  - Google Safe Browsing API integration
- **Deep URL Inspection**:
  - SSL Certificate validation and expiry check
  - WHOIS Domain Information retrieval
  - IP Address Geolocation and ISP information
  - Subdomain anomaly detection and redirect analysis
  - Homograph attack detection
- **Admin & User Dashboards**: Built with Flask, featuring secure login systems, scan history, and role-based access control.
- **Data Export**: Admins can download scan histories in CSV or PDF formats.
- **Database Backend**: Uses PostgreSQL for robust data storage.

## Tech Stack

- **Backend**: Python, Flask
- **Database**: PostgreSQL
- **Machine Learning**: XGBoost, Scikit-Learn
- **APIs**: VirusTotal API, Google Safe Browsing API, IP-API
- **Frontend**: HTML, CSS, JavaScript

## Installation

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd urlintel
   ```

2. **Set up a virtual environment (optional but recommended):**
   ```bash
   python -m venv .virtual
   # On Windows use: .virtual\Scripts\activate
   # On Mac/Linux use: source .virtual/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Variables:**
   Rename `.env.example` to `.env` and fill in your API keys and database credentials:
   ```env
   FLASK_SECRET_KEY=your_secret_key
   DATABASE_URL=postgresql://user:password@localhost:5432/dbname
   VIRUSTOTAL_API_KEY=your_virustotal_key
   GOOGLE_SAFE_BROWSING_KEY=your_google_safe_browsing_key
   ```

5. **Initialize the Database:**
   The database tables (`scans` and `users`) are automatically created upon the first run of the application. A default admin user is created with:
   - **Username**: `admin`
   - **Password**: `admin123`
   
   *(Remember to change this default password in a production environment!)*

6. **Run the application:**
   ```bash
   python app.py
   ```
   Alternatively, you can run it via Flask:
   ```bash
   flask run
   ```
   The application will be available locally on `http://127.0.0.1:5000/`.

## Author

- **AKASH.A**

## License

This project is open-source and available for educational purposes only.

