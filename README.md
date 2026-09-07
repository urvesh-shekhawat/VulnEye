# 🛡️ VulnEye — Enterprise Web Vulnerability & SOC Intelligence Platform

[![Vercel Deployment](https://img.shields.io/badge/Deployed%20on-Vercel-black?logo=vercel&logoColor=white)](https://vercel.com)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)](https://python.org)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.x-red?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![OAuth 2.0](https://img.shields.io/badge/Auth-Google%20OAuth-4285F4?logo=google&logoColor=white)](https://console.cloud.google.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Bilingual: EN / HI](https://img.shields.io/badge/Language-English%20%7C%20Hindi%20Bilingual-00f0ff.svg)](#-bilingual-support)

**VulnEye** is a commercial-grade, modern Web Security Scanner, AI Threat Explainer, and SOC Command Center designed for developers, penetration testers, and security startups. It delivers automated non-intrusive security audits, real-time threat explanations in **English & Hindi**, continuous domain monitoring, and corporate-grade executive PDF reporting.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Enterprise Feature Suite](#-enterprise-feature-suite)
- [Live Modules & Architecture](#-live-modules--architecture)
- [Technology Stack](#-technology-stack)
- [Project Directory Structure](#-project-directory-structure)
- [Local Installation & Setup](#-local-installation--setup)
- [Google Cloud OAuth Configuration](#-google-cloud-oauth-configuration)
- [Production Cloud Deployment (Vercel / Render)](#-production-cloud-deployment)
- [API Reference](#-api-reference)
- [Disclaimer & License](#-disclaimer--license)

---

## 🎯 Overview

VulnEye bridges the gap between raw automated scanning and actionable remediation. It allows security analysts and startup teams to audit the perimeter defense of web assets without launching dangerous intrusive attacks. Every vulnerability identified comes with dual-language educational breakdowns, risk scoring, and verified server configuration snippets (Nginx, Apache, Express, Django).

---

## ✨ Enterprise Feature Suite

### 1. 🔍 Multi-Vector Security Scanner
* **SSL/TLS & Cryptography Audit:** Certificate validity, chain verification, cipher deprecation, and HTTPS redirection enforcement.
* **HTTP Security Headers:** Checks for missing `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, `Permissions-Policy`, and `Referrer-Policy`.
* **Public Port & Service Discovery:** Rapid asynchronous probing of common exposed ports (21, 22, 25, 53, 80, 110, 443, 1433, 3306, 5432, 6379, 8080).
* **Sensitive Directory & File Discovery:** Non-intrusive probing for common exposed administrative panels, backup files, and config endpoints (`/admin`, `/.env`, `/.git`, `/config.json`, `/backup.sql`).
* **CORS & Cookie Security:** Verifies `Access-Control-Allow-Origin` wildcards and audits `Secure`, `HttpOnly`, and `SameSite` flags on session cookies.
* **Tech Stack Detection:** Identifies web servers, frontend frameworks, CDNs, and backend libraries from response headers and DOM signatures.

### 2. 🤖 AI Security Report Explainer (`/analyzer`)
* **Bilingual English & Hindi Mode:** Users can toggle between **English** and **Hindi (हिंग्लिश / हिंदी)** for in-depth vulnerability explanations.
* **Interactive JSON/URL Report Import:** Paste raw scan results or enter any domain to receive an instant executive summary, impact breakdown, and step-by-step remediation guide.
* **Selective UI Language Switching:** Explanations dynamically translate without modifying website navigation chrome.

### 3. 📖 Security Handbook & Knowledgebase (`/guide`)
* Comprehensive interactive glossary covering all major web security vectors (SSL/TLS, Missing Headers, Open Ports, Sensitive Files, CORS, Forms).
* Provides direct remediation snippets for **Nginx**, **Apache**, **Node.js (Helmet)**, and **Python (Django/Flask)**.
* Includes one-click bilingual language switching (English / Hindi).

### 4. 💳 Full Working Checkout & Payment Window (`/checkout`, `/pricing`, `/invoice/<id>`)
* **4 Live Payment Gateways:** Supports Credit/Debit Cards, UPI & Dynamic QR Code, PayPal, and Cryptocurrency (BTC, ETH, USDT).
* **Simulated 256-Bit Cryptographic Authorization:** Interactive radar sweep progress loader with live transaction approval.
* **Instant Plan Upgrades:** Real-time database update for **Pro Enterprise** and **SOC Custom** membership tiers.
* **Printable PDF Invoices:** Auto-generates official receipts at `/invoice/<transaction_id>` with transaction IDs, itemized breakdowns, and browser print triggers.

### 5. 📊 Executive SOC Command Center (`/dashboard`)
* Real-time threat posture overview with interactive **ApexCharts** risk distribution donut charts.
* Quick metrics: Total Domains Audited, Critical Risk Targets, Active Telemetry, and Clearance Status.
* Searchable live scan logs with one-click PDF export and direct re-scan actions.

### 6. 👁️ Continuous Target Watchlist (`/monitoring`)
* Add target domains to an automated security watchlist.
* Tracks risk drift, uptime reachability, and baseline security grade shifts over time.

### 7. ⚔️ Side-by-Side Target Compare (`/compare`)
* Compare the security posture of two different domains side-by-side.
* Ideal for auditing **Staging vs Production** or benchmarking against competitor infrastructures.

### 8. 🧰 Free Cyber Tools Suite (`/tools`)
* **Subdomain Enumerator:** Passive discovery of public DNS subdomains.
* **SSL Certificate Inspector:** Real-time certificate expiry, issuer, and SAN inspection.
* **Security Headers Checker:** Instant header compliance grade report.
* **Password Strength & Entropy Analyzer:** High-security password validation engine.

### 9. 🔊 Sci-Fi Cyber Sound Synthesizer (Web Audio API)
* Built-in browser oscillator generating real-time high-tech sound effects (button clicks, hover shimmer, theme sweeps, scan sonar pings, modal apertures, and success chords).
* Zero external MP3 dependencies with instant **`🔊 SFX On / 🔇 SFX Off`** navbar toggle and visual HUD toast.

### 10. 👤 Clean Avatar-Only Navbar & Rich Profile Modal
* Ultra-compact navigation bar displaying a circular glowing profile avatar with an active online status dot.
* One-click dropdown modal displaying user profile details, email, subscription badge, security clearance, quick navigation links, and secure sign-out.

---

## 🛠️ Technology Stack

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Backend Framework** | **Python 3.12+ / Flask 3.x** | High-speed serverless routing, OAuth2 authentication, and REST APIs |
| **Security Scanning Engine** | **Socket, Requests, BeautifulSoup4** | Multi-threaded port probing, header analysis, SSL inspection |
| **Report Generation** | **ReportLab 4.x** | High-resolution corporate PDF dossiers with custom styling and severity pills |
| **Authentication** | **Authlib / Google OpenID Connect** | Secure OAuth 2.0 user login and session handling |
| **Database** | **SQLite 3 / SQLAlchemy** | Self-healing schema with serverless `/tmp/scans.db` automatic fallback |
| **Frontend UI/UX** | **Vanilla HTML5, Modern CSS3, ES6 JavaScript** | Glassmorphism, CSS keyframes, dark/light theme, ApexCharts |
| **Audio Engine** | **Web Audio API** | Dynamic real-time sound frequency synthesis |

---

## 📂 Project Directory Structure

```text
VulnEye/
├── api/                             # Main Application Source Folder
│   ├── index.py                     # Flask App & Serverless Entry Handler
│   ├── static/                      # Static Assets
│   │   ├── style.css                # Global Glassmorphism & Cyber Theme
│   │   └── cyber-effects.js         # Particle Canvas & Web Audio SFX Synthesizer
│   └── templates/                   # Jinja2 HTML5 Templates
│       ├── analyzer.html            # AI Security Report Explainer (EN/HI)
│       ├── checkout.html            # Working Multi-Gateway Payment Window
│       ├── compare.html             # Side-by-Side Target Audit Comparator
│       ├── dashboard.html           # Executive SOC Command Center
│       ├── docs.html                # REST API Documentation
│       ├── guide.html               # Security Handbook & Knowledgebase (EN/HI)
│       ├── history.html             # Historical Scan Logs Dashboard
│       ├── index.html               # Scan Launchpad
│       ├── invoice.html             # Printable Official Billing Receipt
│       ├── landing.html             # High-Conversion Public Showcase Page
│       ├── login.html               # Google OAuth & Demo Login UI
│       ├── monitoring.html          # Domain Target Watchlist
│       ├── pricing.html             # Membership Tiers & Plan Modals
│       ├── result.html              # Vulnerability Report Dashboard
│       ├── scan_progress.html       # Real-Time SSE Audit Terminal
│       ├── settings.html            # API Keys & Active Subscription View
│       └── tools/                   # Free Cyber Utilities
│           ├── headers_checker.html # Security Headers Analyzer
│           ├── password_analyzer.html# Password Entropy Calculator
│           ├── ssl_checker.html     # SSL/TLS Certificate Inspector
│           ├── subdomains.html      # Subdomain Discovery Tool
│           └── tools_index.html     # Cyber Suite Hub
├── app.py                           # Local Development Server Runner
├── database.py                      # Database Models (Scans, Subscriptions, Invoices)
├── scanner.py                       # Security Auditing Logic & Algorithms
├── requirements.txt                 # Python Dependencies
├── vercel.json                      # Vercel Serverless Routing Config
├── render.yaml                      # Render Web Service Deployment Spec
├── .env.example                     # Environment Variable Template
└── README.md                        # Documentation & Project Guide
```

---

## 🚀 Local Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/urvesh-shekhawat/VulnEye.git
cd VulnEye
```

### 2. Create Virtual Environment & Install Dependencies
```bash
# Create venv
python -m venv venv

# Activate on Windows:
.\venv\Scripts\activate

# Activate on macOS/Linux:
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Edit `.env` with your parameters:
```env
SECRET_KEY="your-super-secret-key-change-this"
GOOGLE_CLIENT_ID="your-google-client-id.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="your-google-client-secret"
```

### 4. Start the Application
```bash
python app.py
```
Open **`http://localhost:5000`** in your browser.

---

## 🔐 Google Cloud OAuth Configuration

To enable Google Sign-In:

1. Open the **[Google Cloud Console Credentials Page](https://console.cloud.google.com/apis/credentials)**.
2. Create or select a project and configure the **OAuth Consent Screen**.
3. Go to **Credentials** ➔ **Create Credentials** ➔ **OAuth Client ID** (Web Application).
4. Configure Authorized URIs:
   - **Authorized JavaScript Origins:**
     - Local: `http://localhost:5000`
     - Production: `https://your-domain.vercel.app`
   - **Authorized Redirect URIs:**
     - Local: `http://localhost:5000/authorize`
     - Production: `https://your-domain.vercel.app/authorize`
5. Copy your **Client ID** and **Client Secret** into your `.env` or cloud dashboard.

---

## 🌌 Production Cloud Deployment

### Deploying to Vercel (Serverless)

VulnEye is pre-configured with `vercel.json` for zero-configuration serverless deployments:

1. Push your repository to GitHub.
2. In the **[Vercel Dashboard](https://vercel.com)**, click **Add New** ➔ **Project** ➔ **Import VulnEye**.
3. Under **Environment Variables**, add:
   - `SECRET_KEY` = `[Random Secure String]`
   - `GOOGLE_CLIENT_ID` = `[Your Google Client ID]`
   - `GOOGLE_CLIENT_SECRET` = `[Your Google Client Secret]`
4. Click **Deploy**.

---

## 📡 API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/scan?url=target.com` | Conducts security audit and returns JSON assessment |
| `POST` | `/api/checkout/process` | Processes simulated subscription upgrade & generates receipt |
| `GET` | `/invoice/<transaction_id>` | Returns printable transaction invoice |
| `POST` | `/api/tools/ssl` | Inspects target SSL certificate details |
| `POST` | `/api/tools/headers` | Analyzes HTTP security headers |
| `POST` | `/api/tools/subdomains` | Discovers public subdomains |
| `POST` | `/api/tools/password` | Evaluates password strength and entropy |

---

## 📜 Disclaimer & License

### ⚠️ Legal Disclaimer
VulnEye is developed strictly for authorized cybersecurity testing, educational research, and defense auditing. Unauthorized scanning against targets without prior written consent is strictly prohibited. The creators assume no liability for misuse.

### 📄 License
This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <sub>Built with ❤️ for the Cybersecurity & SecOps Community</sub>
</div>
