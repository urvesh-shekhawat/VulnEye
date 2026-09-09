# 🛡️ VulnEye — Enterprise Web Vulnerability & SOC Intelligence Platform

<div align="center">

[![Vercel Deployment](https://img.shields.io/badge/Deployed%20on-Vercel-black?logo=vercel&logoColor=white)](https://vercel.com)
[![Python Version](https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.x-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/ORM-SQLAlchemy%20%7C%20SQLite%20%7C%20PostgreSQL-336791?logo=postgresql&logoColor=white)](https://www.sqlalchemy.org/)
[![OAuth 2.0](https://img.shields.io/badge/Auth-Google%20OAuth%202.0-4285F4?logo=google&logoColor=white)](https://console.cloud.google.com/)
[![PDF Engine](https://img.shields.io/badge/Reports-ReportLab%204.x-FF6F00?logo=adobeacrobatreader&logoColor=white)](https://www.reportlab.com/)
[![Bilingual](https://img.shields.io/badge/Language-English%20%7C%20Hindi%20(हिंग्लिश)-00f0ff.svg)](#-ai-bilingual-threat-explainer)
[![License: MIT](https://img.shields.io/badge/License-MIT-059669.svg)](LICENSE)

<p align="center">
  <b>Commercial-grade Web Security Scanner, Real-Time SSE Audit Terminal, AI Bilingual Threat Explainer, and SOC Command Center.</b>
</p>

[Key Features](#-key-features) •
[Architecture](#-system-architecture) •
[Quick Start](#-local-installation--quick-start) •
[REST API & Webhooks](#-rest-api--webhooks) •
[Cloud Deployment](#-production-cloud-deployment) •
[Security Badges](#-dynamic-svg-security-badges)

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [System Architecture](#-system-architecture)
- [Key Features](#-key-features)
  - [1. Multi-Vector Perimeter Security Scanner](#1--multi-vector-perimeter-security-scanner)
  - [2. Real-Time SSE Audit Terminal](#2--real-time-sse-audit-terminal)
  - [3. AI Bilingual Threat Explainer & Fix Generator](#3--ai-bilingual-threat-explainer--fix-generator)
  - [4. Executive SOC Command Center & Metrics](#4--executive-soc-command-center--metrics)
  - [5. Continuous 24/7 Target Watchlist](#5--continuous-247-target-watchlist)
  - [6. Side-by-Side Target Audit Comparator](#6--side-by-side-target-audit-comparator)
  - [7. Cyber Defense Utilities Suite](#7--cyber-defense-utilities-suite)
  - [8. Real-Time SIEM Webhook Alerts (Discord / Slack)](#8--real-time-siem-webhook-alerts-discord--slack)
  - [9. Dynamic SVG Security Grade Badges](#9--dynamic-svg-security-grade-badges)
  - [10. Commercial SaaS Tiering & Multi-Gateway Checkout](#10--commercial-saas-tiering--multi-gateway-checkout)
  - [11. Corporate-Grade PDF Dossiers & JSON Export](#11--corporate-grade-pdf-dossiers--json-export)
  - [12. Zero-Dependency Web Audio SFX Synthesizer](#12--zero-dependency-web-audio-sfx-synthesizer)
- [Technology Stack](#-technology-stack)
- [Directory Structure](#-directory-structure)
- [Local Installation & Quick Start](#-local-installation--quick-start)
- [Google OAuth 2.0 Setup](#-google-oauth-20-setup)
- [Database Configuration](#-database-configuration)
- [REST API & Webhooks Reference](#-rest-api--webhooks-reference)
- [Dynamic SVG Security Badges](#-dynamic-svg-security-badges)
- [Production Cloud Deployment](#-production-cloud-deployment)
  - [Deploy to Vercel (Serverless)](#deploy-to-vercel-serverless)
  - [Deploy to Render / Docker](#deploy-to-render--docker)
- [Disclaimer & License](#-disclaimer--license)

---

## 🎯 Overview

**VulnEye** is an enterprise-grade cybersecurity scanning and threat intelligence platform designed for security engineers, DevOps specialists, and penetration testers. It provides non-intrusive perimeter audits that detect critical exposures—such as missing OWASP security headers, public database ports, unencrypted transport, sensitive dotfile leaks (`.env`, `.git`), and misconfigured CORS policies—without launching hazardous or destructive payloads.

VulnEye pairs automated scanning with an **AI Threat Explainer** delivering actionable, dual-language (**English** & **Hindi / हिंग्लिश**) remediation guides, complete with production-ready configuration snippets for **Nginx**, **Apache**, **Node.js (Helmet)**, and **Linux UFW**.

---

## 🏛️ System Architecture

```mermaid
flowchart TB
    subgraph ClientLayer ["Client & Security Analyst Layer"]
        UI["Modern Cyber UI (Glassmorphism & SFX)"]
        SSE_UI["SSE Real-Time Audit Terminal"]
        DevAPI["CI/CD Pipelines & Developer API Clients"]
        Badges["GitHub README Dynamic Badges"]
    end

    subgraph AppLayer ["VulnEye Core Engine (Flask 3.x)"]
        Router["WSGI Router & Serverless Middleware"]
        Auth["Authlib OAuth 2.0 & Guest Session Handler"]
        SSE_Stream["Server-Sent Events (SSE) Telemetry"]
        
        subgraph ScannerModule ["Multi-Vector Security Engine"]
            DNS["SSRF Guard & DNS Resolver"]
            SSL_TLS["TLS/SSL & Cert Chain Inspector"]
            Headers["OWASP Security Header Auditor"]
            PortScanner["Parallel TCP Port & Service Sweeper"]
            Dotfiles["Sensitive Files & Dotfile Discovery"]
            CORS_Cookie["CORS & Session Cookie Auditor"]
            TechFingerprint["Tech Stack & Form Analyzer"]
            RiskCalc["Weighted Risk Scoring Engine"]
        end
        
        Explainer["AI Bilingual Threat & Fix Generator (EN/HI)"]
        PDFGen["ReportLab 4.x PDF Dossier Compiler"]
        BadgeGen["Dynamic SVG Vector Badge Engine"]
        WebhookDisp["Webhook Dispatcher (Discord / Slack / Custom)"]
    end

    subgraph StorageLayer ["Persistence Layer"]
        SQLA["SQLAlchemy ORM"]
        DB[("SQLite 3 / PostgreSQL")]
    end

    UI --> Router
    SSE_UI --> SSE_Stream
    DevAPI --> Router
    Badges --> BadgeGen

    Router --> Auth
    Router --> ScannerModule
    Router --> Explainer
    Router --> PDFGen
    Router --> WebhookDisp

    ScannerModule --> RiskCalc
    RiskCalc --> StorageLayer
    SQLA --> DB
```

---

## ✨ Key Features

### 1. 🔍 Multi-Vector Perimeter Security Scanner
* **TLS/SSL Cryptography:** Inspects certificate issuer, SANs, signature algorithm, expiration countdown, protocol versions, and HTTPS redirect enforcement.
* **OWASP Defense Headers:** Checks for `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, `Permissions-Policy`, and `Referrer-Policy`.
* **Public Port & Service Reconnaissance:** Rapid multi-threaded TCP sweep across critical database and management ports (`21`, `22`, `25`, `53`, `80`, `110`, `443`, `1433`, `3306`, `5432`, `6379`, `8080`, `27017`).
* **Sensitive File & Dotfile Exposure:** Identifies public leaks of `/.env`, `/.git`, `/.gitignore`, `/config.json`, `/backup.sql`, `/wp-config.php`, `/id_rsa`, `/docker-compose.yml`, and common admin portals.
* **CORS & Session Cookies:** Identifies wildcard (`*`) access controls and audits `Secure`, `HttpOnly`, and `SameSite` flags.
* **Technology Fingerprinting:** Detects underlying web servers, backend languages, CDN providers, frontend frameworks, and interactive form input vectors.
* **SSRF Protection:** Built-in validation blocks scans targeted at localhost (`127.0.0.1`), loopback, link-local, and internal private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

### 2. ⚡ Real-Time SSE Audit Terminal
* Streams live telemetry directly to the frontend via **Server-Sent Events (`/scan/stream`)**.
* Visual HUD terminal with radar sweep animations, sonar ping acoustics, and granular stage-by-stage status feedback.

### 3. 🤖 AI Bilingual Threat Explainer & Fix Generator (`/analyzer`)
* **Dual-Language Modes:** Instant toggle between **English** and **Hindi (हिंग्लिश / हिंदी)** for executive summaries, hacker exploit vectors, and plain-language vulnerability impact.
* **Automated Remediation Generator:** Synthesizes custom, drop-in **Nginx server blocks** and **Linux UFW firewall commands** tailored to the scan's exact missing headers and open ports.

### 4. 📊 Executive SOC Command Center & Metrics (`/dashboard`)
* Visual threat landscape with **ApexCharts** interactive risk distribution charts.
* Real-time metrics: Total Audits Executed, Critical Risk Assets, Active Watchlist Telemetry, and Clearance Status.
* Searchable scan history with quick re-scan actions, one-click PDF dossiers, and deletion controls.

### 5. 👁️ Continuous 24/7 Target Watchlist (`/monitoring`)
* Register critical domains for ongoing security monitoring.
* Tracks risk drift, reachability changes, and security grade fluctuations across daily or weekly schedules.

### 6. ⚔️ Side-by-Side Target Audit Comparator (`/compare`)
* Cross-compare security posture, missing headers, and open ports between two targets or historical snapshots.
* Ideal for verifying **Staging vs. Production** parity or benchmarking competitor infrastructures.

### 7. 🧰 Cyber Defense Utilities Suite (`/tools`)
* **CVSS v3.1 Calculator (`/tools/cvss`):** Interactive vulnerability score calculator computing Base, Temporal, and Environmental metrics with CVSS vector string generation.
* **SSL Certificate Inspector (`/tools/ssl`):** Detailed breakdown of SSL chains, validity period, and issuer authorities.
* **Security Headers Checker (`/tools/headers`):** Instant OWASP compliance grade card.
* **Subdomain Enumerator (`/tools/subdomains`):** Passive reconnaissance of public DNS subdomains.
* **Password Strength & Entropy Analyzer (`/tools/password`):** Cryptographic entropy calculator with crack-time estimations.

### 8. 🔔 Real-Time SIEM Webhook Alerts (Discord / Slack)
* Dispatches instant JSON alerts to **Discord** or **Slack** incoming webhooks when High or Critical risks are discovered.
* Built-in test dispatcher and configurable severity filters accessible under `/settings`.

### 9. 🏷️ Dynamic SVG Security Grade Badges (`/api/v1/badge`, `/badge/<domain>`)
* Real-time, embeddable vector badges showing security grades (`Grade A+ Secure`, `Grade B Warning`, `Grade F Critical`) for project READMEs and status dashboards.

### 10. 💳 Commercial SaaS Tiering & Multi-Gateway Checkout (`/checkout`, `/pricing`)
* 3 Membership Tiers: **Community Scout (Free)**, **Pro SecOps ($49/mo)**, and **Enterprise Sentinel ($199/mo)**.
* 4 Working Checkout Gateways: Credit/Debit Cards, UPI & Dynamic QR Codes, PayPal, and Cryptocurrency (BTC, ETH, USDT).
* Auto-generated printable corporate invoices available at `/invoice/<transaction_id>`.

### 11. 📄 Corporate-Grade PDF Dossiers & JSON Export (`/export-pdf`, `/export/json`)
* High-resolution multi-page PDF reports engineered with **ReportLab 4.x**, featuring compliance badges, severity tables, and executive roadmap summaries.

### 12. 🔊 Zero-Dependency Web Audio SFX Synthesizer
* Native HTML5 Web Audio API sound synthesizer producing cyberpunk interface soundscapes without external audio asset downloads.
* Global toggle (`SFX On` / `SFX Off`) with persistent localStorage preferences.

---

## 🛠️ Technology Stack

| Domain | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend Core** | Python 3.9+ / Flask 3.x | Routing, Serverless WSGI compatibility, API endpoints |
| **Security Scanner** | `socket`, `requests`, `BeautifulSoup4` | Multi-threaded port probing, header analysis, SSL inspection |
| **Report Generation** | `ReportLab 4.x` | Enterprise-grade styled PDF audit dossiers |
| **Authentication** | `Authlib` / Google OpenID Connect | OAuth 2.0 Single Sign-On and session management |
| **Database & ORM** | `SQLAlchemy` (SQLite 3 / PostgreSQL) | Persistent storage with serverless `/tmp/scans.db` fallback |
| **Frontend UI/UX** | HTML5, Modern Vanilla CSS3, ES6 JavaScript | Glassmorphism styling, ApexCharts, SSE client |
| **Audio Engine** | Web Audio API | Real-time frequency-synthesized acoustic feedback |
| **Deployment** | Vercel (Serverless) / Render / Gunicorn | Cloud-native multi-platform deployment targets |

---

## 📂 Directory Structure

```text
VulnEye/
├── api/                             # Main Application Package
│   ├── index.py                     # Flask Core, Routes, SSE Streaming & WSGI Handler
│   ├── static/                      # Static Assets & Styling
│   │   ├── style.css                # Global Glassmorphism Cyber Theme
│   │   └── cyber-effects.js         # Particle Canvas & Web Audio Synthesizer
│   └── templates/                   # Jinja2 HTML Templates
│       ├── 404.html                 # Cyberpunk 404 Error View
│       ├── 500.html                 # Internal Server Error View
│       ├── analyzer.html            # AI Bilingual Threat Explainer (EN/HI)
│       ├── checkout.html            # Multi-Gateway Payment Checkout
│       ├── compare.html             # Side-by-Side Target Audit Comparator
│       ├── dashboard.html           # Executive SOC Command Center
│       ├── docs.html                # REST API & Integration Documentation
│       ├── guide.html               # Security Knowledgebase & Handbook (EN/HI)
│       ├── history.html             # Historical Audit Logs
│       ├── index.html               # Security Audit Launchpad
│       ├── invoice.html             # Official Billing Receipt
│       ├── landing.html             # Showcase Landing Page
│       ├── login.html               # Google OAuth & Demo Sign-In
│       ├── monitoring.html          # 24/7 Asset Watchlist
│       ├── pricing.html             # Membership Tiers & Plan Showcase
│       ├── result.html              # Vulnerability Report Dashboard
│       ├── scan_progress.html       # Real-Time SSE Audit Terminal
│       ├── settings.html            # API Keys, Webhooks & Subscription Settings
│       └── tools/                   # Cyber Utilities Hub
│           ├── cvss_calculator.html # CVSS v3.1 Interactive Calculator
│           ├── headers_checker.html # Security Headers Analyzer
│           ├── password_analyzer.html# Password Entropy Calculator
│           ├── ssl_checker.html     # SSL/TLS Certificate Inspector
│           ├── subdomains.html      # Subdomain Discovery Tool
│           └── tools_index.html     # Cyber Suite Overview Hub
├── app.py                           # Local Development Server Runner
├── database.py                      # SQLAlchemy Models, Migrations & Helpers
├── scanner.py                       # Security Scanning Engine & Algorithms
├── requirements.txt                 # Python Dependencies
├── vercel.json                      # Vercel Serverless Routing Config
├── render.yaml                      # Render Web Service Deployment Spec
├── .env.example                     # Environment Variable Template
├── .gitignore                       # Git Exclusion Patterns
└── README.md                        # Documentation & Project Guide
```

---

## 🚀 Local Installation & Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/urvesh-shekhawat/VulnEye.git
cd VulnEye
```

### 2. Set Up Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate on Windows:
.\venv\Scripts\activate

# Activate on macOS / Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create your `.env` file from the provided template:
```bash
cp .env.example .env
```
Edit `.env` with your settings:
```env
# Flask Session Key
SECRET_KEY="your-secure-random-secret-key"

# Optional: Google OAuth 2.0 Credentials (if unset, Guest/Demo mode is available)
GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="your-client-secret"

# Optional: PostgreSQL Database URL (defaults to SQLite: scans.db)
DATABASE_URL="sqlite:///scans.db"
```

### 5. Launch the Application
```bash
python app.py
```
Open **`http://localhost:5000`** in your browser.

> [!TIP]
> You can instantly explore the full platform without configuring Google OAuth by clicking **"Guest / Demo Analyst Mode"** on the login screen.

---

## 🔐 Google OAuth 2.0 Setup

To enable Google Sign-In:

1. Navigate to the **[Google Cloud Console Credentials Page](https://console.cloud.google.com/apis/credentials)**.
2. Create or select a project and configure the **OAuth Consent Screen** (User Type: *External*).
3. Create an **OAuth Client ID** of type **Web Application**.
4. Configure Authorized URIs:
   - **Authorized JavaScript Origins:**
     - Local: `http://localhost:5000`
     - Production: `https://your-app.vercel.app`
   - **Authorized Redirect URIs:**
     - Local: `http://localhost:5000/authorize`
     - Production: `https://your-app.vercel.app/authorize`
5. Copy your **Client ID** and **Client Secret** into your `.env` or production environment variables.

---

## 💾 Database Configuration

VulnEye uses **SQLAlchemy** to support both SQLite and PostgreSQL out-of-the-box:

* **Local Development:** Defaults to `sqlite:///scans.db`.
* **Serverless (Vercel):** Automatically uses SQLite with self-healing fallback to `/tmp/scans.db`.
* **PostgreSQL (Production / Render / Supabase / Neon):** Set the `DATABASE_URL` environment variable:
  ```env
  DATABASE_URL="postgresql://user:password@host:5432/vulneye_db"
  ```

---

## 📡 REST API & Webhooks Reference

VulnEye includes a RESTful API with Bearer token authentication for CI/CD pipeline automation.

### Authentication
Include your API token (generated in `/settings`) in the `Authorization` header:
```http
Authorization: Bearer vye_live_your_api_token_here
```

### API Endpoints

#### 1. System Health Check
```http
GET /api/v1/health
```
```json
{
  "service": "VulnEye CyberSentinel API v1",
  "status": "online",
  "timestamp": "2026-09-09T08:30:00.000000"
}
```

#### 2. Execute Security Scan
```http
POST /api/v1/scan
Content-Type: application/json
Authorization: Bearer vye_live_your_token

{
  "url": "https://example.com"
}
```
*Also supports `GET /api/v1/scan?url=https://example.com`.*

#### 3. Fetch Historical Scans
```http
GET /api/v1/history
Authorization: Bearer vye_live_your_token
```

#### 4. Security Badge Endpoint
```http
GET /api/v1/badge?url=https://example.com
# or
GET /badge/example.com
```
*Returns a dynamic `image/svg+xml` response.*

#### 5. Webhook Alerts (Discord / Slack)
When configured in `/settings`, VulnEye sends automated payloads upon detecting High/Critical vulnerabilities:
```json
{
  "username": "VulnEye SOC Alert",
  "embeds": [
    {
      "title": "🚨 Security Perimeter Alert: https://example.com",
      "color": 14428672,
      "fields": [
        {"name": "Risk Level", "value": "HIGH", "inline": true},
        {"name": "Status Code", "value": "200", "inline": true},
        {"name": "Findings", "value": "Missing HSTS, Exposed Port 3306"}
      ]
    }
  ]
}
```

---

## 🏷️ Dynamic SVG Security Badges

Embed real-time VulnEye security badges directly into your repository README:

### Markdown
```markdown
[![VulnEye Security Grade](https://your-domain.vercel.app/badge/example.com)](https://your-domain.vercel.app)
```

### HTML
```html
<a href="https://your-domain.vercel.app">
  <img src="https://your-domain.vercel.app/badge/example.com" alt="VulnEye Security Grade"/>
</a>
```

---

## 🌌 Production Cloud Deployment

### Deploy to Vercel (Serverless)

VulnEye is configured for seamless Vercel deployment with zero configuration:

1. Push your code to a GitHub repository.
2. In the **[Vercel Dashboard](https://vercel.com)**, click **Add New Project** and import `VulnEye`.
3. Add Environment Variables under **Project Settings**:
   - `SECRET_KEY`: A cryptographically secure random string.
   - `GOOGLE_CLIENT_ID`: Your Google OAuth Client ID.
   - `GOOGLE_CLIENT_SECRET`: Your Google OAuth Client Secret.
   - `DATABASE_URL` *(Optional)*: PostgreSQL connection string if not using SQLite `/tmp`.
4. Click **Deploy**.

### Deploy to Render / Docker

VulnEye includes a `render.yaml` specification for deploying as a standard web service:

1. Connect your repository to **[Render](https://render.com)**.
2. Create a **New Web Service** using Python environment.
3. Configure:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn api.index:app`
4. Supply environment variables (`SECRET_KEY`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`).

---

## 📜 Disclaimer & License

### ⚠️ Legal Disclaimer
VulnEye is developed strictly for authorized security auditing, defensive assessment, and educational research. Scanning targets without prior explicit written authorization from the system owner is illegal and unethical. The authors and maintainers assume no responsibility for unauthorized actions or misuse.

### 📄 License
Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more details.

---

<div align="center">
  <sub>Built with ❤️ for the Cybersecurity, SecOps, and Developer Community</sub>
</div>
