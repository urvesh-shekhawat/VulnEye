# 🛡️ VulnEye — Enterprise Web Vulnerability Scanner

[![Vercel Deployment](https://img.shields.io/badge/Deployed%20on-Vercel-black?logo=vercel&logoColor=white)](https://vercel.com)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)](https://python.org)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.x-red?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![OAuth 2.0](https://img.shields.io/badge/Auth-Google%20OAuth-4285F4?logo=google&logoColor=white)](https://console.cloud.google.com/)

VulnEye is a premium, modern web vulnerability scanner designed to conduct rapid, non-intrusive security assessments of public web domains. Fully optimized for serverless deployments on Vercel, it features a sleek glassmorphic dark/light interface, Google OAuth 2.0 authentication, and a corporate-grade dynamic PDF report generation engine.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Core Features](#-core-features)
- [Technology Stack](#-technology-stack)
- [Project Structure](#-project-structure)
- [Local Installation & Setup](#-local-installation--setup)
- [Google Cloud Console Setup](#-google-cloud-console-setup)
- [Vercel Deployment (CI/CD)](#-vercel-deployment-cicd)
- [Contributing](#-contributing)
- [Disclaimer & License](#-disclaimer--license)

---

## 🎯 Overview

VulnEye assists developers and security professionals in assessing the baseline security posture of public-facing web applications. Rather than using aggressive, intrusive payloads, it performs high-speed security audits, analyzing transport layer encryptions, HTTP header configurations, public port exposures, and generic administrative directory structures. 

---

## ✨ Core Features

### 🔑 1. Secure Google OAuth 2.0 Sign-In
* Integrated using the secure `Authlib` engine communicating with Google's OpenID Connect discovery services.
* Custom-designed, official brand-compliant Google Login screen.
* Safe local authentication fallback displaying warning banners if environment credentials are not yet configured.

### 🔍 2. Multi-Vector Security Scanner
* **SSL/TLS Security Audit:** Assesses cert availability, secure transport, and secure redirection.
* **HTTP Headers Scanner:** Analyzes response headers for vital configurations such as HSTS (`Strict-Transport-Security`), CSP (`Content-Security-Policy`), `X-Frame-Options`, and `X-Content-Type-Options`.
* **Port Scanner & Service Mapping:** Safely audits a checklist of common database, system, and web service ports (e.g., 20, 21, 22, 23, 25, 53, 80, 110, 443, 1433, 3306, 5432, 8080) for unexpected exposure.
* **Directory Brute-Forcer:** Audits target domains for accessible generic administrative or system folders (e.g., `/admin`, `/login`, `/config`, `/test`).
* **Form Auditor:** Automatically extracts interactive HTML form definitions, capturing actions, methods, and input fields.

### 📄 3. Corporate-Grade PDF Security Reports
* Generates professional, highly styled security assessment dossiers via `ReportLab`.
* Features custom brand banner bars, double-staged headers, metadata grids (timestamps and scan parameters), and zebra-striped metric tables.
* **Smart Text-Wrapping:** Wraps extremely long target URLs inside paragraph blocks to prevent text clipping and page overflows.
* **Severity Pill Banners:** High-contrast color-coded indicators representing aggregated risk (Low = Mint green, Medium = Amber gold, High = Crimson red).

### ⚙️ 4. Serverless-Safe Self-Healing Database
* Configured to run on Vercel's read-only serverless functions.
* Dynamically detects serverless environments and redirects SQLite writes to the ephemeral `/tmp/scans.db` directory.
* Automatically recreates directories and compiles SQL schemas on-the-fly when serverless containers cold-start.

### 🎨 5. Luxury Glassmorphism UI/UX
* Dynamic background featuring floating color-shifting **ambient auroras** animated with smooth CSS keyframes.
* Translucent cards (`backdrop-filter: blur(24px)`) styled with glowing focus rings, border-pulse animations, and interactive hover transitions.
* Sleek dark/light toggles that transition effortlessly, dynamically updating the layout and components.
* Auto-resolving navbar profile badges displaying your active **Google avatar picture** and full name!

---

## 🛠️ Technology Stack

| Technology | Purpose | Implementation Details |
| :--- | :--- | :--- |
| **Python 3.12+** | Backend Logic & Audits | Flask 3.x, Authlib, requests, beautifulsoup4, reportlab, python-dotenv |
| **SQLite 3** | Ephemeral/Local Logging | Self-healing directory & table initializations, serverless compatibility |
| **HTML5 & CSS3** | High-End User Interface | Glassmorphism, HSL tailored variables, keyframe animations, Outfit font |
| **ES6 JavaScript** | Frontend Interactions | LocalStorage-backed state sync, dynamic dark mode rendering |

---

## 📂 Project Structure

The project has been refactored to align with the modern serverless layout expected by cloud deployment hosts:

```text
VulnEye/
├── api/                   # Main Serverless Source Folder
│   ├── index.py           # Flask Application Entry Point (Vercel Entry)
│   ├── static/            # Static Assets
│   │   └── style.css      # Cohesive Luxury Global Stylesheet
│   └── templates/         # Jinja2 HTML Templates (Glassmorphism Designs)
│       ├── history.html   # Scans Logs Dashboard & Tables
│       ├── index.html     # Futuristic Scanner Launchpad
│       ├── login.html     # Premium Google Login UI
│       └── result.html    # Vulnerabilities Results Dashboard
├── .env.example           # Secrets Template for Local Configurations
├── .gitignore             # Git Exclude Lists (UTF-8 Encoded)
├── app.py                 # Lightweight Local Runner Stub
├── database.py            # SQLite Dynamic Database Manager (Serverless /tmp fallbacks)
├── requirements.txt       # Python Dependencies
├── scanner.py             # Security Scan Logic & Algorithms
└── vercel.json            # Vercel Serverless Function Routing Configuration
```

---

## 🚀 Local Installation & Setup

Follow these steps to run VulnEye locally in your development environment:

### Step 1: Clone and Navigate
```bash
git clone https://github.com/urvesh-shekhawat/VulnEye.git
cd VulnEye
```

### Step 2: Establish Virtual Environment & Install Dependencies
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

### Step 3: Configure Local Environment variables
1. Copy the template configuration file:
   ```bash
   cp .env.example .env
   ```
2. Open `.env` and fill in your real Google Cloud Console Credentials (refer to the Google Credentials Setup section below):
   ```env
   SECRET_KEY="A_Complex_Random_String_For_Signing_Sessions"
   GOOGLE_CLIENT_ID="123456789-abcdefg.apps.googleusercontent.com"
   GOOGLE_CLIENT_SECRET="GOCSPX-abc123yourclientsecret"
   ```

### Step 4: Run the Development Server
```bash
python app.py
```
Open **`http://localhost:5000`** in your browser to start auditing targets!

> [!NOTE]
> When running locally, the application automatically allows local HTTP loopback callbacks (e.g., `http://localhost:5000/authorize`) by dynamically setting `OAUTHLIB_INSECURE_TRANSPORT="1"` behind the scenes, ensuring a zero-configuration local setup.

---

## 🔐 Google Cloud Console Setup

To configure Google OAuth 2.0 Credentials:

1. Go to the **[Google Cloud Console Credentials Page](https://console.cloud.google.com/apis/credentials)**.
2. Select or create a project.
3. Configure the **OAuth Consent Screen** (User Type: External) and add your app's basic information.
4. Go to **Credentials**, click **Create Credentials** -> **OAuth Client ID**.
5. Select **Web Application** as the application type.
6. Add the following parameters:
   * **Authorized JavaScript origins:**
     * Local dev: `http://localhost:5000`
     * Production: `https://your-app.vercel.app` (your Vercel URL)
   * **Authorized redirect URIs:**
     * Local dev: `http://localhost:5000/authorize`
     * Production: `https://your-app.vercel.app/authorize`
7. Click **Create** and copy your **Client ID** and **Client Secret** into your `.env` file (local) or Vercel dashboard (production).

---

## 🌌 Vercel Deployment (CI/CD)

Since VulnEye is configured with modern serverless rewrites inside `vercel.json`, deploying it live takes under a minute:

1. Push your latest code changes to your GitHub/GitLab repository.
2. Log into the **[Vercel Dashboard](https://vercel.com)**.
3. Click **Add New** -> **Project**, find your **`VulnEye`** repository, and click **Import**.
4. In the Project Settings screen:
   * Keep **Framework Preset** as `Other` (Vercel automatically detects `vercel.json` and builds the `@vercel/python` runtime).
   * Keep **Root Directory** as `./`.
5. Under the **Environment Variables** tab, add your production variables:
   * `SECRET_KEY` = `[your custom random session signing key]`
   * `GOOGLE_CLIENT_ID` = `[your Google Client ID]`
   * `GOOGLE_CLIENT_SECRET` = `[your Google Client Secret]`
6. Click **Deploy**.

Vercel will compile your code, bundle the `api/` directory (carrying templates, styles, and modules), provision a secure HTTPS URL, and host your app live!

> [!IMPORTANT]
> **Vercel Database Persistence Note:**
> Serverless environments are stateless. The SQLite database at `/tmp/scans.db` will persist within individual active lambda containers but will be wiped when containers idle or recycle. This is ideal for zero-cost demo environments. If you require permanent history logs, we can configure a cloud PostgreSQL database (e.g. Supabase or Neon) and supply a `DATABASE_URL` env variable!

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request on GitHub.

---

## 📜 Disclaimer & License

### ⚠️ Disclaimer
This tool is intended for authorized security testing only. Unauthorized access to computer systems is illegal. Always ensure you have explicit permission before scanning any website or application. The authors are not responsible for any misuse of this tool.

### License
This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

**Happy Scanning! 🔒**
