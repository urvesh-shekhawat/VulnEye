# VulnEye

A web vulnerability scanner built with Flask that helps identify and analyze security vulnerabilities in web applications.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Vulnerability Scanning](#vulnerability-scanning)
- [Results & Reports](#results--reports)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

VulnEye is a comprehensive web vulnerability scanner that assists security professionals and developers in identifying potential security flaws in web applications. Built with Flask, it provides an intuitive interface for scanning URLs and analyzing vulnerabilities.

## ✨ Features

- **URL Vulnerability Scanning** - Scan websites for common web vulnerabilities
- **Real-time Analysis** - Get immediate feedback on potential security issues
- **Detailed Reports** - Comprehensive vulnerability reports with recommendations
- **User-Friendly Interface** - Clean and intuitive web-based dashboard
- **Multiple Vulnerability Checks** - Detect various types of security flaws including:
  - SQL Injection vulnerabilities
  - Cross-Site Scripting (XSS)
  - Cross-Site Request Forgery (CSRF)
  - Security Headers Analysis
  - SSL/TLS Configuration
  - And more...

## 🛠️ Technology Stack

| Technology | Purpose | Percentage |
|-----------|---------|-----------|
| **Python** | Backend logic and vulnerability detection | 26.7% |
| **HTML** | Web interface templates | 50.5% |
| **CSS** | Styling and UI design | 22.8% |

- **Framework**: Flask
- **Language**: Python 3.x
- **Frontend**: HTML5, CSS3
- **Server**: Flask Development/Production Server

## 📦 Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)
- Virtual environment (recommended)

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/urvesh-shekhawat/VulnEye.git
   cd VulnEye
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the application**
   Open your browser and navigate to `http://localhost:5000`

## 🚀 Usage

### Basic Scanning

1. Navigate to the home page
2. Enter the target URL you want to scan
3. Click the "Scan" button
4. Wait for the scan to complete
5. Review the vulnerability report

### Advanced Options

- **Scan Depth**: Choose between quick scan or deep analysis
- **Custom Headers**: Add custom HTTP headers for the scan
- **Authentication**: Provide credentials if required
- **Timeout Settings**: Adjust scan timeout preferences

## ⚙️ Configuration

Create a `.env` file in the root directory for configuration:

```env
FLASK_ENV=development
FLASK_DEBUG=True
SECRET_KEY=your-secret-key-here
SCAN_TIMEOUT=300
MAX_REDIRECTS=5
LOG_LEVEL=INFO
```

## 🔍 Vulnerability Scanning

VulnEye performs comprehensive scanning including:

- **Input Validation**: Detects missing input validation
- **Authentication Flaws**: Identifies weak authentication mechanisms
- **Sensitive Data Exposure**: Finds exposed sensitive information
- **XML External Entities (XXE)**: Detects XXE vulnerabilities
- **Broken Access Control**: Identifies authorization issues
- **Security Misconfiguration**: Finds improper security settings
- **Insecure Deserialization**: Detects serialization flaws

## 📊 Results & Reports

Scan results include:

- **Severity Level**: Critical, High, Medium, Low, Info
- **Vulnerability Description**: Detailed explanation of the issue
- **Affected Parameter**: Which input/header is vulnerable
- **Remediation Steps**: How to fix the vulnerability
- **References**: Links to security resources
- **Evidence**: Actual request/response showing the vulnerability

## 📁 Project Structure

```
VulnEye/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/
│   ├── base.html         # Base template
│   ├── index.html        # Home page
│   ├── scan.html         # Scan interface
│   └── results.html      # Results page
├── static/
│   ├── css/
│   │   └── style.css     # Main stylesheet
│   └── js/
│       └── script.js     # Frontend scripts
├── scanners/             # Vulnerability scanner modules
│   ├── __init__.py
│   ├── sql_injection.py
│   ├── xss_scanner.py
│   └── header_scanner.py
└── utils/                # Utility functions
    ├── __init__.py
    └── helpers.py
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is intended for authorized security testing only. Unauthorized access to computer systems is illegal. Always ensure you have explicit permission before scanning any website or application. The authors are not responsible for any misuse of this tool.

## 📧 Contact & Support

For issues, questions, or suggestions, please open an [GitHub Issue](https://github.com/urvesh-shekhawat/VulnEye/issues).

---

**Happy Scanning! 🔒**
