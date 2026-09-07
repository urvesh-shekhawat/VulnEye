import os
import sys
import json
import time
import datetime
from io import BytesIO
from urllib.parse import urlparse

# Add parent directory to sys.path so modules like scanner and database can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, redirect, url_for, session, make_response, Response, jsonify
from scanner import (
    normalize_url,
    extract_domain,
    is_safe_target,
    resolve_host_info,
    check_status,
    check_https,
    check_ssl_cert,
    check_security_headers,
    scan_ports,
    scan_directories,
    scan_sensitive_files,
    scan_subdomains,
    analyze_password_strength,
    check_cookie_security,
    check_cors,
    detect_tech_stack,
    detect_forms,
    calculate_risk,
    run_scan
)
from database import (
    init_db,
    save_scan,
    get_all_scans,
    get_scan_by_id,
    get_latest_scan_results,
    delete_scan,
    add_monitored_asset,
    get_monitored_assets,
    delete_monitored_asset,
    generate_api_key,
    get_user_api_keys,
    revoke_api_key,
    verify_api_key,
    compare_scans,
    get_soc_dashboard_metrics,
    get_user_subscription,
    process_subscription_payment,
    get_user_transactions,
    get_transaction_by_id,
    get_webhook_config,
    save_webhook_config,
    send_webhook_alert
)
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from bs4 import BeautifulSoup

# Explicitly define template and static folder relative to this file
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "templates"))
static_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "static"))

# Load local environment variables (.env) if present
load_dotenv()

# Enable insecure HTTP for local OAuth development (allows http://localhost callbacks)
if not os.environ.get("VERCEL"):
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
# Use SECRET_KEY from environment with a fallback
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey123_fallback")

# WSGI Middleware to fix Vercel serverless path prefixes (/api/index.py, /api)
class PrefixMiddleware(object):
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path_info = environ.get('PATH_INFO', '')
        if path_info.startswith('/api/index.py'):
            environ['PATH_INFO'] = path_info[len('/api/index.py'):] or '/'
        elif path_info.startswith('/api/index'):
            environ['PATH_INFO'] = path_info[len('/api/index'):] or '/'
        elif path_info.startswith('/api') and not (
            path_info.startswith('/api/v1') or 
            path_info.startswith('/api/static') or 
            path_info.startswith('/api/webhook') or 
            path_info.startswith('/api/checkout') or 
            path_info.startswith('/api/tools')
        ):
            environ['PATH_INFO'] = path_info[len('/api'):] or '/'
        return self.wsgi_app(environ, start_response)

app.wsgi_app = PrefixMiddleware(app.wsgi_app)

# Setup Authlib OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Initialize DB
init_db()

def is_logged_in():
    return session.get("logged_in")

def get_current_user_email():
    user = session.get("user")
    if user and isinstance(user, dict):
        return user.get("email")
    return None

# ================= AUTHENTICATION ROUTES =================
@app.route("/login")
def login():
    if is_logged_in():
        return redirect(url_for("dashboard"))
    
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    
    warning = None
    if not client_id or not client_secret:
        warning = "Google OAuth credentials are not configured in your environment. You can use 'Demo / Guest Analyst' mode or configure .env."
        
    return render_template("login.html", warning=warning)

@app.route("/login/guest")
@app.route("/login/demo")
def login_guest():
    session['user'] = {
        'name': 'Cyber Analyst',
        'email': 'analyst@vulneye.sec',
        'picture': 'https://api.dicebear.com/7.x/bottts/svg?seed=VulnEyeSecurity'
    }
    session['logged_in'] = True
    return redirect(url_for("dashboard"))

@app.route("/login/google")
def login_google():
    redirect_uri = url_for("authorize", _external=True)
    if os.environ.get("VERCEL") or request.headers.get("X-Forwarded-Proto") == "https":
        redirect_uri = redirect_uri.replace("http://", "https://")
    return google.authorize_redirect(redirect_uri)

@app.route("/authorize")
def authorize():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        if user_info:
            session['user'] = user_info
            session['logged_in'] = True
            return redirect(url_for("dashboard"))
    except Exception as e:
        return render_template("login.html", error=f"Google Authentication failed: {str(e)}")
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ================= PUBLIC LANDING & EXECUTIVE SOC DASHBOARD =================
@app.route("/")
def home():
    if is_logged_in():
        return redirect(url_for("dashboard"))
    return render_template("landing.html")

@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_email = get_current_user_email()
    metrics = get_soc_dashboard_metrics(user_email)
    return render_template("dashboard.html", metrics=metrics)

# ================= SCANNER HUD & SSE STREAMING =================
@app.route("/scan", methods=["GET", "POST"])
def scan():
    if not is_logged_in():
        return redirect(url_for("login"))

    if request.method == "POST":
        url = request.form.get("url")
        if not url:
            return redirect(url_for("dashboard"))
        return render_template("scan_progress.html", url=url)
    
    url = request.args.get("url")
    if url:
        return render_template("scan_progress.html", url=url)
    return render_template("index.html")

@app.route("/scan/stream")
def scan_stream():
    if not is_logged_in():
        return "Unauthorized", 401

    url = request.args.get("url")
    if not url:
        return "Missing URL", 400

    url_normalized = normalize_url(url)
    user_email = get_current_user_email()
    redirect_url = url_for('result', url=url_normalized)

    def generate_stream():
        yield f"data: {json.dumps({'status': 'starting', 'message': 'Normalizing target URL & validating safety parameters...'})}\n\n"
        time.sleep(0.3)

        parsed = urlparse(url_normalized)
        host = parsed.netloc

        host_info = resolve_host_info(host)
        if not host_info["safe"]:
            error_results = {
                "url": url_normalized,
                "host_info": host_info,
                "reachable": False,
                "error": host_info["message"],
                "status_code": None,
                "https": False,
                "ssl_certificate": {},
                "missing_headers": [],
                "present_headers": {},
                "open_ports": [],
                "found_directories": [],
                "sensitive_files": [],
                "cookies": [],
                "cors": {},
                "tech_stack": [],
                "forms": [],
                "risk": "Unknown"
            }
            save_scan(error_results, user_email=user_email)
            yield f"data: {json.dumps({'status': 'done', 'redirect': redirect_url})}\n\n"
            return

        target_ip = host_info.get("ip", "Unknown")
        yield f"data: {json.dumps({'status': 'reachable', 'message': f'Resolving target IP ({target_ip}) & testing HTTP reachability...'})}\n\n"
        status_data = check_status(url_normalized)

        if not status_data["reachable"]:
            error_results = {
                "url": url_normalized,
                "host_info": host_info,
                "reachable": False,
                "error": status_data.get("error", "Host unreachable"),
                "status_code": None,
                "https": False,
                "ssl_certificate": {},
                "missing_headers": [],
                "present_headers": {},
                "open_ports": [],
                "found_directories": [],
                "sensitive_files": [],
                "cookies": [],
                "cors": {},
                "tech_stack": [],
                "forms": [],
                "risk": "Unknown"
            }
            save_scan(error_results, user_email=user_email)
            yield f"data: {json.dumps({'status': 'done', 'redirect': redirect_url})}\n\n"
            return

        response = status_data["response"]
        soup = None
        try:
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception:
            pass

        yield f"data: {json.dumps({'status': 'ssl', 'message': 'Inspecting TLS certificate validity, expiration, & cipher suites...'})}\n\n"
        https_status = check_https(url_normalized)
        ssl_cert_info = check_ssl_cert(host) if https_status else {}

        yield f"data: {json.dumps({'status': 'headers', 'message': 'Auditing OWASP defense headers (CSP, HSTS, X-Frame-Options)...'})}\n\n"
        headers_info = check_security_headers(response)

        yield f"data: {json.dumps({'status': 'ports', 'message': 'Sweeping 30+ service & database ports in parallel...'})}\n\n"
        open_ports = scan_ports(host)

        yield f"data: {json.dumps({'status': 'dirs', 'message': 'Probing admin entry points & exposed files (.env, .git, backups)...'})}\n\n"
        found_dirs = scan_directories(url_normalized)
        sensitive_leaks = scan_sensitive_files(url_normalized)

        yield f"data: {json.dumps({'status': 'forms', 'message': 'Analyzing cookie security flags, CORS origins, & input forms...'})}\n\n"
        cookies_info = check_cookie_security(response)
        cors_info = check_cors(url_normalized)
        tech_stack = detect_tech_stack(response, soup)
        forms = detect_forms(soup)

        yield f"data: {json.dumps({'status': 'saving', 'message': 'Synthesizing threat intelligence & compiling audit report...'})}\n\n"
        results = {
            "url": url_normalized,
            "host_info": host_info,
            "reachable": True,
            "status_code": status_data["status_code"],
            "https": https_status,
            "ssl_certificate": ssl_cert_info,
            "missing_headers": headers_info["missing"],
            "present_headers": headers_info["present"],
            "open_ports": open_ports,
            "found_directories": found_dirs,
            "sensitive_files": sensitive_leaks,
            "cookies": cookies_info,
            "cors": cors_info,
            "tech_stack": tech_stack,
            "forms": forms
        }
        results["risk"] = calculate_risk(results)

        save_scan(results, user_email=user_email)
        time.sleep(0.3)

        yield f"data: {json.dumps({'status': 'done', 'redirect': redirect_url})}\n\n"

    return Response(generate_stream(), mimetype='text/event-stream')

# ================= RESULTS & AUDIT DOSSIER =================
@app.route("/result")
def result():
    if not is_logged_in():
        return redirect(url_for("login"))

    url = request.args.get("url")
    if not url:
        return redirect(url_for("dashboard"))

    user_email = get_current_user_email()
    results = get_latest_scan_results(url, user_email=user_email)
    if not results:
        results = run_scan(url)
        save_scan(results, user_email=user_email)

    return render_template("result.html", results=results)

@app.route("/history")
def history():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_email = get_current_user_email()
    scans = get_all_scans(user_email=user_email)
    return render_template("history.html", scans=scans)

@app.route("/scan/delete/<int:scan_id>", methods=["GET", "POST"])
def delete_scan_route(scan_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    user_email = get_current_user_email()
    delete_scan(scan_id, user_email=user_email)
    return redirect(url_for("history"))

# ================= 24/7 ASSET MONITORING =================
@app.route("/monitoring")
def monitoring():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_email = get_current_user_email()
    assets = get_monitored_assets(user_email)
    return render_template("monitoring.html", assets=assets)

@app.route("/monitoring/add", methods=["POST"])
def add_asset():
    if not is_logged_in():
        return redirect(url_for("login"))

    domain = request.form.get("domain")
    frequency = request.form.get("frequency", "daily")
    if domain:
        user_email = get_current_user_email()
        add_monitored_asset(user_email, domain, frequency)

    return redirect(url_for("monitoring"))

@app.route("/monitoring/delete/<int:asset_id>", methods=["GET", "POST"])
def delete_asset(asset_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    user_email = get_current_user_email()
    delete_monitored_asset(asset_id, user_email)
    return redirect(url_for("monitoring"))

# ================= SCAN COMPARISON & DIFF ENGINE =================
@app.route("/compare", methods=["GET", "POST"])
def compare():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_email = get_current_user_email()
    scans = get_all_scans(user_email=user_email)

    scan_id_1 = request.form.get("scan_1") or request.args.get("scan_1")
    scan_id_2 = request.form.get("scan_2") or request.args.get("scan_2")

    comparison_result = None
    if scan_id_1 and scan_id_2:
        try:
            comparison_result = compare_scans(int(scan_id_1), int(scan_id_2), user_email)
        except Exception:
            pass

    return render_template("compare.html", scans=scans, comparison=comparison_result, scan_1=scan_id_1, scan_2=scan_id_2)

# ================= SECURITY KNOWLEDGE BASE & SCANNER GUIDE =================
@app.route("/guide")
def guide():
    return render_template("guide.html")

# ================= INTERACTIVE REPORT EXPLAINER & AI DIAGNOSTIC =================
@app.route("/analyzer", methods=["GET", "POST"])
def analyzer():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_email = get_current_user_email()
    scans = get_all_scans(user_email=user_email)

    selected_scan_id = request.form.get("scan_id") or request.args.get("scan_id")
    target_url = request.form.get("url") or request.args.get("url")

    scan_data = None
    if selected_scan_id:
        try:
            scan_data = get_scan_by_id(int(selected_scan_id), user_email)
        except Exception:
            pass
    elif target_url:
        scan_data = get_latest_scan_results(target_url, user_email=user_email)
        if not scan_data:
            scan_data = run_scan(target_url)
            save_scan(scan_data, user_email=user_email)
    elif scans and len(scans) > 0:
        # Default to most recent scan
        try:
            scan_data = get_scan_by_id(scans[0][0], user_email)
            selected_scan_id = scans[0][0]
        except Exception:
            pass

    # Build Plain-Language Explanation & Remediation Blueprint
    explanation = None
    if scan_data and scan_data.get("reachable"):
        explanation = build_plain_language_remediation(scan_data)

    return render_template(
        "analyzer.html",
        scans=scans,
        scan_data=scan_data,
        selected_scan_id=selected_scan_id,
        explanation=explanation
    )

def build_plain_language_remediation(data):
    missing_hdrs = data.get("missing_headers", [])
    open_ports = data.get("open_ports", [])
    leaks = data.get("sensitive_files", [])
    ssl_info = data.get("ssl_certificate", {})
    cors_info = data.get("cors", {})
    cookies = data.get("cookies", [])
    risk = data.get("risk", "Unknown")

    findings = []
    
    # 1. SSL Analysis
    if not data.get("https"):
        findings.append({
            "title_hi": "Unencrypted HTTP Traffic (No HTTPS)",
            "title_en": "Unencrypted HTTP Communication (Missing HTTPS)",
            "severity": "High",
            "plain_meaning_hi": "Aapki website par aane wala data (passwords, cookies, messages) bina kisi encryption ke open internet me jaa raha hai.",
            "plain_meaning_en": "All web traffic to and from your website is transmitted in cleartext without cryptographic TLS encryption.",
            "hacker_vector_hi": "Attacker public Wi-Fi ya ISP level par Man-in-the-Middle (MITM) attack karke users ke login credentials aur session cookies chura sakta hai.",
            "hacker_vector_en": "Attackers on public Wi-Fi or ISP nodes can perform Man-in-the-Middle (MITM) attacks to eavesdrop on sensitive credentials, session tokens, and credit card data.",
            "fix_steps_hi": "Free SSL certificate install karein (Let's Encrypt ya Cloudflare Flexible/Full SSL) aur HTTP se HTTPS par 301 Permanent Redirect lagayein.",
            "fix_steps_en": "Install a valid TLS/SSL certificate (e.g., Let's Encrypt via Certbot or Cloudflare SSL) and enforce strict 301 Permanent Redirect from HTTP to HTTPS."
        })
    elif ssl_info.get("expired"):
        findings.append({
            "title_hi": "Expired TLS / SSL Certificate",
            "title_en": "Expired TLS / SSL Certificate",
            "severity": "High",
            "plain_meaning_hi": "Aapka SSL certificate expire ho chuka hai, jisse browsers users ko 'Your connection is not private' ka red warning screen dikhate hain.",
            "plain_meaning_en": "The website's cryptographic TLS certificate has exceeded its expiration date, triggering full-screen browser privacy warnings for all visitors.",
            "hacker_vector_hi": "Users ka trust khatam ho jata hai aur expired certs spoofing ya interception attacks ke liye vulnerable ho sakte hain.",
            "hacker_vector_en": "Visitors cannot verify your identity, allowing malicious actors to impersonate your site using forged or expired credentials without user suspicion.",
            "fix_steps_hi": "Certbot command `certbot renew --force-renewal` run karke cert renew karein.",
            "fix_steps_en": "Renew your SSL certificate immediately using Certbot (`sudo certbot renew --force-renewal`) or update your certificate authority."
        })

    # 2. Exposed Database/Admin Ports
    for p in open_ports:
        p_num = p["port"] if isinstance(p, dict) else p
        p_srv = p["service"] if isinstance(p, dict) else "TCP Service"
        if p_num in [3306, 5432, 6379, 27017, 1433]:
            findings.append({
                "title_hi": f"Database Port Open: {p_num} ({p_srv})",
                "title_en": f"Publicly Exposed Database Port: {p_num} ({p_srv})",
                "severity": "High",
                "plain_meaning_hi": f"Aapka database ({p_srv}) poori duniya ke liye open internet par exposed hai. Koi bhi direct database port se connect hone ki koshish kar sakta hai.",
                "plain_meaning_en": f"Your internal database instance ({p_srv}) is directly accessible to the public internet on port {p_num}.",
                "hacker_vector_hi": "Hackers automated botnets se brute-force passwords try karenge ya unauthenticated Redis/MongoDB ko dump/delete karke Ransomware demand kar sakte hain.",
                "hacker_vector_en": "Automated scanners and malicious botnets launch distributed brute-force dictionary attacks or exploit default unauthenticated setups to dump, wipe, or ransom your database.",
                "fix_steps_hi": f"Firewall rule lagayein: `sudo ufw deny {p_num}` aur database config (`bind-address`) ko `127.0.0.1` ya private VPC subnet par bind karein.",
                "fix_steps_en": f"Block public traffic via firewall (`sudo ufw deny {p_num}/tcp`) and bind database listening address (`bind-address = 127.0.0.1`) strictly to localhost or private VPC."
            })
        elif p_num in [21, 23]:
            findings.append({
                "title_hi": f"Legacy Insecure Protocol: Port {p_num} ({p_srv})",
                "title_en": f"Insecure Cleartext Protocol: Port {p_num} ({p_srv})",
                "severity": "High",
                "plain_meaning_hi": f"Telnet/FTP jaise purane unencrypted protocols use ho rahe hain jisme passwords plain text me travel karte hain.",
                "plain_meaning_en": f"Legacy service {p_srv} transmits login credentials and session data in cleartext without encryption.",
                "hacker_vector_hi": "Packet sniffing se koi bhi username aur password capture kar sakta hai.",
                "hacker_vector_en": "Network packet capture attacks can intercept administrative credentials in transit.",
                "fix_steps_hi": f"FTP/Telnet service disable karein aur secure alternative (SFTP / SSH) use karein.",
                "fix_steps_en": f"Disable {p_srv} daemon and transition strictly to encrypted SSH/SFTP alternatives."
            })

    # 3. Sensitive Files Leak
    for leak in leaks:
        findings.append({
            "title_hi": f"Sensitive File Exposure: {leak['file']}",
            "title_en": f"Critical Secret / Source Disclosure: {leak['file']}",
            "severity": leak.get("severity", "High"),
            "plain_meaning_hi": f"Aapke server ka sensitive internal file ({leak['file']}) bina kisi password ke direct download ho raha hai.",
            "plain_meaning_en": f"A sensitive internal configuration or source repository file ({leak['file']}) is publicly accessible via direct HTTP GET request.",
            "hacker_vector_hi": "Agar `.env` hai toh hackers ko Database passwords, AWS keys, JWT secrets mil jayenge. Agar `.git` hai toh poora source code download ho jayega.",
            "hacker_vector_en": "Attackers can download your entire database credentials, Stripe/AWS API keys, or reverse-engineer your full proprietary source code via Git extraction.",
            "fix_steps_hi": "Web server (Nginx/Apache) me dotfiles block rule enable karein aur public directory se sensitive files delete karein.",
            "fix_steps_en": "Enforce strict dotfile deny rules in Nginx/Apache configuration and immediately remove all backup archives from the public web root."
        })

    # 4. Missing Headers
    header_explanations = {
        "X-Frame-Options": {
            "name_hi": "Missing X-Frame-Options (Clickjacking Risk)",
            "name_en": "Missing X-Frame-Options Header (Clickjacking Exposure)",
            "meaning_hi": "Aapki website ko koi doosra hacker iframe ke andar load karke fake buttons ke peeche hide kar sakta hai.",
            "meaning_en": "Your web application allows itself to be framed within external third-party iframes without restriction.",
            "vector_hi": "Clickjacking: User ko lagta hai woh koi harmless button click kar raha hai, lekin background me woh aapki website par sensitive actions kar deta hai.",
            "vector_en": "Clickjacking: Attackers overlay an invisible iframe of your app over a deceptive webpage, tricking logged-in users into clicking sensitive account-level actions.",
            "fix_hi": "Nginx config me `add_header X-Frame-Options 'DENY' always;` add karein.",
            "fix_en": "Add `add_header X-Frame-Options 'DENY' always;` to your Nginx server block or set `X-Frame-Options: SAMEORIGIN` in your backend framework."
        },
        "Content-Security-Policy": {
            "name_hi": "Missing Content-Security-Policy (CSP)",
            "name_en": "Missing Content-Security-Policy (CSP) Header",
            "meaning_hi": "Browser ko yeh nahi pata ki scripts sirf trusted sources se load karni hain ya kisi bhi unknown domain se.",
            "meaning_en": "The browser lacks explicit whitelist rules governing which domains can execute JavaScript or load styles.",
            "vector_hi": "Cross-Site Scripting (XSS): Agar website me koi comment ya input flaw hua, toh hacker malicious JavaScript inject karke sabhi users ke passwords chura lega.",
            "vector_en": "Cross-Site Scripting (XSS): Malicious script injection exploits can execute arbitrary code, steal user session cookies, or keylog user inputs without browser resistance.",
            "fix_hi": "Nginx me CSP header define karein: `add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';\" always;`",
            "fix_en": "Define a robust CSP header: `add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';\" always;`"
        },
        "Strict-Transport-Security": {
            "name_hi": "Missing HSTS (Strict-Transport-Security)",
            "name_en": "Missing HTTP Strict Transport Security (HSTS)",
            "meaning_hi": "Browser ko force nahi kiya gaya hai ki woh hamesha encrypted HTTPS hi use kare.",
            "meaning_en": "Browsers are not explicitly instructed to communicate exclusively over HTTPS for all future requests.",
            "vector_hi": "SSL Stripping: Attacker user ke HTTPS connection ko downgrade karke insecure HTTP me convert kar sakta hai.",
            "vector_en": "SSL Stripping: Active network adversaries can strip TLS handshake requests and force communications over plaintext HTTP.",
            "fix_hi": "Nginx me `add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;` add karein.",
            "fix_en": "Configure HSTS with at least 1-year duration: `add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;`"
        },
        "X-Content-Type-Options": {
            "name_hi": "Missing X-Content-Type-Options",
            "name_en": "Missing X-Content-Type-Options Header",
            "meaning_hi": "Browser image ya text file ko executable JavaScript samajh kar run karne ki koshish kar sakta hai (MIME sniffing).",
            "meaning_en": "Browsers are allowed to MIME-sniff response bodies and execute non-script files as scripts.",
            "vector_hi": "Hacker image upload form me `.jpg` naam se JavaScript upload karega jo browser me execute ho jayegi.",
            "vector_en": "MIME confusion attacks allow uploaded user avatars or attachments to be interpreted and executed as malicious JavaScript payloads.",
            "fix_hi": "Nginx me `add_header X-Content-Type-Options 'nosniff' always;` add karein.",
            "fix_en": "Add `add_header X-Content-Type-Options 'nosniff' always;` to prevent browser MIME-type sniffing."
        }
    }

    for h in missing_hdrs:
        if h in header_explanations:
            info = header_explanations[h]
            findings.append({
                "title_hi": info["name_hi"],
                "title_en": info["name_en"],
                "severity": "Medium",
                "plain_meaning_hi": info["meaning_hi"],
                "plain_meaning_en": info["meaning_en"],
                "hacker_vector_hi": info["vector_hi"],
                "hacker_vector_en": info["vector_en"],
                "fix_steps_hi": info["fix_hi"],
                "fix_steps_en": info["fix_en"]
            })

    # Verdicts
    if risk == "Low":
        verdict_hi = "Aapki website ka overall security posture hardened hai. Kuch minor defense headers add karke aap isko 100% compliant bana sakte hain."
        verdict_en = "Your web application demonstrates a strong security posture. Addressing a few minor headers will achieve 100% OWASP compliance."
    elif risk == "Medium":
        verdict_hi = "Aapki website me kuch critical defense headers missing hain jisse Clickjacking ya XSS attacks ka risk rehta hai. Niche diye gaye Nginx config ko apply karein."
        verdict_en = "Your website has unconfigured defense headers that expose visitors to potential Clickjacking and XSS vectors. Apply the remediation snippets below."
    else:
        verdict_hi = "⚠️ IMMEDIATE ACTION REQUIRED: Critical database ports ya sensitive dotfiles exposed hain jinhe automated bots target kar sakte hain."
        verdict_en = "⚠️ CRITICAL ACTION REQUIRED: Severe perimeter exposures such as open database ports or leaked dotfiles were detected. Remediate immediately."

    # Generate Tailored Nginx Snippet
    nginx_lines = ["server {", "    # ... existing server config ...", ""]
    nginx_lines.append("    # 1. ENFORCE CRITICAL OWASP SECURITY HEADERS")
    if "Strict-Transport-Security" in missing_hdrs:
        nginx_lines.append("    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;")
    if "X-Frame-Options" in missing_hdrs:
        nginx_lines.append("    add_header X-Frame-Options \"DENY\" always;")
    if "X-Content-Type-Options" in missing_hdrs:
        nginx_lines.append("    add_header X-Content-Type-Options \"nosniff\" always;")
    if "Content-Security-Policy" in missing_hdrs:
        nginx_lines.append("    add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';\" always;")
    if "Referrer-Policy" in missing_hdrs:
        nginx_lines.append("    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;")
    
    nginx_lines.append("")
    nginx_lines.append("    # 2. BLOCK SENSITIVE DOTFILES (.env, .git, backups)")
    nginx_lines.append("    location ~ /\\.(?!well-known) {")
    nginx_lines.append("        deny all;")
    nginx_lines.append("        return 404;")
    nginx_lines.append("    }")
    nginx_lines.append("}")
    nginx_snippet = "\n".join(nginx_lines)

    # Generate Tailored Firewall Commands
    ufw_commands = ["# Linux UFW Firewall Hardening:"]
    for p in open_ports:
        p_num = p["port"] if isinstance(p, dict) else p
        if p_num in [3306, 5432, 6379, 27017, 1433]:
            ufw_commands.append(f"sudo ufw deny {p_num}/tcp  # Restrict public {p.get('service', 'DB')} access")
    ufw_commands.append("sudo ufw allow 80/tcp    # Allow Web HTTP")
    ufw_commands.append("sudo ufw allow 443/tcp   # Allow Web HTTPS")
    ufw_commands.append("sudo ufw enable          # Activate firewall")
    ufw_snippet = "\n".join(ufw_commands)

    return {
        "risk_level": risk,
        "verdict_hi": verdict_hi,
        "verdict_en": verdict_en,
        "findings": findings,
        "nginx_snippet": nginx_snippet,
        "ufw_snippet": ufw_snippet,
        "total_issues": len(findings)
    }

# ================= SAAS PRICING & FULL PAYMENT CHECKOUT =================
@app.route("/pricing")
def pricing():
    user_email = get_current_user_email() if is_logged_in() else None
    subscription = get_user_subscription(user_email)
    return render_template("pricing.html", subscription=subscription)

@app.route("/checkout")
def checkout():
    if not is_logged_in():
        return redirect(url_for("login"))

    plan = request.args.get("plan", "pro").lower()
    cycle = request.args.get("cycle", "monthly").lower()
    
    plan_info = {
        "name": "Pro SecOps",
        "price_monthly": 49,
        "price_annual": 39,
        "amount": "$49" if cycle == "monthly" else "$468",
        "features": [
            "Unlimited Security Audits & Threat Dossiers",
            "Executive PDF & JSON Compliance Reports",
            "24/7 Asset Watchlist (Up to 15 Domains)",
            "Scan Diff & Regression Engine",
            "Developer API Keys & CI/CD Integrations",
            "Slack & Webhook Alerts"
        ]
    }
    if plan == "enterprise":
        plan_info = {
            "name": "Enterprise Sentinel",
            "price_monthly": 199,
            "price_annual": 159,
            "amount": "$199" if cycle == "monthly" else "$1908",
            "features": [
                "Everything in Pro SecOps",
                "Unlimited Monitored Domains & Endpoints",
                "Custom SOC2 & ISO 27001 Threat Mapping",
                "Subdomain Auto-Discovery Reconnaissance",
                "Multi-User Role Based Access (RBAC)",
                "Dedicated 24/7 Cybersecurity Analyst Support"
            ]
        }

    user_email = get_current_user_email()
    return render_template("checkout.html", plan_info=plan_info, plan=plan, cycle=cycle, user_email=user_email)

@app.route("/api/checkout/process", methods=["POST"])
@app.route("/checkout/process", methods=["POST"])
def process_checkout_api():
    if not is_logged_in():
        return jsonify({"success": False, "error": "Authentication required"}), 401

    data = request.get_json() or request.form or {}
    plan_name = data.get("plan_name") or "Pro SecOps"
    billing_cycle = data.get("billing_cycle") or "monthly"
    amount = data.get("amount") or "$49"
    payment_method = data.get("payment_method") or "Credit/Debit Card"
    user_email = get_current_user_email()

    try:
        res = process_subscription_payment(
            user_email=user_email,
            plan_name=plan_name,
            billing_cycle=billing_cycle,
            amount=amount,
            payment_method=payment_method
        )

        # Update Session Plan Badge
        if session.get("user"):
            session["user"]["plan"] = plan_name
        session["plan"] = plan_name

        return jsonify({
            "success": True,
            "transaction_id": res["transaction_id"],
            "plan": plan_name,
            "amount": amount,
            "billing_cycle": billing_cycle,
            "date": res["date"],
            "invoice_url": f"/invoice/{res['transaction_id']}"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/invoice/<transaction_id>")
def view_invoice(transaction_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    user_email = get_current_user_email()
    txn = get_transaction_by_id(transaction_id, user_email)
    if not txn:
        return "Transaction receipt not found or access denied", 404

    return render_template("invoice.html", txn=txn)

@app.route("/docs")
def docs():
    return render_template("docs.html")

# ================= DEVELOPER SETTINGS & API KEYS =================
@app.route("/settings")
def settings():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_email = get_current_user_email()
    api_keys = get_user_api_keys(user_email)
    subscription = get_user_subscription(user_email)
    transactions = get_user_transactions(user_email)
    webhook_config = get_webhook_config(user_email)
    new_token = session.pop("newly_created_token", None)
    return render_template(
        "settings.html",
        api_keys=api_keys,
        subscription=subscription,
        transactions=transactions,
        webhook_config=webhook_config,
        new_token=new_token
    )

@app.route("/settings/api-key/create", methods=["POST"])
def create_api_key():
    if not is_logged_in():
        return redirect(url_for("login"))

    name = request.form.get("name", "Production Key")
    user_email = get_current_user_email()
    key_info = generate_api_key(user_email, name)
    session["newly_created_token"] = key_info["raw_token"]

    return redirect(url_for("settings"))

@app.route("/settings/api-key/revoke/<int:key_id>", methods=["POST", "GET"])
def revoke_key(key_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    user_email = get_current_user_email()
    revoke_api_key(key_id, user_email)
    return redirect(url_for("settings"))

@app.route("/settings/webhook/save", methods=["POST"])
@app.route("/api/webhook/save", methods=["POST"])
@app.route("/webhook/save", methods=["POST"])
def save_user_webhook():
    if not is_logged_in():
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    user_email = get_current_user_email()
    data = request.get_json(silent=True) or request.form
    webhook_url = data.get("webhook_url", "").strip()
    channel_type = data.get("channel_type", "discord")
    alert_level = data.get("alert_level", "High & Critical")
    is_enabled = data.get("is_enabled", "true") in ["true", True, "on", 1]

    saved = save_webhook_config(user_email, webhook_url, channel_type, alert_level, is_enabled)
    if request.is_json:
        return jsonify({"success": saved})
    return redirect(url_for("settings"))

@app.route("/api/webhook/test", methods=["POST"])
@app.route("/webhook/test", methods=["POST"])
def test_user_webhook():
    if not is_logged_in():
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    user_email = get_current_user_email()
    data = request.get_json(silent=True) or request.form
    webhook_url = data.get("webhook_url") or get_webhook_config(user_email).get("webhook_url")

    if not webhook_url:
        return jsonify({"success": False, "error": "No webhook URL configured. Please enter a valid URL."}), 400

    ok, msg = send_webhook_alert(
        webhook_url=webhook_url,
        target_url="https://demo-corp.vulneye.sec",
        risk_level="High",
        findings_summary="Simulated Threat Alert: 3 Missing Security Headers & Insecure Port 8080 detected on target infrastructure.",
        is_test=True
    )
    return jsonify({"success": ok, "message": msg})

# ================= DYNAMIC SVG SECURITY BADGE API =================
@app.route("/api/v1/badge")
@app.route("/badge/<path:domain>")
def generate_security_badge(domain=None):
    target = domain or request.args.get("url") or request.args.get("domain") or "example.com"
    norm_url = normalize_url(target)

    # Fetch cached assessment if available
    cached_scan = get_latest_scan_results(norm_url)
    if cached_scan:
        risk = cached_scan.get("risk", "Medium")
    else:
        risk = "Low" if norm_url.startswith("https") else "Medium"

    if risk == "Low":
        status_text = "Grade A+ (Secure)"
        color_left = "#059669"
        color_right = "#10b981"
    elif risk == "Medium":
        status_text = "Grade B (Warning)"
        color_left = "#d97706"
        color_right = "#f59e0b"
    else:
        status_text = "Grade F (Critical)"
        color_left = "#dc2626"
        color_right = "#ef4444"

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="220" height="26" viewBox="0 0 220 26" fill="none">
  <defs>
    <linearGradient id="bGrad" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#090d16"/>
      <stop offset="100%" stop-color="#151d2f"/>
    </linearGradient>
    <linearGradient id="sGrad" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="{color_left}"/>
      <stop offset="100%" stop-color="{color_right}"/>
    </linearGradient>
  </defs>
  <rect width="84" height="26" rx="6" fill="url(#bGrad)" stroke="#1e293b" stroke-width="1"/>
  <rect x="80" width="140" height="26" rx="6" fill="url(#sGrad)"/>
  <rect x="80" width="4" height="26" fill="url(#bGrad)"/>
  <g fill="#ffffff" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-size="10.5" font-weight="700">
    <text x="8" y="17" fill="#00f0ff">🛡️ VulnEye</text>
    <text x="90" y="17" fill="#ffffff">{status_text}</text>
  </g>
</svg>"""
    resp = make_response(svg)
    resp.headers["Content-Type"] = "image/svg+xml"
    resp.headers["Cache-Control"] = "no-cache, max-age=180"
    return resp

# ================= FREE CYBER TOOLS SUITE =================
@app.route("/tools")
def tools_index():
    return render_template("tools/tools_index.html")

@app.route("/tools/cvss")
def tool_cvss_calculator():
    return render_template("tools/cvss_calculator.html")

@app.route("/tools/ssl-checker", methods=["GET", "POST"])
def tool_ssl_checker():
    result = None
    target = None
    if request.method == "POST":
        target = request.form.get("target")
        if target:
            domain = extract_domain(target)
            result = check_ssl_cert(domain)
    return render_template("tools/ssl_checker.html", result=result, target=target)

@app.route("/tools/headers-checker", methods=["GET", "POST"])
def tool_headers_checker():
    result = None
    target = None
    if request.method == "POST":
        target = request.form.get("target")
        if target:
            url = normalize_url(target)
            result = check_security_headers(url)
    return render_template("tools/headers_checker.html", result=result, target=target)

@app.route("/tools/subdomain-finder", methods=["GET", "POST"])
def tool_subdomain_finder():
    result = None
    target = None
    if request.method == "POST":
        target = request.form.get("target")
        if target:
            result = scan_subdomains(target)
    return render_template("tools/subdomains.html", result=result, target=target)

@app.route("/tools/password-analyzer", methods=["GET", "POST"])
def tool_password_analyzer():
    result = None
    password = None
    if request.method == "POST":
        password = request.form.get("password")
        if password:
            result = analyze_password_strength(password)
    return render_template("tools/password_analyzer.html", result=result, password=password)

# ================= CUSTOM ERROR HANDLERS =================
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500

# ================= EXPORT & PDF DOWNLOAD =================
@app.route("/export/json")
def export_json():
    if not is_logged_in():
        return redirect(url_for("login"))

    url = request.args.get("url")
    if not url:
        return "Missing target URL", 400

    user_email = get_current_user_email()
    results = get_latest_scan_results(url, user_email=user_email)
    if not results:
        results = run_scan(url)

    response = make_response(json.dumps(results, indent=2))
    response.headers["Content-Type"] = "application/json"
    filename = f"vulneye_audit_{urlparse(url).netloc or 'target'}.json"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response

@app.route("/export-pdf", methods=["POST", "GET"])
def export_pdf():
    if not is_logged_in():
        return redirect(url_for("login"))

    url = request.form.get("url") or request.args.get("url")
    if not url:
        return redirect(url_for("home"))

    user_email = get_current_user_email()
    results = get_latest_scan_results(url, user_email=user_email)
    if not results:
        results = run_scan(url)

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=32,
        leftMargin=32,
        topMargin=32,
        bottomMargin=32
    )
    styles = getSampleStyleSheet()
    elements = []

    C_PRIMARY = HexColor("#0f172a")
    C_BG_LIGHT = HexColor("#f8fafc")
    C_BORDER = HexColor("#e2e8f0")
    C_TEXT_MUTED = HexColor("#64748b")
    C_SUCCESS = HexColor("#059669")
    C_WARNING = HexColor("#d97706")
    C_DANGER = HexColor("#dc2626")

    hdr_title = ParagraphStyle('HeaderTitle', fontName='Helvetica-Bold', fontSize=15, leading=18, textColor=colors.white)
    hdr_subtitle = ParagraphStyle('HeaderSubtitle', fontName='Helvetica', fontSize=8.5, leading=11, textColor=HexColor("#93c5fd"))
    doc_title = ParagraphStyle('DocTitle', fontName='Helvetica-Bold', fontSize=20, leading=24, textColor=C_PRIMARY, spaceAfter=4)
    doc_meta = ParagraphStyle('DocMeta', fontName='Helvetica', fontSize=8.5, leading=12, textColor=C_TEXT_MUTED, spaceAfter=12)
    sec_title = ParagraphStyle('SecTitle', fontName='Helvetica-Bold', fontSize=11, leading=14, textColor=C_PRIMARY, spaceBefore=12, spaceAfter=6)
    th_style = ParagraphStyle('TH', fontName='Helvetica-Bold', fontSize=8, leading=10, textColor=colors.white)
    td_style = ParagraphStyle('TD', fontName='Helvetica', fontSize=8, leading=11, textColor=HexColor("#334155"))

    hdr_content = [
        [
            Paragraph("<b>🛡️ VULNEYE CYBER SENTINEL</b>", hdr_title),
            Paragraph(f"AUDIT ID: #{results.get('id', 'LIVE')}<br/>SECURITY ASSESSMENT DOSSIER", ParagraphStyle('HdrRight', parent=hdr_subtitle, alignment=TA_RIGHT))
        ],
        [
            Paragraph("Automated Vulnerability Intelligence & Attack Surface Audit", hdr_subtitle),
            Paragraph("CONFIDENTIAL & PROPRIETARY", ParagraphStyle('HdrConf', parent=hdr_subtitle, fontName='Helvetica-Bold', alignment=TA_RIGHT, textColor=HexColor("#fca5a5")))
        ]
    ]
    hdr_table = Table(hdr_content, colWidths=[330, 201])
    hdr_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), C_PRIMARY),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 14),
        ('RIGHTPADDING', (0, 0), (-1, -1), 14),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(hdr_table)
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Security Evaluation & Threat Surface Report", doc_title))
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    host_ip = results.get("host_info", {}).get("ip", "N/A")
    reverse_dns = results.get("host_info", {}).get("reverse_dns", "None")
    
    meta_text = f"<b>Target URL:</b> <font color='#0284c7'>{results.get('url')}</font> &nbsp;|&nbsp; <b>Resolved IP:</b> {host_ip} ({reverse_dns}) &nbsp;|&nbsp; <b>Generated:</b> {timestamp}"
    elements.append(Paragraph(meta_text, doc_meta))

    risk = results.get("risk", "Unknown")
    grade = "A+" if risk == "Low" else ("B" if risk == "Medium" else "F")
    risk_color = C_SUCCESS if risk == "Low" else (C_WARNING if risk == "Medium" else C_DANGER)
    risk_bg = HexColor("#d1fae5") if risk == "Low" else (HexColor("#fef3c7") if risk == "Medium" else HexColor("#fee2e2"))

    ssl_data = results.get("ssl_certificate", {})
    ssl_status_text = "Valid" if ssl_data.get("valid") else ("Expired" if ssl_data.get("expired") else ("Inactive" if not results.get("https") else "Warning"))

    open_ports_cnt = len(results.get("open_ports", []))
    leaks_cnt = len(results.get("sensitive_files", []))
    missing_hdrs_cnt = len(results.get("missing_headers", []))

    card1_cell = [
        Paragraph("<font size=7 color='#64748b'><b>HOST AVAILABILITY</b></font>", td_style),
        Paragraph(f"<b>{'ONLINE (200)' if results.get('reachable') else 'OFFLINE'}</b>", ParagraphStyle('C1', fontName='Helvetica-Bold', fontSize=10, textColor=C_SUCCESS if results.get('reachable') else C_DANGER)),
        Paragraph(f"<font size=7 color='#64748b'>HTTP Status: {results.get('status_code', 'N/A')}</font>", td_style)
    ]
    card2_cell = [
        Paragraph("<font size=7 color='#64748b'><b>TRANSPORT SECURITY</b></font>", td_style),
        Paragraph(f"<b>{ssl_status_text.upper()}</b>", ParagraphStyle('C2', fontName='Helvetica-Bold', fontSize=10, textColor=C_SUCCESS if ssl_data.get('valid') else C_DANGER)),
        Paragraph(f"<font size=7 color='#64748b'>TLS: {ssl_data.get('protocol_version', 'N/A')}</font>", td_style)
    ]
    card3_cell = [
        Paragraph("<font size=7 color='#64748b'><b>IDENTIFIED RISKS</b></font>", td_style),
        Paragraph(f"<b>{open_ports_cnt + leaks_cnt + missing_hdrs_cnt} FLAGGED</b>", ParagraphStyle('C3', fontName='Helvetica-Bold', fontSize=10, textColor=C_WARNING if (open_ports_cnt + leaks_cnt) > 0 else C_SUCCESS)),
        Paragraph(f"<font size=7 color='#64748b'>{open_ports_cnt} Ports | {leaks_cnt} Leaks</font>", td_style)
    ]
    card4_cell = [
        Paragraph("<font size=7 color='#64748b'><b>SECURITY RATING</b></font>", td_style),
        Paragraph(f"<b>GRADE {grade} ({risk.upper()})</b>", ParagraphStyle('C4', fontName='Helvetica-Bold', fontSize=10, textColor=risk_color)),
        Paragraph(f"<font size=7 color='#64748b'>Overall Threat Level</font>", td_style)
    ]

    kpi_table = Table([[card1_cell, card2_cell, card3_cell, card4_cell]], colWidths=[130, 130, 130, 141])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (2, 0), C_BG_LIGHT),
        ('BACKGROUND', (3, 0), (3, 0), risk_bg),
        ('BOX', (0, 0), (-1, -1), 0.75, C_BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, C_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(kpi_table)
    elements.append(Spacer(1, 10))

    def build_domain_table(headers, rows_data, widths):
        table_content = [[Paragraph(f"<b>{h}</b>", th_style) for h in headers]]
        for row in rows_data:
            formatted_row = []
            for cell in row:
                if isinstance(cell, str):
                    formatted_row.append(Paragraph(cell, td_style))
                else:
                    formatted_row.append(cell)
            table_content.append(formatted_row)

        t = Table(table_content, colWidths=widths)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), C_PRIMARY),
            ('GRID', (0, 0), (-1, -1), 0.5, C_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
        ]))
        return t

    # Domain 1
    elements.append(Paragraph("<b>1. Cryptographic Transport & TLS Certificate</b>", sec_title))
    if results.get("https") and ssl_data:
        days = ssl_data.get("days_remaining", 0)
        days_color = "#059669" if days > 30 else "#dc2626"
        tls_rows = [
            ["Certificate Issuer", ssl_data.get("issuer", "Unknown"), "Status", f"<font color='{days_color}'><b>{'VALID' if ssl_data.get('valid') else 'EXPIRED'}</b></font>"],
            ["TLS Protocol Version", ssl_data.get("protocol_version", "TLSv1.3"), "Days Remaining", f"<font color='{days_color}'><b>{days} days</b></font>"],
            ["Certificate Subject", ssl_data.get("subject", "Target Domain"), "Expiry Date", ssl_data.get("expiry_date", "N/A")]
        ]
        elements.append(build_domain_table(["TLS Property", "Audited Valuation", "Certificate Metric", "Status Valuation"], tls_rows, [140, 150, 110, 131]))
    else:
        elements.append(Paragraph("<font color='#dc2626'>⚠️ <b>Insecure Transport:</b> Target website does not serve HTTPS encryption or has an invalid SSL certificate.</font>", td_style))
    elements.append(Spacer(1, 8))

    # Domain 2
    elements.append(Paragraph("<b>2. OWASP Security Defense Headers Audit</b>", sec_title))
    hdr_checks = [
        ("Strict-Transport-Security (HSTS)", "Enforces HTTPS connections and prevents SSL stripping.", "Strict-Transport-Security"),
        ("Content-Security-Policy (CSP)", "Prevents Cross-Site Scripting (XSS) and code injection.", "Content-Security-Policy"),
        ("X-Frame-Options", "Protects against UI Redressing & Clickjacking attacks.", "X-Frame-Options"),
        ("X-Content-Type-Options", "Stops MIME-type sniffing vulnerabilities.", "X-Content-Type-Options"),
        ("Referrer-Policy", "Controls confidential URL leakage in Referer header.", "Referrer-Policy"),
        ("Permissions-Policy", "Restricts browser API access (Camera, Geolocation).", "Permissions-Policy")
    ]
    missing_list = results.get("missing_headers", [])
    hdr_rows = []
    for name, desc, key in hdr_checks:
        if key in missing_list:
            hdr_rows.append([name, desc, "<font color='#dc2626'><b>MISSING</b></font>"])
        else:
            hdr_rows.append([name, desc, "<font color='#059669'><b>ENFORCED ✓</b></font>"])
    elements.append(build_domain_table(["Security Defense Header", "Vulnerability Impact / Description", "Compliance"], hdr_rows, [160, 270, 101]))
    elements.append(Spacer(1, 8))

    # Domain 3
    elements.append(Paragraph("<b>3. Sensitive Files & Dotfile Exposure</b>", sec_title))
    leaks = results.get("sensitive_files", [])
    if leaks:
        leak_rows = []
        for l in leaks:
            sev_color = "#dc2626" if l["severity"] == "High" else "#d97706"
            leak_rows.append([
                f"<code>{l['file']}</code>",
                f"<font color='{sev_color}'><b>{l['severity'].upper()}</b></font>",
                f"HTTP {l['status']}",
                l['description']
            ])
        elements.append(build_domain_table(["Exposed Path", "Severity", "Status", "Risk Implication"], leak_rows, [110, 70, 70, 281]))
    else:
        elements.append(Paragraph("<font color='#059669'>✓ <b>Protected:</b> Zero sensitive dotfiles (.env, .git) or backup archives exposed.</font>", td_style))
    elements.append(Spacer(1, 8))

    # Domain 4
    elements.append(Paragraph("<b>4. Attack Surface: Exposed Services & Ports</b>", sec_title))
    ports = results.get("open_ports", [])
    if ports:
        port_rows = []
        for p in ports:
            p_num = p["port"] if isinstance(p, dict) else p
            p_srv = p["service"] if isinstance(p, dict) else "TCP Service"
            risk_desc = "Critical - Restrict to Private VPC" if p_num in [3306, 5432, 6379, 27017, 1433] else ("High - Ensure Strong SSH keys" if p_num == 22 else "Standard Web Traffic")
            port_rows.append([f"Port {p_num}/TCP", p_srv, "<font color='#dc2626'><b>OPEN</b></font>", risk_desc])
        elements.append(build_domain_table(["Port / Protocol", "Service Identification", "Exposure State", "Security Guideline"], port_rows, [100, 140, 90, 201]))
    else:
        elements.append(Paragraph("<font color='#059669'>✓ <b>Hardened:</b> No non-standard or database ports publicly exposed.</font>", td_style))
    elements.append(Spacer(1, 8))

    # Domain 5
    elements.append(Paragraph("<b>5. Session Cookies, CORS & Technology Footprint</b>", sec_title))
    tech_str = ", ".join(results.get("tech_stack", [])) or "Standard Web Application"
    cors_info = results.get("cors", {})
    cors_str = "Restricted & Secure" if not cors_info.get("misconfigured") else f"⚠️ {cors_info.get('risk_details')}"

    misc_rows = [
        ["Technology Fingerprint", tech_str],
        ["Cross-Origin Resource Sharing (CORS)", cors_str],
        ["Interactive Web Forms", f"{len(results.get('forms', []))} form entry points analyzed"]
    ]
    elements.append(build_domain_table(["Audited Dimension", "Findings & Configuration State"], misc_rows, [170, 361]))
    elements.append(Spacer(1, 10))

    # Remediation
    remediation_box_data = [
        [Paragraph("<b>💡 ACTIONABLE REMEDIATION & SECURITY ROADMAP</b>", ParagraphStyle('RemHdr', fontName='Helvetica-Bold', fontSize=9, textColor=HexColor("#0369a1")))],
        [Paragraph(
            "• <b>Security Headers:</b> Add <code>Header set X-Frame-Options 'DENY'</code> and <code>Header set X-Content-Type-Options 'nosniff'</code> in your web server configuration.<br/>"
            "• <b>Block Dotfiles:</b> In Nginx, add <code>location ~ /\\.(?!well-known) { deny all; }</code> to block access to <code>.env</code> and <code>.git</code> directories.<br/>"
            "• <b>Firewall Hardening:</b> Restrict open database ports (3306, 5432, 6379) to localhost using <code>ufw default deny incoming</code>.<br/>"
            "• <b>Cookies & CORS:</b> Ensure all session cookies have <code>Secure; HttpOnly; SameSite=Lax</code> and avoid wildcard CORS origins.",
            ParagraphStyle('RemBody', parent=td_style, fontSize=7.5, leading=11, textColor=HexColor("#334155"))
        )]
    ]
    rem_table = Table(remediation_box_data, colWidths=[531])
    rem_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), HexColor("#f0f9ff")),
        ('BOX', (0, 0), (-1, -1), 1, HexColor("#0284c7")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    elements.append(rem_table)
    elements.append(Spacer(1, 10))

    disclaimer_style = ParagraphStyle('DisclaimerText', fontName='Helvetica', fontSize=7, leading=9, textColor=HexColor('#94a3b8'), alignment=TA_CENTER)
    elements.append(Paragraph("This automated security dossier was generated by VulnEye Cyber Sentinel. Built in alignment with OWASP & CIS Benchmarks. Scan responsibly.", disclaimer_style))

    doc.build(elements)
    buffer.seek(0)

    response = make_response(buffer.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    target_clean = urlparse(url).netloc.replace(":", "_") or "target"
    response.headers["Content-Disposition"] = f"attachment; filename=vulneye_audit_{target_clean}.pdf"
    return response

# ================= REST API V1 (WITH API KEY SUPPORT) =================
@app.route("/api/v1/health")
@app.route("/v1/health")
def api_health():
    return jsonify({
        "status": "online",
        "service": "VulnEye CyberSentinel API v1",
        "timestamp": datetime.datetime.utcnow().isoformat()
    })

@app.route("/api/v1/scan", methods=["POST", "GET"])
@app.route("/v1/scan", methods=["POST", "GET"])
def api_scan():
    auth_header = request.headers.get("Authorization")
    api_user = verify_api_key(auth_header)
    
    if not api_user and not is_logged_in():
        return jsonify({"error": "Unauthorized. Provide a valid Bearer API key in Authorization header."}), 401

    user_email = api_user or get_current_user_email()

    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        url = data.get("url") if data else None
    else:
        url = request.args.get("url")

    if not url:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    results = run_scan(url)
    save_scan(results, user_email=user_email)

    return jsonify({
        "status": "success",
        "target": url,
        "audit_data": results
    })

@app.route("/api/v1/history")
@app.route("/v1/history")
def api_history():
    auth_header = request.headers.get("Authorization")
    api_user = verify_api_key(auth_header)
    
    if not api_user and not is_logged_in():
        return jsonify({"error": "Unauthorized. Provide a valid Bearer API key in Authorization header."}), 401

    user_email = api_user or get_current_user_email()
    scans = get_all_scans(user_email=user_email)
    
    formatted = []
    for s in scans:
        formatted.append({
            "id": s[0],
            "url": s[1],
            "scan_time": s[2],
            "reachable": s[3],
            "status_code": s[4],
            "https": s[5],
            "risk": s[6],
            "user_email": s[7]
        })

    return jsonify({
        "status": "success",
        "count": len(formatted),
        "history": formatted
    })

if __name__ == "__main__":
    app.run(debug=True)
