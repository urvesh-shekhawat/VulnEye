import os
import sys

# Add parent directory to sys.path so modules like scanner and database can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, redirect, url_for, session, make_response, Response
from scanner import run_scan
from database import init_db, save_scan, get_all_scans
from reportlab.pdfgen import canvas
from io import BytesIO
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth

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

@app.route("/login")
def login():
    if is_logged_in():
        return redirect(url_for("home"))
    
    # Check if Google OAuth is configured, if not, show a warning on the login page
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    
    warning = None
    if not client_id or not client_secret:
        warning = "Google OAuth credentials are not configured in your environment. Please copy .env.example to .env and configure them."
        
    return render_template("login.html", warning=warning)

@app.route("/login/google")
def login_google():
    redirect_uri = url_for("authorize", _external=True)
    # Automatically force HTTPS if running in Vercel's proxy environment
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
            return redirect(url_for("home"))
    except Exception as e:
        return render_template("login.html", error=f"Google Authentication failed: {str(e)}")
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
def home():
    if not is_logged_in():
        return redirect(url_for("login"))
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    if not is_logged_in():
        return redirect(url_for("login"))

    url = request.form.get("url")
    return render_template("scan_progress.html", url=url)

@app.route("/scan/stream")
def scan_stream():
    if not is_logged_in():
        return "Unauthorized", 401

    url = request.args.get("url")
    if not url:
        return "Missing URL", 400

    def generate_stream():
        import json
        import time
        from scanner import normalize_url, check_status, check_https, check_security_headers, scan_ports, scan_directories, detect_forms, calculate_risk
        from urllib.parse import urlparse

        # 1. Starting
        yield f"data: {json.dumps({'status': 'starting', 'message': 'Initializing VulnEye scanner...'})}\n\n"
        time.sleep(0.4)

        url_normalized = normalize_url(url)

        # 2. Reachability
        yield f"data: {json.dumps({'status': 'reachable', 'message': 'Analyzing host reachability and status code...'})}\n\n"
        status = check_status(url_normalized)

        if not status["reachable"]:
            results = {
                "url": url_normalized,
                "reachable": False,
                "status_code": None,
                "https": False,
                "missing_headers": [],
                "open_ports": [],
                "found_directories": [],
                "forms": [],
                "risk": "Unknown"
            }
            save_scan(results)
            session['last_scan'] = results
            yield f"data: {json.dumps({'status': 'done', 'redirect': url_for('result', url=url_normalized)})}\n\n"
            return

        parsed = urlparse(url_normalized)
        host = parsed.netloc

        # 3. SSL Check
        yield f"data: {json.dumps({'status': 'ssl', 'message': 'Auditing TLS/HTTPS encryption configuration...'})}\n\n"
        https_status = check_https(url_normalized)
        time.sleep(0.3)

        # 4. Headers Check
        yield f"data: {json.dumps({'status': 'headers', 'message': 'Testing missing HTTP defense headers...'})}\n\n"
        missing_headers = check_security_headers(url_normalized)
        time.sleep(0.3)

        # 5. Port Scan
        yield f"data: {json.dumps({'status': 'ports', 'message': 'Scanning common external service ports...'})}\n\n"
        open_ports = scan_ports(host)

        # 6. Directories Scan
        yield f"data: {json.dumps({'status': 'dirs', 'message': 'Probing directory index for administrative entry points...'})}\n\n"
        found_directories = scan_directories(url_normalized)

        # 7. Forms Extraction
        yield f"data: {json.dumps({'status': 'forms', 'message': 'Scanning forms and parsing form inputs...'})}\n\n"
        forms = detect_forms(url_normalized)
        time.sleep(0.2)

        # Compilation
        yield f"data: {json.dumps({'status': 'saving', 'message': 'Compiling risk matrices and saving logs...'})}\n\n"
        results = {
            "url": url_normalized,
            "reachable": True,
            "status_code": status["status_code"],
            "https": https_status,
            "missing_headers": missing_headers,
            "open_ports": open_ports,
            "found_directories": found_directories,
            "forms": forms
        }
        results["risk"] = calculate_risk(results)

        save_scan(results)
        session['last_scan'] = results
        time.sleep(0.5)

        # Done Redirect
        yield f"data: {json.dumps({'status': 'done', 'redirect': url_for('result', url=url_normalized)})}\n\n"

    # Set response mime-type to text/event-stream
    return Response(generate_stream(), mimetype='text/event-stream')

@app.route("/result")
def result():
    if not is_logged_in():
        return redirect(url_for("login"))

    url = request.args.get("url")
    if not url:
        return redirect(url_for("home"))

    results = session.get('last_scan')
    if not results or results.get('url') != url:
        # Fallback to dynamic re-run if session cache is wiped
        from scanner import run_scan
        results = run_scan(url)
        session['last_scan'] = results

    return render_template("result.html", results=results)

@app.route("/history")
def history():
    if not is_logged_in():
        return redirect(url_for("login"))

    scans = get_all_scans()
    return render_template("history.html", scans=scans)

@app.route("/export-pdf", methods=["POST"])
def export_pdf():
    if not is_logged_in():
        return redirect(url_for("login"))

    url = request.form.get("url")
    results = run_scan(url)

    buffer = BytesIO()
    
    # 40pt margins for a clean grid layout
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)

    styles = getSampleStyleSheet()
    elements = []

    # ===== CUSTOM PREMIUM STYLES =====
    title_style = ParagraphStyle(
        'PremiumTitle',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=30,
        textColor=HexColor('#0f172a'),
        alignment=TA_LEFT,
        spaceAfter=6
    )
    
    meta_style = ParagraphStyle(
        'PremiumMeta',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=HexColor('#64748b'),
        spaceAfter=20
    )
    
    section_style = ParagraphStyle(
        'PremiumSectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=HexColor('#0f172a'),
        spaceBefore=14,
        spaceAfter=10
    )
    
    th_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=12,
        textColor=colors.white
    )
    
    td_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=HexColor('#334155')
    )

    td_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=13,
        textColor=HexColor('#0f172a')
    )

    # ===== TOP ACCENT BANNER =====
    banner_data = [[Paragraph("<b>🛡️ VULNEYE SECURITY AUDIT REPORT</b>", ParagraphStyle('BannerText', fontName='Helvetica-Bold', fontSize=10, textColor=colors.white))]]
    banner_table = Table(banner_data, colWidths=[515])
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), HexColor('#2563eb')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ]))
    elements.append(banner_table)
    elements.append(Spacer(1, 15))

    # ===== TITLE & METADATA =====
    elements.append(Paragraph("Security Assessment Report", title_style))
    
    import datetime
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Using Paragraph wrapper for long URLs to auto-wrap cleanly
    elements.append(Paragraph(f"<b>Target URL:</b> {results['url']} &nbsp;&nbsp;|&nbsp;&nbsp; <b>Audit Date:</b> {timestamp}", meta_style))

    # ===== SUMMARY TABLE =====
    # Auto-wrap cells in Paragraph
    summary_data = [
        [Paragraph("Metric Description", th_style), Paragraph("Identified Valuation", th_style)],
        [Paragraph("Reachable State", td_bold), Paragraph("Yes (Online)" if results['reachable'] else "No (Offline)", td_style)],
        [Paragraph("HTTP Status Code", td_bold), Paragraph(str(results['status_code']) if results['status_code'] else "N/A", td_style)],
        [Paragraph("TLS/HTTPS Encryption", td_bold), Paragraph("Enabled (Secure)" if results['https'] else "Disabled (Insecure)", td_style)],
    ]

    summary_table = Table(summary_data, colWidths=[180, 335])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0f172a')),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cbd5e1')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, HexColor('#f8fafc')]),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 15))

    # ===== PREMIUM RISK SEVERITY BADGE =====
    risk = results["risk"]
    if risk == "Low":
        risk_bg = HexColor("#d1fae5")
        risk_border = HexColor("#10b981")
        risk_text_color = HexColor("#065f46")
    elif risk == "Medium":
        risk_bg = HexColor("#fef3c7")
        risk_border = HexColor("#f59e0b")
        risk_text_color = HexColor("#92400e")
    else:
        risk_bg = HexColor("#fee2e2")
        risk_border = HexColor("#ef4444")
        risk_text_color = HexColor("#991b1b")

    risk_p_style = ParagraphStyle(
        'RiskText',
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=14,
        textColor=risk_text_color,
        alignment=TA_CENTER
    )

    risk_cell = [[Paragraph(f"AUDITED AGGREGATED RISK: {risk.upper()}", risk_p_style)]]
    risk_table = Table(risk_cell, colWidths=[515])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), risk_bg),
        ('BOX', (0, 0), (-1, -1), 1, risk_border),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    elements.append(risk_table)
    elements.append(Spacer(1, 15))

    # ===== FUNCTION FOR SECTIONS =====
    def create_section(title, items):
        elements.append(Paragraph(f"<b>{title}</b>", section_style))

        table_data = []
        if items:
            for item in items:
                # Wrap item in Paragraph to enable multi-line wrapping in table cell
                table_data.append([Paragraph(f"<font color='#2563eb'>•</font> {item}", td_style)])
        else:
            table_data.append([Paragraph("✓ No exposures identified in this section.", ParagraphStyle('NoExp', parent=td_style, fontName='Helvetica-Bold', textColor=HexColor('#10b981')))])

        sec_table = Table(table_data, colWidths=[515])
        sec_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 14),
        ]))
        elements.append(sec_table)
        elements.append(Spacer(1, 10))

    # ===== SECTIONS =====
    create_section("Missing Security Headers", results["missing_headers"])
    create_section("Open Services & Ports", results["open_ports"])
    create_section("Accessible Generic Directories", results["found_directories"])

    # Forms
    forms = []
    for f in results["forms"]:
        forms.append(f"{f['method']} {f['action']} (Inputs: {f['input_count']})")
    create_section("Detected Interactive Forms", forms)

    # ===== WATERMARK FOOTER =====
    disclaimer_style = ParagraphStyle(
        'DisclaimerText',
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=HexColor('#94a3b8'),
        alignment=TA_CENTER,
        spaceBefore=25
    )
    elements.append(Paragraph("This automated security assessment was securely generated by VulnEye. Scan responsibly.", disclaimer_style))

    # ===== BUILD =====
    doc.build(elements)

    buffer.seek(0)

    response = make_response(buffer.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=vulneye_report.pdf"

    return response

if __name__ == "__main__":
    app.run(debug=True)
