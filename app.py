from flask import Flask, render_template, request, redirect, url_for, session, make_response
from scanner import run_scan
from database import init_db, save_scan, get_all_scans
from reportlab.pdfgen import canvas
from io import BytesIO
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4


app = Flask(__name__)
app.secret_key = "supersecretkey123"   # demo purpose only

# Initialize DB
init_db()

# Demo login credentials
USERNAME = "admin"
PASSWORD = "admin123"

def is_logged_in():
    return session.get("logged_in")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == USERNAME and password == PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("home"))
        else:
            return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")

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
    results = run_scan(url)

    save_scan(results)

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
    doc = SimpleDocTemplate(buffer, pagesize=A4)

    styles = getSampleStyleSheet()
    elements = []

    # ===== TITLE =====
    title = Paragraph("<b> VulnEye Security Report</b>", styles[ 'Title'])
    elements.append(title)
    elements.append(Spacer(1, 10))

    # ===== SUMMARY TABLE =====
    summary_data = [
        ["URL", results['url']],
        ["Reachable", str(results['reachable'])],
        ["HTTPS", str(results['https'])],
        ["Status Code", str(results['status_code'])],
    ]

    summary_table = Table(summary_data, colWidths=[150, 300])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 15))

    # ===== RISK BADGE =====
    risk = results["risk"]

    if risk == "Low":
        risk_color = colors.green
    elif risk == "Medium":
        risk_color = colors.orange  
    else:
        risk_color = colors.red

    risk_table = Table([[f"Risk Level: {risk}"]], colWidths=[200])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), risk_color),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('BOX', (0, 0), (-1, -1), 1, colors.black)
    ]))

    elements.append(risk_table)
    elements.append(Spacer(1, 20))

    # ===== FUNCTION =====
    def create_section(title, items):
        elements.append(Paragraph(f"<b>{title}</b>", styles['Heading2']))
        elements.append(Spacer(1, 8))

        if items:
            data = [[str(i)] for i in items]
        else:
            data = [["None"]]

        table = Table(data, colWidths=[450])
        table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
            ('BACKGROUND', (0, 0), (-1, -1), colors.whitesmoke),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 15))

    # ===== SECTIONS =====
    create_section(" Missing Security Headers", results["missing_headers"])
    create_section(" Open Ports", results["open_ports"])
    create_section(" Found Directories", results["found_directories"])

    # Forms
    forms = []
    for f in results["forms"]:
        forms.append(f"{f['method']} {f['action']} (Inputs: {f['input_count']})")

    create_section(" Detected Forms", forms)

    # ===== VULNERABILITIES =====
    vulnerabilities = []

    if not results["https"]:
        vulnerabilities.append("No HTTPS encryption (High Risk)")

    if results["missing_headers"]:
        vulnerabilities.append("Missing security headers")

    if 80 in results["open_ports"]:
        vulnerabilities.append("Port 80 open (HTTP insecure)")

    # create_section(" Vulnerabilities Summary", vulnerabilities)

    

    # ===== BUILD =====
    doc.build(elements)

    buffer.seek(0)

    response = make_response(buffer.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=vulneye_report.pdf"

    return response
    

if __name__ == "__main__":
    app.run(debug=True)