import requests
import socket
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

def normalize_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url

def check_status(url):
    try:
        response = requests.get(url, timeout=5)
        return {
            "reachable": True,
            "status_code": response.status_code
        }
    except:
        return {
            "reachable": False,
            "status_code": None
        }

def check_https(url):
    return url.startswith("https://")

def check_security_headers(url):
    required_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security"
    ]

    missing_headers = []

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        for header in required_headers:
            if header not in headers:
                missing_headers.append(header)

        return missing_headers
    except:
        return required_headers

def scan_ports(host):
    # Extended Port Scan (safe + practical for minor project)
    common_ports = [
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80,
        110, 123, 135, 137, 138, 139, 143, 161, 389, 443,
        445, 465, 587, 993, 995, 1433, 1521, 2049, 3306, 3389,
        5432, 5900, 6379, 8080, 8443, 9000
    ]

    open_ports = []

    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass

    return open_ports

def scan_directories(url):
    common_dirs = ["admin", "login", "dashboard", "backup", "uploads", "config", "test"]
    found_dirs = []

    for directory in common_dirs:
        test_url = urljoin(url + "/", directory)
        try:
            response = requests.get(test_url, timeout=3)
            if response.status_code == 200:
                found_dirs.append("/" + directory)
        except:
            pass

    return found_dirs

def detect_forms(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        form_details = []
        for form in forms:
            action = form.get("action", "N/A")
            method = form.get("method", "GET").upper()
            inputs = form.find_all("input")

            form_details.append({
                "action": action,
                "method": method,
                "input_count": len(inputs)
            })

        return form_details
    except:
        return []

def calculate_risk(results):
    score = 0

    if not results["https"]:
        score += 2

    score += len(results["missing_headers"])

    if len(results["open_ports"]) > 10:
        score += 3
    elif len(results["open_ports"]) > 5:
        score += 2
    elif len(results["open_ports"]) > 1:
        score += 1

    if len(results["found_directories"]) > 0:
        score += 2

    if len(results["forms"]) > 0:
        score += 1

    if score <= 3:
        return "Low"
    elif score <= 7:
        return "Medium"
    else:
        return "High"

def run_scan(url):
    url = normalize_url(url)
    status = check_status(url)

    if not status["reachable"]:
        return {
            "url": url,
            "reachable": False,
            "status_code": None,
            "https": False,
            "missing_headers": [],
            "open_ports": [],
            "found_directories": [],
            "forms": [],
            "risk": "Unknown"
        }

    parsed = urlparse(url)
    host = parsed.netloc

    results = {
        "url": url,
        "reachable": True,
        "status_code": status["status_code"],
        "https": check_https(url),
        "missing_headers": check_security_headers(url),
        "open_ports": scan_ports(host),
        "found_directories": scan_directories(url),
        "forms": detect_forms(url)
    }

    results["risk"] = calculate_risk(results)
    return results