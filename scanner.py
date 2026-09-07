import socket
import ssl
import ipaddress
import datetime
import math
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= 1. NORMALIZATION & SSRF DEFENSE =================
def normalize_url(url):
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url

def extract_domain(url_or_host):
    url_clean = normalize_url(url_or_host)
    parsed = urlparse(url_clean)
    host = parsed.netloc or parsed.path
    return host.split(":")[0].strip("/")

def is_safe_target(host):
    """
    Prevent Server-Side Request Forgery (SSRF) against private networks and loopback interfaces.
    """
    if not host:
        return False, "Target host cannot be empty."
    
    clean_host = host.split(":")[0]

    try:
        ip_str = socket.gethostbyname(clean_host)
        ip = ipaddress.ip_address(ip_str)

        if ip.is_loopback:
            return False, f"Scanning loopback address ({ip_str}) is prohibited."
        if ip.is_private:
            return False, f"Scanning internal/private network ({ip_str}) is prohibited."
        if ip.is_link_local:
            return False, f"Scanning link-local address ({ip_str}) is prohibited."
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return False, f"Scanning reserved or multicast address ({ip_str}) is prohibited."
        
        return True, ip_str
    except socket.gaierror:
        return False, f"Could not resolve host: {clean_host}"
    except Exception as e:
        return False, str(e)

# ================= 2. NETWORK RESOLUTION & TELEMETRY =================
def resolve_host_info(host):
    clean_host = host.split(":")[0]
    info = {
        "ip": "Unknown",
        "reverse_dns": "None",
        "safe": True,
        "message": ""
    }
    is_safe, res = is_safe_target(clean_host)
    if not is_safe:
        info["safe"] = False
        info["message"] = res
        return info

    info["ip"] = res
    try:
        reverse_name, _, _ = socket.gethostbyaddr(res)
        info["reverse_dns"] = reverse_name
    except Exception:
        info["reverse_dns"] = "No PTR Record"

    return info

def check_status(url):
    try:
        headers = {"User-Agent": "VulnEye-Security-Scanner/2.0 (Security Sentinel)"}
        response = requests.get(url, headers=headers, timeout=6, allow_redirects=True)
        return {
            "reachable": True,
            "status_code": response.status_code,
            "final_url": response.url,
            "response": response
        }
    except Exception as e:
        return {
            "reachable": False,
            "status_code": None,
            "error": str(e)
        }

def check_https(url):
    return url.lower().startswith("https://")

# ================= 3. SSL / TLS CERTIFICATE AUDIT =================
def check_ssl_cert(host, port=443):
    clean_host = host.split(":")[0]
    cert_info = {
        "valid": False,
        "issuer": "N/A",
        "subject": "N/A",
        "expiry_date": "N/A",
        "days_remaining": 0,
        "protocol_version": "N/A",
        "expired": False,
        "grade": "F"
    }

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((clean_host, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
                cert_info["protocol_version"] = ssock.version()
                
                issuer_dict = dict(x[0] for x in cert.get('issuer', ()))
                cert_info["issuer"] = issuer_dict.get('organizationName') or issuer_dict.get('commonName', 'Unknown')

                subject_dict = dict(x[0] for x in cert.get('subject', ()))
                cert_info["subject"] = subject_dict.get('commonName', clean_host)

                not_after_str = cert.get('notAfter')
                if not_after_str:
                    expiry_dt = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    cert_info["expiry_date"] = expiry_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                    
                    days_left = (expiry_dt - datetime.datetime.utcnow()).days
                    cert_info["days_remaining"] = days_left
                    cert_info["expired"] = days_left <= 0
                    cert_info["valid"] = days_left > 0

                    if days_left > 30 and cert_info["valid"]:
                        cert_info["grade"] = "A+"
                    elif days_left > 0 and cert_info["valid"]:
                        cert_info["grade"] = "B"
                    else:
                        cert_info["grade"] = "F"
    except Exception as e:
        cert_info["error"] = str(e)

    return cert_info

# ================= 4. SECURITY DEFENSE HEADERS =================
def check_security_headers(url_or_response):
    required_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    missing_headers = []
    present_headers = {}

    try:
        if isinstance(url_or_response, requests.Response):
            headers = url_or_response.headers
        else:
            headers = requests.get(url_or_response, headers={"User-Agent": "VulnEye-Scanner"}, timeout=5).headers

        for header in required_headers:
            if header not in headers:
                missing_headers.append(header)
            else:
                present_headers[header] = headers[header]

        score = int(((len(required_headers) - len(missing_headers)) / len(required_headers)) * 100)
        grade = "A+" if score >= 80 else ("B" if score >= 50 else "F")

        return {
            "missing": missing_headers,
            "present": present_headers,
            "score": score,
            "grade": grade
        }
    except Exception:
        return {
            "missing": required_headers,
            "present": {},
            "score": 0,
            "grade": "F"
        }

# ================= 5. HIGH-SPEED PORT SCANNER =================
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Proxy/Alt", 8443: "HTTPS-Alt", 9000: "SonarQube/FastCGI", 9200: "Elasticsearch",
    27017: "MongoDB"
}

def _scan_single_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.6)
            result = sock.connect_ex((host, port))
            if result == 0:
                service = PORT_SERVICES.get(port, "Unknown")
                return {"port": port, "service": service}
    except Exception:
        pass
    return None

def scan_ports(host):
    clean_host = host.split(":")[0]
    ports_to_scan = list(PORT_SERVICES.keys())
    open_ports = []

    with ThreadPoolExecutor(max_workers=25) as executor:
        futures = [executor.submit(_scan_single_port, clean_host, port) for port in ports_to_scan]
        for future in as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)

    open_ports.sort(key=lambda x: x["port"])
    return open_ports

# ================= 6. DIRECTORY & SENSITIVE FILE PROBES =================
COMMON_DIRS = [
    "admin", "login", "dashboard", "backup", "uploads",
    "config", "test", "api", "phpmyadmin", "swagger", "cpanel"
]

def _check_single_dir(url, directory):
    test_url = urljoin(url + "/", directory)
    try:
        resp = requests.get(test_url, headers={"User-Agent": "VulnEye-Scanner"}, timeout=3.5, allow_redirects=False)
        if resp.status_code in [200, 301, 302, 401, 403]:
            return {
                "path": "/" + directory,
                "status": resp.status_code
            }
    except Exception:
        pass
    return None

def scan_directories(url):
    found_dirs = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_check_single_dir, url, d) for d in COMMON_DIRS]
        for future in as_completed(futures):
            res = future.result()
            if res:
                found_dirs.append(res)
    found_dirs.sort(key=lambda x: x["path"])
    return found_dirs

SENSITIVE_FILES = [
    {"path": "/.env", "desc": "Environment Configuration (High Risk)", "severity": "High"},
    {"path": "/.git/HEAD", "desc": "Git Source Repository (High Risk)", "severity": "High"},
    {"path": "/robots.txt", "desc": "Robots Indexing Directive", "severity": "Info"},
    {"path": "/sitemap.xml", "desc": "Sitemap Architecture", "severity": "Info"},
    {"path": "/.DS_Store", "desc": "macOS Directory Artifact", "severity": "Medium"},
    {"path": "/backup.zip", "desc": "Unprotected Backup Archive", "severity": "High"},
    {"path": "/config.json", "desc": "JSON Configuration File", "severity": "Medium"},
    {"path": "/wp-config.php.bak", "desc": "WordPress Config Backup", "severity": "High"},
    {"path": "/server-status", "desc": "Apache/Server Status Handler", "severity": "Medium"}
]

def _check_single_sensitive_file(url, item):
    test_url = urljoin(url + "/", item["path"].lstrip("/"))
    try:
        resp = requests.get(test_url, headers={"User-Agent": "VulnEye-Scanner"}, timeout=3.5, allow_redirects=False)
        if resp.status_code == 200 and len(resp.content) > 0:
            if item["path"] == "/.git/HEAD" and "ref:" not in resp.text:
                return None
            if item["path"] == "/.env" and ("<html" in resp.text.lower() or "<!doctype" in resp.text.lower()):
                return None
            return {
                "file": item["path"],
                "status": resp.status_code,
                "description": item["desc"],
                "severity": item["severity"]
            }
    except Exception:
        pass
    return None

def scan_sensitive_files(url):
    leaks = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_check_single_sensitive_file, url, item) for item in SENSITIVE_FILES]
        for future in as_completed(futures):
            res = future.result()
            if res:
                leaks.append(res)
    leaks.sort(key=lambda x: x["file"])
    return leaks

# ================= 7. SUBDOMAIN RECONNAISSANCE TOOL =================
COMMON_SUBDOMAINS = [
    "www", "api", "dev", "staging", "admin", "mail", "vpn",
    "portal", "auth", "cdn", "app", "test", "git", "jenkins",
    "status", "docs", "blog", "shop", "beta", "secure"
]

def _resolve_subdomain(sub, base_domain):
    fqdn = f"{sub}.{base_domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return {
            "subdomain": fqdn,
            "ip": ip,
            "status": "Online"
        }
    except Exception:
        return None

def scan_subdomains(target):
    base_domain = extract_domain(target)
    # Remove leading www. if provided
    if base_domain.startswith("www."):
        base_domain = base_domain[4:]

    discovered = []
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(_resolve_subdomain, sub, base_domain) for sub in COMMON_SUBDOMAINS]
        for future in as_completed(futures):
            res = future.result()
            if res:
                discovered.append(res)

    discovered.sort(key=lambda x: x["subdomain"])
    return {
        "base_domain": base_domain,
        "total_probed": len(COMMON_SUBDOMAINS),
        "found_count": len(discovered),
        "subdomains": discovered
    }

# ================= 8. PASSWORD & SECRET ENTROPY ANALYZER =================
def analyze_password_strength(password):
    if not password:
        return {
            "entropy": 0,
            "strength": "Empty",
            "crack_time": "Instant",
            "score": 0,
            "feedback": ["Password cannot be empty."]
        }

    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    charset_size = 0
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_digit: charset_size += 10
    if has_special: charset_size += 33

    if charset_size == 0:
        charset_size = 1

    # Shannon Entropy formula: H = L * log2(N)
    entropy = round(length * math.log2(charset_size), 2)
    
    # Calculate crack time estimation (based on 10 billion guesses/sec)
    combinations = charset_size ** length
    seconds_to_crack = combinations / (10 ** 10)

    if seconds_to_crack < 1:
        crack_time = "Less than 1 second"
    elif seconds_to_crack < 60:
        crack_time = f"{int(seconds_to_crack)} seconds"
    elif seconds_to_crack < 3600:
        crack_time = f"{int(seconds_to_crack / 60)} minutes"
    elif seconds_to_crack < 86400:
        crack_time = f"{int(seconds_to_crack / 3600)} hours"
    elif seconds_to_crack < 31536000:
        crack_time = f"{int(seconds_to_crack / 86400)} days"
    elif seconds_to_crack < 31536000 * 100:
        crack_time = f"{int(seconds_to_crack / 31536000)} years"
    else:
        crack_time = "Centuries (Unbreakable)"

    feedback = []
    if length < 12:
        feedback.append("Length should be at least 12-16 characters (NIST Recommended).")
    if not (has_lower and has_upper):
        feedback.append("Use both uppercase and lowercase letters.")
    if not has_digit:
        feedback.append("Include numbers (0-9).")
    if not has_special:
        feedback.append("Include special symbols (!@#$%^&*).")

    if entropy >= 75 and length >= 14:
        strength = "Very Strong"
        score = 100
    elif entropy >= 55 and length >= 10:
        strength = "Strong"
        score = 80
    elif entropy >= 35:
        strength = "Moderate"
        score = 50
    else:
        strength = "Weak"
        score = 25

    return {
        "entropy": entropy,
        "strength": strength,
        "crack_time": crack_time,
        "score": score,
        "length": length,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_special": has_special,
        "feedback": feedback
    }

# ================= 9. COOKIES & CORS POLICY =================
def check_cookie_security(response):
    cookies_analysis = []
    if not response or not hasattr(response, "cookies"):
        return cookies_analysis

    for cookie in response.cookies:
        issues = []
        if not cookie.secure:
            issues.append("Missing 'Secure' flag (Vulnerable to MITM)")
        if not cookie.has_nonstandard_attr('HttpOnly') and not getattr(cookie, '_rest', {}).get('HttpOnly'):
            issues.append("Missing 'HttpOnly' flag (Vulnerable to XSS)")
        
        samesite = getattr(cookie, '_rest', {}).get('SameSite', 'None')
        if not samesite or samesite.lower() == 'none':
            issues.append("SameSite attribute is None/Missing (CSRF risk)")

        cookies_analysis.append({
            "name": cookie.name,
            "domain": cookie.domain,
            "secure": cookie.secure,
            "httponly": bool(getattr(cookie, '_rest', {}).get('HttpOnly') or cookie.has_nonstandard_attr('HttpOnly')),
            "samesite": samesite,
            "issues": issues
        })

    return cookies_analysis

def check_cors(url):
    cors_result = {
        "misconfigured": False,
        "allow_origin": "N/A",
        "allow_credentials": "N/A",
        "risk_details": "CORS headers are properly restricted or not configured."
    }
    test_origin = "https://evil-scanner-test.com"
    try:
        resp = requests.get(
            url,
            headers={"Origin": test_origin, "User-Agent": "VulnEye-Scanner"},
            timeout=4
        )
        origin_header = resp.headers.get("Access-Control-Allow-Origin")
        credentials_header = resp.headers.get("Access-Control-Allow-Credentials")

        if origin_header:
            cors_result["allow_origin"] = origin_header
            cors_result["allow_credentials"] = credentials_header or "false"

            if origin_header == "*":
                cors_result["misconfigured"] = True
                cors_result["risk_details"] = "Wildcard '*' Access-Control-Allow-Origin detected."
            elif origin_header == test_origin:
                cors_result["misconfigured"] = True
                if credentials_header and credentials_header.lower() == "true":
                    cors_result["risk_details"] = "Arbitrary origin reflection with Allow-Credentials enabled! High CSRF/Data theft vulnerability."
                else:
                    cors_result["risk_details"] = "Arbitrary origin reflection detected."
    except Exception:
        pass

    return cors_result

# ================= 10. TECH STACK & FORMS =================
def detect_tech_stack(response, soup):
    tech = set()
    if not response:
        return list(tech)

    headers = response.headers
    server = headers.get("Server", "")
    if server:
        tech.add(f"Server: {server}")

    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        tech.add(f"Framework: {powered_by}")

    if "cf-ray" in headers or "cloudflare" in server.lower():
        tech.add("CDN / WAF: Cloudflare")
    if "x-amz-cf-id" in headers:
        tech.add("CDN: AWS CloudFront")
    if "x-github-request-id" in headers:
        tech.add("Host: GitHub Pages")
    if "x-vercel-id" in headers:
        tech.add("Platform: Vercel")

    if soup:
        meta_gen = soup.find("meta", attrs={"name": "generator"})
        if meta_gen and meta_gen.get("content"):
            tech.add(f"CMS/Generator: {meta_gen['content']}")

        html_text = soup.prettify().lower()
        if "wp-content" in html_text or "wp-includes" in html_text:
            tech.add("CMS: WordPress")
        if "drupal" in html_text:
            tech.add("CMS: Drupal")
        if "react" in html_text or soup.find(id="root") or soup.find(id="__next"):
            tech.add("Frontend: React.js")
        if "vue" in html_text or soup.find(id="app"):
            tech.add("Frontend: Vue.js")
        if "bootstrap" in html_text:
            tech.add("UI Library: Bootstrap")
        if "tailwind" in html_text:
            tech.add("UI Library: Tailwind CSS")

    return sorted(list(tech))

def detect_forms(soup):
    if not soup:
        return []

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

# ================= 11. RISK SCORING =================
def calculate_risk(results):
    score = 0

    if not results.get("https"):
        score += 2

    ssl_info = results.get("ssl_certificate", {})
    if ssl_info.get("expired"):
        score += 3
    elif results.get("https") and not ssl_info.get("valid") and not ssl_info.get("error"):
        score += 2

    missing_headers = results.get("missing_headers", [])
    score += len(missing_headers) * 0.75

    open_ports_count = len(results.get("open_ports", []))
    if open_ports_count > 10:
        score += 3
    elif open_ports_count > 5:
        score += 2
    elif open_ports_count > 2:
        score += 1

    sensitive_files = results.get("sensitive_files", [])
    for leak in sensitive_files:
        if leak.get("severity") == "High":
            score += 3
        else:
            score += 1

    cors = results.get("cors", {})
    if cors.get("misconfigured"):
        score += 2

    cookies = results.get("cookies", [])
    for c in cookies:
        if c.get("issues"):
            score += 0.5

    if len(results.get("found_directories", [])) > 0:
        score += 1.5

    if len(results.get("forms", [])) > 0:
        score += 0.5

    if score <= 3.5:
        return "Low"
    elif score <= 8:
        return "Medium"
    else:
        return "High"

# ================= 12. MASTER RUNNER =================
def run_scan(url):
    url = normalize_url(url)
    parsed = urlparse(url)
    host = parsed.netloc

    host_info = resolve_host_info(host)
    if not host_info["safe"]:
        return {
            "url": url,
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

    status_data = check_status(url)
    if not status_data["reachable"]:
        return {
            "url": url,
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

    response = status_data["response"]
    soup = None
    try:
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception:
        pass

    https_status = check_https(url)
    ssl_cert_info = check_ssl_cert(host) if https_status else {}
    headers_info = check_security_headers(response)
    open_ports = scan_ports(host)
    found_dirs = scan_directories(url)
    sensitive_leaks = scan_sensitive_files(url)
    cookies_info = check_cookie_security(response)
    cors_info = check_cors(url)
    tech_stack = detect_tech_stack(response, soup)
    forms = detect_forms(soup)

    results = {
        "url": url,
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
    return results