import os
import json
import logging
import secrets
import hashlib
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import NullPool

logger = logging.getLogger("vulneye.database")

# 1. Determine Database URL
def normalize_database_url(url=None):
    """
    Normalizes a database URL for SQLAlchemy compatibility:
    - Normalizes 'postgres://' to 'postgresql://' (required for SQLAlchemy 1.4/2.0+)
    - Automatically appends 'sslmode=require' for PostgreSQL URLs when missing
    - Preserves explicitly provided sslmode settings (e.g. sslmode=disable, sslmode=prefer)
    - Sets appropriate fallback for local SQLite or serverless /tmp
    """
    raw_url = url or os.environ.get("DATABASE_URL")
    if raw_url:
        cleaned = raw_url.strip()
        if cleaned.startswith("postgres://"):
            cleaned = cleaned.replace("postgres://", "postgresql://", 1)
        if cleaned.startswith("postgresql://") and "sslmode=" not in cleaned:
            separator = "&" if "?" in cleaned else "?"
            cleaned = f"{cleaned}{separator}sslmode=require"
        return cleaned
    
    if os.environ.get("VERCEL"):
        return "sqlite:////tmp/scans.db"
    return "sqlite:///scans.db"

DATABASE_URL = normalize_database_url()

# 2. Setup SQLAlchemy Engine with Serverless-friendly Pooling
is_serverless = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))

engine_kwargs = {
    "pool_pre_ping": True,
    "echo": False
}

if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
elif is_serverless:
    # Serverless / Vercel with PostgreSQL & Supabase Transaction Pooler (PgBouncer)
    # Using NullPool avoids connection accumulation across stateless lambda invocations
    engine_kwargs["poolclass"] = NullPool
else:
    # Dedicated long-running servers (e.g. Render / Docker / local VM)
    engine_kwargs["pool_recycle"] = 300
    engine_kwargs["pool_size"] = 5
    engine_kwargs["max_overflow"] = 10
    engine_kwargs["pool_timeout"] = 30

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

from urllib.parse import urlparse, parse_qs

_last_init_error = None

def get_last_init_error():
    return _last_init_error

def get_safe_db_metadata():
    """
    Extracts database connection metadata safely without revealing secrets or passwords.
    """
    raw_env = os.environ.get("DATABASE_URL")
    if not raw_env:
        return {
            "configured": False,
            "engine": "sqlite",
            "host": None,
            "port": None,
            "user_format": None,
            "database": None,
            "sslmode": None
        }
    try:
        parsed = urlparse(DATABASE_URL)
        qs = parse_qs(parsed.query)
        username = parsed.username or ""
        user_format = "unknown"
        if "." in username:
            parts = username.split(".", 1)
            user_format = f"{parts[0]}.{parts[1][:4]}***"
        elif username:
            user_format = f"{username[:3]}***"

        return {
            "configured": True,
            "scheme": parsed.scheme,
            "host": parsed.hostname,
            "port": parsed.port,
            "user_format": user_format,
            "database": parsed.path.lstrip("/") if parsed.path else None,
            "sslmode": qs.get("sslmode", [None])[0]
        }
    except Exception as e:
        return {"configured": True, "parse_error": type(e).__name__}

def sanitize_db_error(exc):
    """
    Extracts and sanitizes the database exception message, ensuring no passwords or raw URLs are exposed.
    """
    if exc is None:
        return None
    driver_error = getattr(exc, "orig", exc)
    raw_msg = str(driver_error)
    lines = [line.strip() for line in raw_msg.splitlines() if line.strip()]
    first_line = lines[0] if lines else str(type(exc).__name__)
    return {
        "type": type(exc).__name__,
        "driver_type": type(driver_error).__name__,
        "message": first_line
    }

def get_db_status():
    """
    Safely probes database connectivity and returns engine type and diagnostic metadata without leaking credentials.
    """
    is_postgres = DATABASE_URL.startswith("postgres")
    engine_type = "postgresql" if is_postgres else "sqlite"
    configured = bool(os.environ.get("DATABASE_URL"))
    is_ephemeral = bool(os.environ.get("VERCEL") and DATABASE_URL.startswith("sqlite"))
    metadata = get_safe_db_metadata()

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {
            "status": "connected",
            "engine": engine_type,
            "configured": configured,
            "ephemeral": is_ephemeral,
            "metadata": metadata
        }
    except Exception as e:
        error_info = sanitize_db_error(e)
        logger.warning(
            "Database connectivity probe failed: [%s] %s (Host: %s:%s, Database: %s)",
            error_info.get("type"),
            error_info.get("message"),
            metadata.get("host"),
            metadata.get("port"),
            metadata.get("database")
        )
        return {
            "status": "disconnected",
            "error": error_info,
            "engine": engine_type,
            "configured": configured,
            "ephemeral": is_ephemeral,
            "metadata": metadata
        }

# 3. Model Definitions
class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(255), nullable=True, index=True)
    url = Column(String(500), nullable=False, index=True)
    scan_time = Column(DateTime, default=datetime.utcnow)
    reachable = Column(String(50), nullable=True)
    status_code = Column(String(50), nullable=True)
    https = Column(String(50), nullable=True)
    risk = Column(String(50), nullable=True)
    raw_results = Column(Text, nullable=True)

class MonitoredAsset(Base):
    __tablename__ = "monitored_assets"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(255), nullable=False, index=True)
    domain = Column(String(500), nullable=False)
    frequency = Column(String(50), default="daily") # daily, weekly
    status = Column(String(50), default="Healthy")  # Healthy, Warning, Critical
    created_at = Column(DateTime, default=datetime.utcnow)
    last_scanned_at = Column(DateTime, nullable=True)

class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(255), nullable=False, index=True)
    name = Column(String(100), default="Production CI/CD Key")
    key_prefix = Column(String(20), nullable=False) # e.g. vye_live_abc12...
    key_hash = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

class UserSubscription(Base):
    __tablename__ = "user_subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(255), nullable=False, unique=True, index=True)
    plan = Column(String(50), default="Community Scout") # Community Scout, Pro SecOps, Enterprise Sentinel
    status = Column(String(50), default="Active")
    billing_cycle = Column(String(20), default="monthly")
    amount = Column(String(20), default="$0")
    updated_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)

class PaymentTransaction(Base):
    __tablename__ = "payment_transactions"

    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String(100), nullable=False, unique=True, index=True)
    user_email = Column(String(255), nullable=False, index=True)
    plan_name = Column(String(50), nullable=False)
    billing_cycle = Column(String(20), default="monthly")
    amount = Column(String(20), nullable=False)
    currency = Column(String(10), default="USD")
    payment_method = Column(String(50), default="Credit/Debit Card")
    status = Column(String(20), default="SUCCESS")
    created_at = Column(DateTime, default=datetime.utcnow)

class UserWebhookConfig(Base):
    __tablename__ = "user_webhooks"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(255), nullable=False, unique=True, index=True)
    webhook_url = Column(String(500), nullable=True)
    channel_type = Column(String(50), default="discord") # discord, slack, custom
    alert_level = Column(String(50), default="High & Critical") # All, High & Critical, Critical Only
    is_enabled = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=datetime.utcnow)

def init_db():
    global _last_init_error
    try:
        Base.metadata.create_all(bind=engine)
        
        # Safe migration for existing SQLite database to add user_email column if missing
        if DATABASE_URL.startswith("sqlite"):
            try:
                with engine.connect() as conn:
                    result = conn.execute(text("PRAGMA table_info(scan_history);")).fetchall()
                    col_names = [row[1] for row in result]
                    if "user_email" not in col_names:
                        conn.execute(text("ALTER TABLE scan_history ADD COLUMN user_email VARCHAR(255);"))
                        conn.commit()
            except Exception as mig_err:
                logger.debug("SQLite column migration check skipped: %s", mig_err)
        _last_init_error = None
        return True
    except Exception as e:
        _last_init_error = str(e)
        is_postgres = DATABASE_URL.startswith("postgres")
        engine_name = "PostgreSQL" if is_postgres else "SQLite"
        logger.warning(
            "Database schema initialization skipped or failed for %s engine: %s. Application will continue in degraded mode.",
            engine_name,
            type(e).__name__
        )
        return False

# ================= SCAN HISTORY =================
def save_scan(results, user_email=None):
    init_db()
    session = SessionLocal()
    try:
        scan_entry = ScanHistory(
            user_email=user_email,
            url=results.get("url", ""),
            reachable=str(results.get("reachable", False)),
            status_code=str(results.get("status_code", "")),
            https=str(results.get("https", False)),
            risk=str(results.get("risk", "Unknown")),
            raw_results=json.dumps(results)
        )
        session.add(scan_entry)
        session.commit()
        return scan_entry.id
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def get_all_scans(user_email=None, limit=100):
    if not user_email:
        return []
    init_db()
    session = SessionLocal()
    try:
        query = session.query(ScanHistory).filter(ScanHistory.user_email == user_email)
        scans = query.order_by(ScanHistory.id.desc()).limit(limit).all()
        result = []
        for s in scans:
            time_str = s.scan_time.strftime("%Y-%m-%d %H:%M:%S") if s.scan_time else ""
            result.append((s.id, s.url, time_str, s.reachable, s.status_code, s.https, s.risk, s.user_email))
        return result
    finally:
        session.close()

def get_scan_by_id(scan_id, user_email=None):
    if not user_email:
        return None
    init_db()
    session = SessionLocal()
    try:
        query = session.query(ScanHistory).filter(
            ScanHistory.id == scan_id,
            ScanHistory.user_email == user_email
        )
        scan = query.first()
        if scan and scan.raw_results:
            try:
                data = json.loads(scan.raw_results)
                data["id"] = scan.id
                data["scan_time"] = scan.scan_time.strftime("%Y-%m-%d %H:%M:%S") if scan.scan_time else ""
                return data
            except Exception:
                pass
        return None
    finally:
        session.close()

def get_latest_scan_results(url, user_email=None):
    if not user_email:
        return None
    init_db()
    session = SessionLocal()
    try:
        query = session.query(ScanHistory).filter(
            ScanHistory.url == url,
            ScanHistory.user_email == user_email
        )
        scan = query.order_by(ScanHistory.id.desc()).first()
        if scan and scan.raw_results:
            try:
                data = json.loads(scan.raw_results)
                data["id"] = scan.id
                data["scan_time"] = scan.scan_time.strftime("%Y-%m-%d %H:%M:%S") if scan.scan_time else ""
                return data
            except Exception:
                pass
        return None
    finally:
        session.close()

def delete_scan(scan_id, user_email=None):
    if not user_email:
        return False
    init_db()
    session = SessionLocal()
    try:
        query = session.query(ScanHistory).filter(
            ScanHistory.id == scan_id,
            ScanHistory.user_email == user_email
        )
        scan = query.first()
        if scan:
            session.delete(scan)
            session.commit()
            return True
        return False
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

# ================= ASSET WATCHLIST & MONITORING =================
def add_monitored_asset(user_email, domain, frequency="daily"):
    init_db()
    session = SessionLocal()
    try:
        from scanner import extract_domain
        clean_domain = extract_domain(domain)
        
        existing = session.query(MonitoredAsset).filter(
            MonitoredAsset.user_email == user_email,
            MonitoredAsset.domain == clean_domain
        ).first()

        if existing:
            existing.frequency = frequency
            session.commit()
            return existing.id

        asset = MonitoredAsset(
            user_email=user_email,
            domain=clean_domain,
            frequency=frequency,
            status="Healthy"
        )
        session.add(asset)
        session.commit()
        return asset.id
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def get_monitored_assets(user_email):
    if not user_email:
        return []
    init_db()
    session = SessionLocal()
    try:
        query = session.query(MonitoredAsset).filter(MonitoredAsset.user_email == user_email)
        return query.order_by(MonitoredAsset.id.desc()).all()
    finally:
        session.close()

def delete_monitored_asset(asset_id, user_email):
    if not user_email:
        return False
    init_db()
    session = SessionLocal()
    try:
        query = session.query(MonitoredAsset).filter(
            MonitoredAsset.id == asset_id,
            MonitoredAsset.user_email == user_email
        )
        asset = query.first()
        if asset:
            session.delete(asset)
            session.commit()
            return True
        return False
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

# ================= API KEYS MANAGEMENT =================
def generate_api_key(user_email, name="Production Key"):
    init_db()
    session = SessionLocal()
    try:
        raw_token = "vye_live_" + secrets.token_hex(20)
        key_prefix = raw_token[:16] + "..."
        key_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        key_entry = ApiKey(
            user_email=user_email,
            name=name,
            key_prefix=key_prefix,
            key_hash=key_hash,
            is_active=True
        )
        session.add(key_entry)
        session.commit()
        return {
            "id": key_entry.id,
            "raw_token": raw_token,
            "name": name,
            "key_prefix": key_prefix,
            "created_at": key_entry.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def get_user_api_keys(user_email):
    if not user_email:
        return []
    init_db()
    session = SessionLocal()
    try:
        query = session.query(ApiKey).filter(ApiKey.user_email == user_email)
        return query.order_by(ApiKey.id.desc()).all()
    finally:
        session.close()

def revoke_api_key(key_id, user_email):
    if not user_email:
        return False
    init_db()
    session = SessionLocal()
    try:
        query = session.query(ApiKey).filter(
            ApiKey.id == key_id,
            ApiKey.user_email == user_email
        )
        key_entry = query.first()
        if key_entry:
            key_entry.is_active = False
            session.commit()
            return True
        return False
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def verify_api_key(raw_token):
    if not raw_token:
        return None
    init_db()
    session = SessionLocal()
    try:
        token_clean = raw_token.replace("Bearer ", "").strip()
        key_hash = hashlib.sha256(token_clean.encode()).hexdigest()
        key_entry = session.query(ApiKey).filter(
            ApiKey.key_hash == key_hash,
            ApiKey.is_active == True
        ).first()
        if key_entry:
            return key_entry.user_email
        return None
    finally:
        session.close()

# ================= SCAN COMPARISON & DIFF ENGINE =================
def compare_scans(scan_id_1, scan_id_2, user_email=None):
    scan_a = get_scan_by_id(scan_id_1, user_email)
    scan_b = get_scan_by_id(scan_id_2, user_email)

    if not scan_a or not scan_b:
        return None

    # Compare Open Ports
    ports_a = set(p["port"] if isinstance(p, dict) else p for p in scan_a.get("open_ports", []))
    ports_b = set(p["port"] if isinstance(p, dict) else p for p in scan_b.get("open_ports", []))
    new_ports = sorted(list(ports_b - ports_a))
    closed_ports = sorted(list(ports_a - ports_b))
    persistent_ports = sorted(list(ports_a & ports_b))

    # Compare Missing Headers
    hdrs_a = set(scan_a.get("missing_headers", []))
    hdrs_b = set(scan_b.get("missing_headers", []))
    fixed_headers = sorted(list(hdrs_a - hdrs_b))
    new_missing_headers = sorted(list(hdrs_b - hdrs_a))

    # Compare Sensitive Files
    leaks_a = set(l["file"] for l in scan_a.get("sensitive_files", []))
    leaks_b = set(l["file"] for l in scan_b.get("sensitive_files", []))
    fixed_leaks = sorted(list(leaks_a - leaks_b))
    new_leaks = sorted(list(leaks_b - leaks_a))

    # Determine Delta Posture
    score_a = 90 if scan_a.get("risk") == "Low" else (65 if scan_a.get("risk") == "Medium" else 30)
    score_b = 90 if scan_b.get("risk") == "Low" else (65 if scan_b.get("risk") == "Medium" else 30)
    score_delta = score_b - score_a

    return {
        "scan_a": scan_a,
        "scan_b": scan_b,
        "score_delta": score_delta,
        "ports": {
            "new": new_ports,
            "closed": closed_ports,
            "persistent": persistent_ports
        },
        "headers": {
            "fixed": fixed_headers,
            "new_missing": new_missing_headers
        },
        "leaks": {
            "fixed": fixed_leaks,
            "new": new_leaks
        }
    }

# ================= EXECUTIVE SOC DASHBOARD METRICS =================
def get_soc_dashboard_metrics(user_email):
    scans = get_all_scans(user_email, limit=100)
    assets = get_monitored_assets(user_email)

    total_scans = len(scans)
    low_risk = sum(1 for s in scans if s[6] == "Low")
    med_risk = sum(1 for s in scans if s[6] == "Medium")
    high_risk = sum(1 for s in scans if s[6] == "High")

    # Posture Score calculation (0-100)
    if total_scans > 0:
        raw_score = ((low_risk * 95) + (med_risk * 65) + (high_risk * 30)) / total_scans
        posture_score = int(raw_score)
    else:
        posture_score = 85

    return {
        "total_scans": total_scans,
        "monitored_assets_count": len(assets),
        "posture_score": posture_score,
        "risk_breakdown": {
            "low": low_risk,
            "medium": med_risk,
            "high": high_risk
        },
        "recent_scans": scans[:8],
        "assets": assets[:6]
    }

# ================= SUBSCRIPTION & PAYMENT PROCESSING =================
def get_user_subscription(user_email):
    if not user_email:
        return {
            "plan": "Community Scout",
            "status": "Active",
            "billing_cycle": "forever",
            "amount": "$0",
            "is_pro": False,
            "is_enterprise": False
        }

    init_db()
    session = SessionLocal()
    try:
        sub = session.query(UserSubscription).filter(UserSubscription.user_email == user_email).first()
        if not sub:
            # Default to Community Scout plan
            return {
                "plan": "Community Scout",
                "status": "Active",
                "billing_cycle": "forever",
                "amount": "$0",
                "is_pro": False,
                "is_enterprise": False,
                "updated_at": None
            }
        
        is_pro = "pro" in sub.plan.lower()
        is_ent = "enterprise" in sub.plan.lower()
        return {
            "plan": sub.plan,
            "status": sub.status,
            "billing_cycle": sub.billing_cycle,
            "amount": sub.amount,
            "is_pro": is_pro,
            "is_enterprise": is_ent,
            "updated_at": sub.updated_at.strftime("%b %d, %Y") if sub.updated_at else None
        }
    finally:
        session.close()

def process_subscription_payment(user_email, plan_name, billing_cycle="monthly", amount="$49", payment_method="Credit/Debit Card", txn_id=None):
    if not user_email:
        raise ValueError("User email is required for payment processing")

    init_db()
    session = SessionLocal()
    try:
        if not txn_id:
            rand_hex = secrets.token_hex(4).upper()
            txn_id = f"TXN_VYE_{datetime.utcnow().strftime('%Y%m%d')}_{rand_hex}"

        # 1. Record Transaction
        txn = PaymentTransaction(
            transaction_id=txn_id,
            user_email=user_email,
            plan_name=plan_name,
            billing_cycle=billing_cycle,
            amount=amount,
            currency="USD",
            payment_method=payment_method,
            status="SUCCESS"
        )
        session.add(txn)

        # 2. Update or Create User Subscription
        sub = session.query(UserSubscription).filter(UserSubscription.user_email == user_email).first()
        if sub:
            sub.plan = plan_name
            sub.status = "Active"
            sub.billing_cycle = billing_cycle
            sub.amount = amount
            sub.updated_at = datetime.utcnow()
        else:
            sub = UserSubscription(
                user_email=user_email,
                plan=plan_name,
                status="Active",
                billing_cycle=billing_cycle,
                amount=amount,
                updated_at=datetime.utcnow()
            )
            session.add(sub)

        session.commit()
        return {
            "success": True,
            "transaction_id": txn_id,
            "plan": plan_name,
            "amount": amount,
            "billing_cycle": billing_cycle,
            "payment_method": payment_method,
            "date": datetime.utcnow().strftime("%B %d, %Y - %H:%M UTC")
        }
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def get_user_transactions(user_email):
    if not user_email:
        return []
    init_db()
    session = SessionLocal()
    try:
        txns = session.query(PaymentTransaction).filter(
            PaymentTransaction.user_email == user_email
        ).order_by(PaymentTransaction.id.desc()).all()

        return [{
            "id": t.id,
            "transaction_id": t.transaction_id,
            "plan_name": t.plan_name,
            "billing_cycle": t.billing_cycle,
            "amount": t.amount,
            "payment_method": t.payment_method,
            "status": t.status,
            "created_at": t.created_at.strftime("%Y-%m-%d %H:%M")
        } for t in txns]
    finally:
        session.close()

def get_transaction_by_id(transaction_id, user_email=None):
    if not transaction_id or not user_email:
        return None
    init_db()
    session = SessionLocal()
    try:
        query = session.query(PaymentTransaction).filter(
            PaymentTransaction.transaction_id == transaction_id,
            PaymentTransaction.user_email == user_email
        )
        t = query.first()
        if not t:
            return None
        return {
            "transaction_id": t.transaction_id,
            "user_email": t.user_email,
            "plan_name": t.plan_name,
            "billing_cycle": t.billing_cycle,
            "amount": t.amount,
            "currency": t.currency,
            "payment_method": t.payment_method,
            "status": t.status,
            "created_at": t.created_at.strftime("%B %d, %Y - %H:%M UTC")
        }
    finally:
        session.close()

# ================= WEBHOOK THREAT ALERTS =================
def get_webhook_config(user_email):
    if not user_email:
        return {"webhook_url": "", "channel_type": "discord", "alert_level": "High & Critical", "is_enabled": False}
    init_db()
    session = SessionLocal()
    try:
        cfg = session.query(UserWebhookConfig).filter(UserWebhookConfig.user_email == user_email).first()
        if not cfg:
            return {"webhook_url": "", "channel_type": "discord", "alert_level": "High & Critical", "is_enabled": False}
        return {
            "webhook_url": cfg.webhook_url or "",
            "channel_type": cfg.channel_type or "discord",
            "alert_level": cfg.alert_level or "High & Critical",
            "is_enabled": bool(cfg.is_enabled),
            "updated_at": cfg.updated_at.strftime("%Y-%m-%d %H:%M") if cfg.updated_at else ""
        }
    finally:
        session.close()

def save_webhook_config(user_email, webhook_url, channel_type="discord", alert_level="High & Critical", is_enabled=True):
    if not user_email:
        return False
    init_db()
    session = SessionLocal()
    try:
        cfg = session.query(UserWebhookConfig).filter(UserWebhookConfig.user_email == user_email).first()
        if not cfg:
            cfg = UserWebhookConfig(
                user_email=user_email,
                webhook_url=webhook_url,
                channel_type=channel_type,
                alert_level=alert_level,
                is_enabled=is_enabled,
                updated_at=datetime.utcnow()
            )
            session.add(cfg)
        else:
            cfg.webhook_url = webhook_url
            cfg.channel_type = channel_type
            cfg.alert_level = alert_level
            cfg.is_enabled = is_enabled
            cfg.updated_at = datetime.utcnow()
        session.commit()
        return True
    except Exception:
        session.rollback()
        return False
    finally:
        session.close()

def send_webhook_alert(webhook_url, target_url, risk_level, findings_summary="Vulnerability scan completed", is_test=False, timeout=8):
    """Dispatches a formatted security alert to Discord, Slack, or generic HTTP Webhooks."""
    if not webhook_url:
        return False, "No webhook URL provided"
    
    from scanner import validate_outbound_url
    is_safe, reason = validate_outbound_url(webhook_url)
    if not is_safe:
        return False, f"SSRF Security Violation: Webhook destination blocked ({reason})"

    import requests
    try:
        # Determine color and title based on risk
        color_map = {
            "High": 0xff2a5f,    # Crimson Red
            "Medium": 0xffb703,  # Amber Gold
            "Low": 0x00ff9d,     # Emerald Green
            "Safe": 0x00f0ff     # Cyan
        }
        embed_color = color_map.get(risk_level, 0x00f0ff)
        
        prefix = "🚨 [TEST ALERT] " if is_test else "🛡️ [SECURITY BREACH ALERT] "
        
        # Discord Embed Payload
        if "discord.com" in webhook_url:
            payload = {
                "username": "VulnEye SOC Sentinel",
                "avatar_url": "https://api.dicebear.com/7.x/bottts/png?seed=VulnEyeSecurity",
                "embeds": [{
                    "title": f"{prefix}Target: {target_url}",
                    "description": f"**Threat Level:** `{risk_level.upper()}`\n**Findings:** {findings_summary}\n\n*Live telemetry event recorded by VulnEye Automated Defense Engine.*",
                    "color": embed_color,
                    "fields": [
                        {"name": "Target Domain", "value": f"`{target_url}`", "inline": True},
                        {"name": "Threat Classification", "value": f"`{risk_level}`", "inline": True},
                        {"name": "Event Timestamp", "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), "inline": False}
                    ],
                    "footer": {
                        "text": "VulnEye Autonomous Threat Intelligence",
                        "icon_url": "https://api.dicebear.com/7.x/bottts/png?seed=VulnEyeSecurity"
                    }
                }]
            }
        # Slack / General Payload
        elif "slack.com" in webhook_url:
            payload = {
                "text": f"{prefix}*Target:* `{target_url}` | *Threat Level:* `{risk_level}`\n>{findings_summary}",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*{prefix}Target:* `{target_url}`\n*Threat Classification:* `{risk_level.upper()}`\n*Summary:* {findings_summary}"
                        }
                    }
                ]
            }
        # Generic Custom Webhook Payload
        else:
            payload = {
                "event": "security_scan_alert",
                "is_test": is_test,
                "target_url": target_url,
                "risk_level": risk_level,
                "findings": findings_summary,
                "timestamp": datetime.utcnow().isoformat()
            }
        
        resp = requests.post(webhook_url, json=payload, headers={"Content-Type": "application/json"}, timeout=timeout, allow_redirects=False)
        if resp.status_code in [200, 204]:
            return True, "Alert delivered successfully"
        return False, f"Server responded with status code {resp.status_code}"
    except Exception as e:
        return False, f"Webhook dispatch error: {str(e)}"

def dispatch_scan_alerts(results, user_email):
    """
    Evaluates completed scan findings and dispatches automated webhook alerts
    based on the user's configured alert level preference.
    
    Alert Levels:
    - 'All': Dispatches for any completed scan.
    - 'High & Critical': Dispatches when overall risk is 'High' or critical perimeter exposures are present.
    - 'Critical Only': Dispatches only when critical exposures (e.g. leaked .env/.git, open DB ports) are present.
    
    Returns structured dict:
      {
        "sent": bool,
        "reason": str,
        "status": "sent" | "skipped" | "failed"
      }
    """
    if not user_email:
        return {"sent": False, "reason": "No user email provided", "status": "skipped"}

    try:
        config = get_webhook_config(user_email)
        if not config or not config.get("is_enabled") or not config.get("webhook_url"):
            return {
                "sent": False,
                "reason": "Webhook notifications not configured or disabled",
                "status": "skipped"
            }

        webhook_url = config.get("webhook_url")
        alert_level = config.get("alert_level", "High & Critical")
        target_url = results.get("url", "Unknown Target")
        risk = results.get("risk", "Low")

        # 1. Extract critical findings safely without raw contents
        critical_findings = []
        
        # Leaked sensitive configuration or source repository files
        for leak in results.get("sensitive_files", []):
            if isinstance(leak, dict):
                leak_file = leak.get("file", "sensitive file")
                if leak.get("severity") == "High" or leak_file in [".env", ".git", "backup.zip", ".bash_history", "wp-config.php"]:
                    critical_findings.append(f"Exposed {leak_file} configuration/source file")

        # Dangerous public database or administrative ports
        db_ports = {
            3306: "MySQL Database",
            5432: "PostgreSQL Database",
            6379: "Redis Cache/DB",
            27017: "MongoDB Database",
            1433: "MSSQL Database",
            9200: "Elasticsearch",
            2375: "Docker Daemon",
            2379: "etcd Cluster"
        }
        for p in results.get("open_ports", []):
            p_num = p.get("port") if isinstance(p, dict) else p
            if p_num in db_ports:
                critical_findings.append(f"Publicly accessible {db_ports[p_num]} (Port {p_num})")

        # Critical SSL / Certificate issues on HTTPS
        ssl_info = results.get("ssl_certificate", {})
        if ssl_info.get("expired"):
            critical_findings.append("Expired SSL/TLS Certificate")

        has_critical_findings = len(critical_findings) > 0
        is_high_risk = risk.lower() in ["high", "critical"]

        # 2. Evaluate alert level threshold
        should_send = False
        if alert_level == "All":
            should_send = True
        elif alert_level == "High & Critical":
            should_send = is_high_risk or has_critical_findings
        elif alert_level == "Critical Only":
            should_send = has_critical_findings
        else:
            should_send = is_high_risk or has_critical_findings

        if not should_send:
            return {
                "sent": False,
                "reason": f"Scan risk '{risk}' does not meet threshold for alert level '{alert_level}'",
                "status": "skipped"
            }

        # 3. Construct safe summary
        if critical_findings:
            summary_lines = [f"{len(critical_findings)} high-severity finding(s) detected:"]
            for f in critical_findings[:5]:
                summary_lines.append(f"• {f}")
            findings_summary = "\n".join(summary_lines)
        else:
            missing_hdrs = results.get("missing_headers", [])
            findings_summary = f"Automated scan completed with risk posture '{risk}'. Missing headers: {len(missing_hdrs)}"

        # 4. Dispatch alert with short timeout for serverless resilience
        ok, msg = send_webhook_alert(
            webhook_url=webhook_url,
            target_url=target_url,
            risk_level=risk,
            findings_summary=findings_summary,
            is_test=False,
            timeout=3
        )

        if ok:
            return {"sent": True, "reason": msg, "status": "sent"}
        else:
            return {"sent": False, "reason": msg, "status": "failed"}

    except Exception as e:
        logger.warning("Error during automated webhook alert dispatch: %s", type(e).__name__)
        return {
            "sent": False,
            "reason": f"Dispatch execution error: {type(e).__name__}",
            "status": "failed"
        }