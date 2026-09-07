import os
import json
import secrets
import hashlib
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, text
from sqlalchemy.orm import declarative_base, sessionmaker

# 1. Determine Database URL
raw_db_url = os.environ.get("DATABASE_URL")
if raw_db_url:
    if raw_db_url.startswith("postgres://"):
        DATABASE_URL = raw_db_url.replace("postgres://", "postgresql://", 1)
    else:
        DATABASE_URL = raw_db_url
else:
    if os.environ.get("VERCEL"):
        DATABASE_URL = "sqlite:////tmp/scans.db"
    else:
        DATABASE_URL = "sqlite:///scans.db"

# 2. Setup SQLAlchemy Engine
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    echo=False
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

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

def init_db():
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
        except Exception:
            pass

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
    init_db()
    session = SessionLocal()
    try:
        query = session.query(ScanHistory)
        if user_email and user_email != "analyst@vulneye.sec":
            query = query.filter((ScanHistory.user_email == user_email) | (ScanHistory.user_email == None))
        
        scans = query.order_by(ScanHistory.id.desc()).limit(limit).all()
        result = []
        for s in scans:
            time_str = s.scan_time.strftime("%Y-%m-%d %H:%M:%S") if s.scan_time else ""
            result.append((s.id, s.url, time_str, s.reachable, s.status_code, s.https, s.risk, s.user_email))
        return result
    finally:
        session.close()

def get_scan_by_id(scan_id, user_email=None):
    init_db()
    session = SessionLocal()
    try:
        query = session.query(ScanHistory).filter(ScanHistory.id == scan_id)
        if user_email and user_email != "analyst@vulneye.sec":
            query = query.filter((ScanHistory.user_email == user_email) | (ScanHistory.user_email == None))
        
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
    init_db()
    session = SessionLocal()
    try:
        query = session.query(ScanHistory).filter(ScanHistory.url == url)
        if user_email and user_email != "analyst@vulneye.sec":
            query = query.filter((ScanHistory.user_email == user_email) | (ScanHistory.user_email == None))
        
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
    init_db()
    session = SessionLocal()
    try:
        query = session.query(ScanHistory).filter(ScanHistory.id == scan_id)
        if user_email and user_email != "analyst@vulneye.sec":
            query = query.filter((ScanHistory.user_email == user_email) | (ScanHistory.user_email == None))
        
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
    init_db()
    session = SessionLocal()
    try:
        query = session.query(MonitoredAsset)
        if user_email and user_email != "analyst@vulneye.sec":
            query = query.filter(MonitoredAsset.user_email == user_email)
        return query.order_by(MonitoredAsset.id.desc()).all()
    finally:
        session.close()

def delete_monitored_asset(asset_id, user_email):
    init_db()
    session = SessionLocal()
    try:
        query = session.query(MonitoredAsset).filter(MonitoredAsset.id == asset_id)
        if user_email and user_email != "analyst@vulneye.sec":
            query = query.filter(MonitoredAsset.user_email == user_email)
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
    init_db()
    session = SessionLocal()
    try:
        query = session.query(ApiKey)
        if user_email and user_email != "analyst@vulneye.sec":
            query = query.filter(ApiKey.user_email == user_email)
        return query.order_by(ApiKey.id.desc()).all()
    finally:
        session.close()

def revoke_api_key(key_id, user_email):
    init_db()
    session = SessionLocal()
    try:
        query = session.query(ApiKey).filter(ApiKey.id == key_id)
        if user_email and user_email != "analyst@vulneye.sec":
            query = query.filter(ApiKey.user_email == user_email)
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
    init_db()
    session = SessionLocal()
    try:
        query = session.query(PaymentTransaction).filter(PaymentTransaction.transaction_id == transaction_id)
        if user_email and user_email != "analyst@vulneye.sec":
            query = query.filter(PaymentTransaction.user_email == user_email)
        
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