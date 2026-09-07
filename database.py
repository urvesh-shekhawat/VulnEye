import os
import json
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

# 1. Determine Database URL
# Render provides DATABASE_URL (often postgres://...) which SQLAlchemy requires as postgresql://
raw_db_url = os.environ.get("DATABASE_URL")
if raw_db_url:
    if raw_db_url.startswith("postgres://"):
        DATABASE_URL = raw_db_url.replace("postgres://", "postgresql://", 1)
    else:
        DATABASE_URL = raw_db_url
else:
    # Local or serverless SQLite fallback
    if os.environ.get("VERCEL"):
        DATABASE_URL = "sqlite:////tmp/scans.db"
    else:
        DATABASE_URL = "sqlite:///scans.db"

# 2. Setup SQLAlchemy Engine and Session
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

# 3. Model Definition
class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(500), nullable=False, index=True)
    scan_time = Column(DateTime, default=datetime.utcnow)
    reachable = Column(String(50), nullable=True)
    status_code = Column(String(50), nullable=True)
    https = Column(String(50), nullable=True)
    risk = Column(String(50), nullable=True)
    raw_results = Column(Text, nullable=True)

def init_db():
    Base.metadata.create_all(bind=engine)

def save_scan(results):
    init_db()
    session = SessionLocal()
    try:
        scan_entry = ScanHistory(
            url=results.get("url", ""),
            reachable=str(results.get("reachable", False)),
            status_code=str(results.get("status_code", "")),
            https=str(results.get("https", False)),
            risk=str(results.get("risk", "Unknown")),
            raw_results=json.dumps(results)
        )
        session.add(scan_entry)
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def get_all_scans():
    init_db()
    session = SessionLocal()
    try:
        scans = session.query(ScanHistory).order_by(ScanHistory.id.desc()).all()
        # Returns tuple format (id, url, scan_time, reachable, status_code, https, risk)
        result = []
        for s in scans:
            time_str = s.scan_time.strftime("%Y-%m-%d %H:%M:%S") if s.scan_time else ""
            result.append((s.id, s.url, time_str, s.reachable, s.status_code, s.https, s.risk))
        return result
    finally:
        session.close()

def get_latest_scan_results(url):
    init_db()
    session = SessionLocal()
    try:
        scan = session.query(ScanHistory).filter(ScanHistory.url == url).order_by(ScanHistory.id.desc()).first()
        if scan and scan.raw_results:
            try:
                return json.loads(scan.raw_results)
            except Exception:
                pass
        return None
    finally:
        session.close()