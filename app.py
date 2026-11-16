"""
ProbashiGuard — AI-powered migrant worker protection platform (Bangladesh).
FastAPI app with Supabase Postgres persistence. Deploys to Vercel via Mangum
(see api/index.py) or to Render (see Procfile).
"""
import os
import io
import json
import time
import copy
import uuid
import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt, JWTError
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from db import get_db, AsyncSessionLocal
from models import User, Scan, AdminAudit


# ============================================================
# 1. CONFIG
# ============================================================

GEMINI_API_KEY  = os.getenv("GEMINI_API_KEY", "").strip()
USE_MOCK        = not bool(GEMINI_API_KEY)
JWT_SECRET      = os.getenv("JWT_SECRET", "dev-secret-change-me-in-production")
JWT_ALG         = "HS256"
JWT_TTL_HOURS   = int(os.getenv("JWT_TTL_HOURS", "24"))
DEV_MODE        = os.getenv("DEV_MODE", "true").lower() == "true"
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()]
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
FONT_PATH       = os.getenv(
    "BANGLA_FONT_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts", "Kalpurush.ttf"),
)
OTP_TTL_SECONDS = 300

# OTP stays in-memory (5-min TTL). On serverless, DEV_MODE also accepts "000000".
_otp: Dict[str, Dict[str, Any]] = {}

_registry: Dict[str, Dict[str, Any]] = {
    "RL-1234": {"name_en": "Al-Haramain Overseas", "name_bn": "আল-হারামাইন ওভারসিজ",
                "status": "valid",       "blacklisted": False, "country": "SA"},
    "RL-2345": {"name_en": "Gulf Star Manpower",   "name_bn": "গালফ স্টার ম্যানপাওয়ার",
                "status": "valid",       "blacklisted": False, "country": "QA"},
    "RL-3456": {"name_en": "Sunrise Recruiting",   "name_bn": "সানরাইজ রিক্রুটিং",
                "status": "suspended",   "blacklisted": False, "country": "MY"},
    "RL-9999": {"name_en": "Skyline Agency",       "name_bn": "স্কাইলাইন এজেন্সি",
                "status": "blacklisted", "blacklisted": True,  "country": "AE"},
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ============================================================
# 2. STARTUP — seed staff
# ============================================================

async def seed_staff_db() -> None:
    async with AsyncSessionLocal() as db:
        for phone, role, name in [
            ("+8801999999999", "admin",    "ProbashiGuard Admin"),
            ("+8801888888888", "reviewer", "ProbashiGuard Reviewer"),
        ]:
            existing = (await db.execute(select(User).where(User.phone == phone))).scalar_one_or_none()
            if not existing:
                db.add(User(phone=phone, role=role, name=name, nid_verified=True))
        await db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await seed_staff_db()
    except Exception as e:
        # Don't crash startup if the DB is unreachable momentarily (e.g. cold start)
        print(f"[startup] seed_staff_db failed (non-fatal): {e}")
    yield


# ============================================================
# 3. APP
# ============================================================

app = FastAPI(title="ProbashiGuard", version="2.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health(db: AsyncSession = Depends(get_db)) -> dict:
    try:
        await db.execute(select(1))
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {str(e)[:200]}"
    return {"ok": True, "db": db_status, "mock": USE_MOCK, "time": now_iso()}


@app.get("/config")
def config() -> dict:
    return {"mock": USE_MOCK, "dev_mode": DEV_MODE}


# ============================================================
# 4. AUTH
# ============================================================

class PhoneBody(BaseModel):
    phone: str

class OtpBody(BaseModel):
    phone: str
    otp: str

class ReviewBody(BaseModel):
    action: str
    note: str = ""

class NoteBody(BaseModel):
    note: str


def _make_token(phone: str, role: str) -> str:
    payload = {
        "sub": phone,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_TTL_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def user_to_dict(u: User) -> dict:
    return {
        "phone":        u.phone,
        "role":         u.role,
        "name":         u.name,
        "nid_verified": bool(u.nid_verified),
        "nid":          u.nid_data,
        "face":         u.face_data,
    }


async def current_user(
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    payload = _decode_token(authorization.split(" ", 1)[1].strip())
    phone = payload.get("sub")
    u = (await db.execute(select(User).where(User.phone == phone))).scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=401, detail="User not found")
    return user_to_dict(u)


def staff_required(user: dict = Depends(current_user)) -> dict:
    if user.get("role") not in ("reviewer", "admin"):
        raise HTTPException(status_code=403, detail="Staff access required")
    return user


def admin_required(user: dict = Depends(current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def add_audit(db: AsyncSession, actor: dict, action: str,
              target: Optional[str] = None, note: str = "") -> None:
    db.add(AdminAudit(
        actor_phone=actor["phone"],
        actor_role=actor["role"],
        action=action,
        target_scan_id=target,
        note=note,
    ))


# ============================================================
# 5. AI LAYER
# ============================================================

def _parse_json(text: str) -> dict:
    if not text:
        return {}
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else t
        if t.endswith("```"):
            t = t[:-3]
    try:
        return json.loads(t)
    except Exception:
        return {}


def _gemini_client():
    from google import genai
    return genai.Client(api_key=GEMINI_API_KEY)


def _mock_nid(front: bytes, back: bytes) -> dict:
    h = hashlib.sha256(front + back).hexdigest()
    names = [("Md. Rafiqul Islam", "মোঃ রফিকুল ইসলাম"),
             ("Abdul Karim", "আব্দুল করিম"),
             ("Shahida Begum", "শাহিদা বেগম")]
    en, bn = names[int(h[:2], 16) % len(names)]
    return {
        "name_en": en, "name_bn": bn,
        "nid_number": "19" + h[:8].upper(),
        "dob": "1995-0%d-1%d" % (int(h[8], 16) % 9 + 1, int(h[9], 16) % 9),
        "address": "Village: " + ["Savar", "Keraniganj", "Narayanganj"][int(h[10], 16) % 3] + ", Dhaka",
        "confidence": 0.93, "raw": {"source": "mock"},
    }


def extract_nid(front: bytes, back: bytes) -> dict:
    if USE_MOCK:
        return _mock_nid(front, back)
    try:
        from google.genai import types
        prompt = (
            "You are an OCR engine for Bangladeshi National ID (NID) cards. "
            "Return STRICT JSON with keys: name_en, name_bn, nid_number, dob, address, confidence (0-1). "
            "No markdown, no explanation."
        )
        resp = _gemini_client().models.generate_content(
            model="gemini-2.5-flash",
            contents=[prompt,
                      types.Part.from_bytes(data=front, mime_type="image/jpeg"),
                      types.Part.from_bytes(data=back,  mime_type="image/jpeg")],
        )
        out = _parse_json(resp.text)
        if not out.get("nid_number"):
            raise ValueError("bad nid response")
        out["raw"] = {"source": "gemini"}
        return out
    except Exception as e:
        out = _mock_nid(front, back)
        out["raw"] = {"source": "mock-fallback", "error": str(e)[:200]}
        return out


def _mock_face(selfie: bytes, nid_photo: bytes) -> dict:
    h = hashlib.sha256(selfie + nid_photo).hexdigest()
    return {
        "match": True,
        "score": round(0.85 + (int(h[:2], 16) % 13) / 100, 2),
        "liveness_score": round(0.80 + (int(h[2:4], 16) % 18) / 100, 2),
        "raw": {"source": "mock"},
    }


def match_face(selfie: bytes, nid_photo: bytes) -> dict:
    if USE_MOCK:
        return _mock_face(selfie, nid_photo)
    try:
        from google.genai import types
        prompt = (
            "Compare the two face images. Return STRICT JSON: "
            '{"match": bool, "score": 0-1, "liveness_score": 0-1}. No markdown.'
        )
        resp = _gemini_client().models.generate_content(
            model="gemini-2.5-flash",
            contents=[prompt,
                      types.Part.from_bytes(data=selfie,    mime_type="image/jpeg"),
                      types.Part.from_bytes(data=nid_photo, mime_type="image/jpeg")],
        )
        out = _parse_json(resp.text)
        if "match" not in out:
            raise ValueError("bad face response")
        out["raw"] = {"source": "gemini"}
        return out
    except Exception as e:
        out = _mock_face(selfie, nid_photo)
        out["raw"] = {"source": "mock-fallback", "error": str(e)[:200]}
        return out


_MOCK_SCENARIOS = {
    "tier1": {
        "document_type": "Work Visa", "country": "Saudi Arabia",
        "visa_type": "Employment Visa", "employer": "Saudi Binladin Group",
        "agency": "Al-Haramain Overseas", "agency_rl": "RL-1234",
        "salary": 1500, "currency": "SAR",
        "contract_terms": ["Standard 2-year contract", "Accommodation provided"],
        "forensic_findings": [],
        "qr_payload": {"verified": True, "spoofed": False},
        "raw": {"source": "mock", "scenario": "tier1"},
    },
    "tier2": {
        "document_type": "Work Visa", "country": "Qatar",
        "visa_type": "Employment Visa", "employer": "Qatar Construction Co.",
        "agency": "Gulf Star Manpower", "agency_rl": "RL-2345",
        "salary": 1200, "currency": "QAR",
        "contract_terms": ["Standard 2-year contract"],
        "forensic_findings": [
            {"code": "FONT_INCONSISTENCY", "severity": "low",
             "message": "Minor font mismatch between header and body",
             "bbox": [120, 220, 540, 260]},
        ],
        "qr_payload": None,
        "raw": {"source": "mock", "scenario": "tier2"},
    },
    "tier3": {
        "document_type": "Work Visa", "country": "Malaysia",
        "visa_type": "Employment Visa", "employer": "Sunrise Plantation Sdn Bhd",
        "agency": "Sunrise Recruiting", "agency_rl": "RL-3456",
        "salary": 900, "currency": "MYR",
        "contract_terms": ["Deduction of 6 months salary as recruitment fee"],
        "forensic_findings": [
            {"code": "CLAUSE_AMBIGUOUS", "severity": "medium",
             "message": "Ambiguous fee clause with no ceiling", "bbox": [100, 600, 520, 640]},
            {"code": "STAMP_ANOMALY", "severity": "medium",
             "message": "Embassy stamp alignment is off", "bbox": [400, 780, 560, 860]},
        ],
        "qr_payload": {"verified": False, "spoofed": False},
        "raw": {"source": "mock", "scenario": "tier3"},
    },
    "tier4": {
        "document_type": "Work Visa", "country": "UAE",
        "visa_type": "Free Visa", "employer": "Unnamed",
        "agency": "Skyline Agency", "agency_rl": "RL-9999",
        "salary": 0, "currency": "AED",
        "contract_terms": ["Free visa", "No salary until placement fee recovered"],
        "forensic_findings": [
            {"code": "STAMP_FORGED", "severity": "critical",
             "message": "Visa stamp does not match known UAE format", "bbox": [400, 800, 570, 880]},
            {"code": "PHOTO_SPLICE", "severity": "critical",
             "message": "Photo region shows digital splicing artefacts", "bbox": [80, 90, 220, 260]},
        ],
        "qr_payload": {"verified": False, "spoofed": True},
        "raw": {"source": "mock", "scenario": "tier4"},
    },
}


def _mock_scan(image: bytes, scenario: str = "tier1") -> dict:
    return dict(_MOCK_SCENARIOS.get(scenario, _MOCK_SCENARIOS["tier1"]))


def scan_document(image: bytes, scenario: Optional[str] = None) -> dict:
    if USE_MOCK:
        return _mock_scan(image, scenario or "tier1")
    try:
        from google.genai import types
        prompt = (
            "You are a forensic document analyst. Analyse this visa/contract photo. "
            "Return STRICT JSON with keys: document_type, country, visa_type, employer, "
            "agency, agency_rl, salary (number), currency, contract_terms (array of strings), "
            "forensic_findings (array of {code, severity: low|medium|high|critical, message, bbox: [x0,y0,x1,y1]}), "
            "qr_payload (object or null). No markdown."
        )
        resp = _gemini_client().models.generate_content(
            model="gemini-2.5-flash",
            contents=[prompt, types.Part.from_bytes(data=image, mime_type="image/jpeg")],
        )
        out = _parse_json(resp.text)
        if not out.get("document_type"):
            raise ValueError("bad scan response")
        out["raw"] = {"source": "gemini"}
        return out
    except Exception as e:
        out = _mock_scan(image, scenario or "tier1")
        out["raw"] = {"source": "mock-fallback", "error": str(e)[:200]}
        return out


# ============================================================
# 6. RISK ENGINE (deterministic)
# ============================================================

def _reason(code: str, tier: int, en: str, bn: str, evidence: Optional[dict] = None) -> dict:
    return {"code": code, "tier": tier, "message_en": en, "message_bn": bn,
            "evidence": evidence or {}}


def check_registry(doc: dict) -> List[dict]:
    rl = doc.get("agency_rl")
    if not rl:
        return [_reason("AGENCY_NOT_IN_REGISTRY", 2,
                        "Agency RL number not present on document",
                        "নথিতে এজেন্সির RL নম্বর নেই")]
    reg = _registry.get(rl)
    if not reg:
        return [_reason("AGENCY_NOT_IN_REGISTRY", 2,
                        f"Agency RL {rl} not found in BMET/BAIRA registry",
                        f"এজেন্সি RL {rl} BMET/BAIRA রেজিস্ট্রিতে পাওয়া যায়নি",
                        {"rl": rl})]
    if reg["blacklisted"]:
        return [_reason("BLACKLISTED_AGENCY", 4,
                        f"Agency {reg['name_en']} ({rl}) is blacklisted by BMET",
                        f"এজেন্সি {reg['name_bn']} ({rl}) BMET দ্বারা ব্ল্যাকলিস্টভুক্ত",
                        {"rl": rl, "name": reg["name_en"]})]
    if reg["status"] == "suspended":
        return [_reason("SUSPENDED_AGENCY", 3,
                        f"Agency {reg['name_en']} ({rl}) is currently suspended",
                        f"এজেন্সি {reg['name_bn']} ({rl}) বর্তমানে স্থগিত",
                        {"rl": rl, "name": reg["name_en"]})]
    return []


def validate_qr(doc: dict) -> List[dict]:
    qr = doc.get("qr_payload")
    if qr is None:
        return [_reason("QR_MISSING", 2,
                        "No verification QR code found on the document",
                        "নথিতে কোনো যাচাই QR কোড পাওয়া যায়নি")]
    if qr.get("spoofed"):
        return [_reason("SPOOFED_QR", 4,
                        "QR payload does not match the document — possible spoof",
                        "QR কোডের তথ্য নথির সাথে মেলেনি — সম্ভাব্য প্রতারণা",
                        {"qr": qr})]
    return []


def check_identity(user: dict) -> List[dict]:
    nid = user.get("nid")
    face = user.get("face")
    if not nid or not face:
        return [_reason("KYC_INCOMPLETE", 3,
                        "Identity verification (e-KYC) is incomplete",
                        "পরিচয় যাচাই (e-KYC) অসম্পূর্ণ")]
    reasons = []
    if not face.get("match", False):
        reasons.append(_reason("FACE_MISMATCH", 3,
                               "Selfie does not match the NID photo",
                               "সেলফি NID-এর ছবির সাথে মেলেনি",
                               {"score": face.get("score")}))
    if face.get("liveness_score", 1.0) < 0.5:
        reasons.append(_reason("LIVENESS_FAILED", 3,
                               "Liveness check failed — possible photo spoof",
                               "লাইভনেস যাচাই ব্যর্থ — সম্ভাব্য ছবি প্রতারণা",
                               {"liveness": face.get("liveness_score")}))
    return reasons


def check_contract(doc: dict) -> List[dict]:
    reasons = []
    terms = [t.lower() for t in doc.get("contract_terms", [])]
    if any("free visa" in t for t in terms):
        reasons.append(_reason("FREE_VISA_SCAM", 4,
                               "'Free visa' scheme detected — a known trafficking pattern",
                               "'ফ্রি ভিসা' স্কিম শনাক্ত — এটি একটি পরিচিত পাচার কৌশল",
                               {"terms": doc.get("contract_terms")}))
    salary = doc.get("salary") or 0
    currency = doc.get("currency", "")
    if salary and salary < 1000:
        reasons.append(_reason("BELOW_MINIMUM_WAGE", 3,
                               f"Offered salary {salary} {currency} is below minimum wage",
                               f"প্রস্তাবিত বেতন {salary} {currency} ন্যূনতম মজুরির নিচে",
                               {"salary": salary, "currency": currency}))
    elif salary and salary < 1500:
        reasons.append(_reason("LOW_WAGE", 2,
                               f"Offered salary {salary} {currency} is below market average",
                               f"প্রস্তাবিত বেতন {salary} {currency} বাজারের গড়ের নিচে",
                               {"salary": salary, "currency": currency}))
    return reasons


_SEVERITY_TO_TIER = {"critical": 4, "high": 3, "medium": 3, "low": 2}


def check_forensics(doc: dict) -> List[dict]:
    out = []
    for f in doc.get("forensic_findings", []):
        sev = (f.get("severity") or "low").lower()
        tier = _SEVERITY_TO_TIER.get(sev, 2)
        code = f.get("code", "FORENSIC")
        msg = f.get("message", "Forensic anomaly")
        out.append(_reason(code, tier,
                           f"Forensic finding ({sev}): {msg}",
                           f"ফরেনসিক ফলাফল ({sev}): {msg}",
                           {"bbox": f.get("bbox"), "severity": sev}))
    return out


LABELS = {
    1: {"status_en": "No Risk (Verified Authentic)",
        "status_bn": "কোনো ঝুঁকি নেই (যাচাইকৃত)",         "color": "#16a34a"},
    2: {"status_en": "Low Risk (Minor Issues)",
        "status_bn": "কম ঝুঁকি (সামান্য সমস্যা)",           "color": "#eab308"},
    3: {"status_en": "Medium Risk (Review Required)",
        "status_bn": "মাঝারি ঝুঁকি (পর্যালোচনা প্রয়োজন)", "color": "#f97316"},
    4: {"status_en": "High Risk (Confirmed Forgery)",
        "status_bn": "উচ্চ ঝুঁকি (প্রতারণা নিশ্চিত)",       "color": "#dc2626"},
}

GUIDE = {
    1: {"en": "Your documents look authentic. Proceed with your migration plan. "
              "Keep a printed copy of this report and always carry your passport.",
        "bn": "আপনার নথি সঠিক মনে হচ্ছে। আপনার অভিবাসন পরিকল্পনা চালিয়ে যান। "
              "এই রিপোর্টের একটি প্রিন্ট কপি রাখুন এবং সর্বদা পাসপোর্ট সাথে রাখুন।"},
    2: {"en": "Minor issues found. Ask your recruiting agency to clarify before signing. "
              "Never pay any fee without a written receipt.",
        "bn": "সামান্য সমস্যা পাওয়া গেছে। চুক্তি স্বাক্ষরের আগে আপনার রিক্রুটিং এজেন্সিকে "
              "জিজ্ঞাসা করুন। লিখিত রসিদ ছাড়া কোনো ফি দেবেন না।"},
    3: {"en": "Several issues require review. Do NOT pay any fee or sign anything until a "
              "ProbashiGuard reviewer or your local BMET office has checked this report. "
              "Contact the BMET helpline: 16135.",
        "bn": "কয়েকটি সমস্যা পর্যালোচনা প্রয়োজন। ProbashiGuard পর্যালোচক বা আপনার স্থানীয় "
              "BMET অফিস এই রিপোর্ট যাচাই না করা পর্যন্ত কোনো ফি দেবেন না এবং কিছু স্বাক্ষর করবেন না। "
              "BMET হেল্পলাইনে যোগাযোগ করুন: ১৬১৩৫।"},
    4: {"en": "This document shows clear signs of fraud. Do NOT travel. Do NOT pay any money. "
              "Report immediately to BMET (16135), OKUP, or BRAC. Keep this report safe.",
        "bn": "এই নথিতে প্রতারণার স্পষ্ট লক্ষণ রয়েছে। ভ্রমণ করবেন না। কোনো টাকা দেবেন না। "
              "অবিলম্বে BMET (১৬১৩৫), OKUP বা BRAC-এ রিপোর্ট করুন। এই রিপোর্ট সংরক্ষণ করুন।"},
}


def classify(scan: dict, user: dict) -> tuple:
    reasons: List[dict] = []
    reasons += check_registry(scan["document"])
    reasons += validate_qr(scan["document"])
    reasons += check_identity(user)
    reasons += check_contract(scan["document"])
    reasons += check_forensics(scan["document"])
    tier = 1 if not reasons else max(r["tier"] for r in reasons)
    return tier, reasons, LABELS[tier]["status_en"], LABELS[tier]["status_bn"]


# ============================================================
# 7. CONVERSION HELPERS
# ============================================================

def scan_to_dict(s: Scan) -> dict:
    return {
        "id":             s.id,
        "worker_phone":   s.worker_phone,
        "created_at":     s.created_at.isoformat() if s.created_at else None,
        "risk_tier":      s.risk_tier,
        "status_en":      s.status_en,
        "status_bn":      s.status_bn,
        "reasons":        s.reasons or [],
        "document":       s.document_data or {},
        "review_status":  s.review_status or "pending",
        "review_history": s.review_history or [],
        "notes":          s.notes or [],
        "_extras": {
            "image_sha256":  s.image_sha256,
            "file_size":     s.file_size,
            "device_hint":   s.device_hint,
            "ip_hash":       s.ip_hash,
            "processing_ms": s.processing_ms,
            "model":         s.model,
        },
        "record_hash":    s.record_hash,
        "verify_url":     s.verify_url,
    }


async def load_scan_with_user(db: AsyncSession, scan_id: str) -> Optional[dict]:
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if not scan:
        return None
    u = (await db.execute(select(User).where(User.phone == scan.worker_phone))).scalar_one_or_none()
    d = scan_to_dict(scan)
    if u:
        d["nid"] = u.nid_data
        d["face"] = u.face_data
        d["worker_name"] = (u.nid_data or {}).get("name_en") if u.nid_data else u.name
    return d


def _mask_phone(p: str) -> str:
    if not p or len(p) < 6:
        return p or ""
    return p[:4] + "****" + p[-3:]


def _redact_scan(scan: dict, viewer: str) -> dict:
    s = copy.deepcopy(scan)
    if viewer == "worker":
        s.pop("_extras", None)
        s.pop("notes", None)
        s.pop("review_history", None)
        if isinstance(s.get("document"), dict):
            s["document"].pop("raw", None)
        if s.get("nid") and isinstance(s["nid"], dict):
            s["nid"].pop("nid_number", None)
        s["worker_phone"] = _mask_phone(s.get("worker_phone", ""))
    else:
        s["worker_phone"] = _mask_phone(s.get("worker_phone", ""))
    return s


# ============================================================
# 8. PDF BUILDER
# ============================================================

def _register_fonts() -> str:
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        pdfmetrics.registerFont(TTFont("Kalpurush", FONT_PATH))
        return "Kalpurush"
    except Exception:
        return "Helvetica"


BN_FONT = _register_fonts()


def _qr_png(url: str) -> io.BytesIO:
    import qrcode
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


def build_pdf(scan: dict, viewer: str = "worker") -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
        Image as RLImage,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"ProbashiGuard Report — {scan['id']}")
    base = getSampleStyleSheet()
    H1 = ParagraphStyle("H1", parent=base["Heading1"], fontName=BN_FONT, fontSize=18, leading=22)
    H2 = ParagraphStyle("H2", parent=base["Heading2"], fontName=BN_FONT, fontSize=13, leading=16)
    P  = ParagraphStyle("P",  parent=base["BodyText"],  fontName=BN_FONT, fontSize=10, leading=14)
    SM = ParagraphStyle("SM", parent=base["BodyText"],  fontName=BN_FONT, fontSize=8,  leading=11,
                        textColor=colors.grey)

    tier = scan["risk_tier"]
    label = LABELS[tier]
    reasons = scan.get("reasons", [])
    d = scan.get("document", {})

    def p(text: str, style=P):
        return Paragraph(text, style)

    story: List[Any] = []

    # ---------- Page 1: cover ----------
    story.append(p("ProbashiGuard", H1))
    story.append(p("স্বপ্ন হোক বিদেশের, ভরসা থাকুক দেশের।", SM))
    story.append(Spacer(1, 8 * mm))
    story.append(p(f"Audit Report — {scan['id']}", H2))
    story.append(Spacer(1, 4 * mm))
    tier_table = Table(
        [[f"RISK TIER {tier}", label["status_en"], label["status_bn"]]],
        colWidths=[35 * mm, 75 * mm, 60 * mm],
    )
    tier_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(label["color"])),
        ("TEXTCOLOR",  (0, 0), (-1, -1), colors.white),
        ("FONTNAME",   (0, 0), (-1, -1), BN_FONT),
        ("FONTSIZE",   (0, 0), (-1, -1), 11),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(tier_table)
    story.append(Spacer(1, 8 * mm))
    story.append(p(f"<b>Generated:</b> {scan.get('created_at', '—')}"))
    story.append(p(f"<b>Worker:</b> {scan.get('worker_name') or _mask_phone(scan.get('worker_phone', ''))}"))
    story.append(p(f"<b>Destination:</b> {d.get('country', '—')}"))
    story.append(p(f"<b>Record hash:</b> {scan.get('record_hash', '—')}"))
    story.append(PageBreak())

    # ---------- Page 2: worker & migration summary ----------
    story.append(p("1. Worker & Migration Summary", H2))
    story.append(Spacer(1, 3 * mm))
    rows = [
        ["Field", "Value"],
        ["Name (from e-KYC)", (scan.get("nid") or {}).get("name_en", "—")],
        ["Phone",             _mask_phone(scan.get("worker_phone", ""))],
        ["Destination",       d.get("country", "—")],
        ["Visa type",         d.get("visa_type", "—")],
        ["Employer",          d.get("employer", "—")],
        ["Agency",            d.get("agency", "—")],
        ["Agency RL",         d.get("agency_rl", "—")],
        ["Offered salary",    f"{d.get('salary', '—')} {d.get('currency', '')}".strip()],
    ]
    t = Table(rows, colWidths=[55 * mm, 115 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, -1), BN_FONT),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(PageBreak())

    # ---------- Page 3: document analysis ----------
    story.append(p("2. Document Analysis", H2))
    story.append(Spacer(1, 3 * mm))
    story.append(p(f"<b>Document type:</b> {d.get('document_type', '—')}"))
    story.append(p(f"<b>Country:</b> {d.get('country', '—')}"))
    story.append(p(f"<b>Contract terms:</b>"))
    for term in d.get("contract_terms", []):
        story.append(p(f"• {term}"))
    story.append(Spacer(1, 4 * mm))
    story.append(p("Forensic findings", H2))
    if not d.get("forensic_findings"):
        story.append(p("No forensic anomalies detected."))
    else:
        for f in d["forensic_findings"]:
            story.append(p(f"• <b>[{f.get('severity', '?').upper()}]</b> "
                           f"{f.get('code', '')}: {f.get('message', '')}"))
    story.append(PageBreak())

    # ---------- Page 4: risk reasons ----------
    story.append(p("3. Risk Reasons (explainable)", H2))
    story.append(Spacer(1, 3 * mm))
    if not reasons:
        story.append(p("No risk reasons triggered. Verdict is Tier 1."))
    else:
        rrows = [["Code", "Tier", "Reason (English)", "কারণ (বাংলা)"]]
        for r in reasons:
            rrows.append([r["code"], str(r["tier"]), r["message_en"], r["message_bn"]])
        rt = Table(rrows, colWidths=[38 * mm, 12 * mm, 60 * mm, 60 * mm])
        rt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, -1), BN_FONT),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("GRID",       (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(rt)
    story.append(PageBreak())

    # ---------- Page 5: guidance ----------
    story.append(p("4. What You Should Do Next", H2))
    story.append(Spacer(1, 3 * mm))
    story.append(p(GUIDE[tier]["en"]))
    story.append(Spacer(1, 4 * mm))
    story.append(p(GUIDE[tier]["bn"]))
    story.append(Spacer(1, 6 * mm))
    story.append(p("<b>Emergency contacts</b>", H2))
    story.append(p("• BMET helpline: 16135"))
    story.append(p("• Probashi Kalyan Desk: 01711-111999"))
    story.append(p("• OKUP: 01711-590200"))
    story.append(PageBreak())

    # ---------- Page 6: verify ----------
    story.append(p("5. Verify This Report", H2))
    story.append(Spacer(1, 3 * mm))
    story.append(p("Scan the QR below, or visit the URL, to confirm this report is genuine. "
                   "The verification page never shows your personal information."))
    story.append(Spacer(1, 6 * mm))
    verify_url = scan.get("verify_url") or ""
    if verify_url:
        qr_buf = _qr_png(verify_url)
        story.append(RLImage(qr_buf, width=45 * mm, height=45 * mm))
        story.append(Spacer(1, 4 * mm))
        story.append(p(f"<b>Verify URL:</b> {verify_url}", SM))
    story.append(p(f"<b>Record hash:</b> {scan.get('record_hash', '—')}", SM))

    # ---------- Admin-only pages 7-9 ----------
    if viewer == "admin":
        story.append(PageBreak())
        story.append(p("6. Chain of Custody (internal)", H2))
        story.append(Spacer(1, 3 * mm))
        x = scan.get("_extras", {})
        crows = [
            ["Field", "Value"],
            ["Image SHA-256",       x.get("image_sha256", "—")],
            ["File size (bytes)",   str(x.get("file_size", "—"))],
            ["Device hint",         x.get("device_hint", "—")],
            ["IP hash",             x.get("ip_hash", "—")],
            ["Processing time (ms)", str(x.get("processing_ms", "—"))],
            ["AI model",            x.get("model", "—")],
        ]
        ct = Table(crows, colWidths=[45 * mm, 125 * mm])
        ct.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, -1), BN_FONT),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("GRID",       (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ]))
        story.append(ct)

        story.append(PageBreak())
        story.append(p("7. Review History & Internal Notes (internal)", H2))
        story.append(Spacer(1, 3 * mm))
        hist = scan.get("review_history", [])
        if not hist:
            story.append(p("No reviews yet."))
        else:
            hr = [["When", "Actor", "Action", "Note"]]
            for h in hist:
                hr.append([h.get("ts", ""), h.get("actor", ""), h.get("action", ""), h.get("note", "")])
            ht = Table(hr, colWidths=[35 * mm, 30 * mm, 30 * mm, 75 * mm])
            ht.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                ("FONTNAME",   (0, 0), (-1, -1), BN_FONT),
                ("FONTSIZE",   (0, 0), (-1, -1), 8),
                ("GRID",       (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(ht)
        story.append(Spacer(1, 6 * mm))
        story.append(p("Internal notes", H2))
        notes = scan.get("notes", [])
        if not notes:
            story.append(p("No notes."))
        else:
            for n in notes:
                story.append(p(f"• <b>{n.get('actor', '')}</b> ({n.get('ts', '')}): {n.get('note', '')}"))

        story.append(PageBreak())
        story.append(p("8. Raw Analysis JSON (internal)", H2))
        story.append(Spacer(1, 3 * mm))
        raw = json.dumps(d.get("raw", {}), indent=2, ensure_ascii=False)
        for line in raw.splitlines()[:200]:
            story.append(p(line.replace("&", "&amp;").replace("<", "&lt;"), SM))

    doc.build(story)
    return buf.getvalue()


# ============================================================
# 9. ROUTES — AUTH
# ============================================================

@app.post("/auth/request-otp")
def request_otp(body: PhoneBody) -> dict:
    phone = body.phone.strip()
    if not phone.startswith("+880") or len(phone) < 13:
        raise HTTPException(status_code=400, detail="Only +880 numbers are supported")
    otp = f"{int(hashlib.sha256((phone + str(time.time())).encode()).hexdigest(), 16) % 1000000:06d}"
    _otp[phone] = {"otp": otp, "expires_at": time.time() + OTP_TTL_SECONDS}
    out = {"sent": True, "phone": phone}
    if DEV_MODE:
        out["dev_otp"] = otp
    return out


@app.post("/auth/verify-otp")
async def verify_otp(body: OtpBody, db: AsyncSession = Depends(get_db)) -> dict:
    phone = body.phone.strip()
    supplied = body.otp.strip()

    rec = _otp.get(phone)
    real_otp_ok = rec and rec["expires_at"] >= time.time() and rec["otp"] == supplied
    # In DEV_MODE, also accept universal 000000 (serverless OTP dict may be lost between requests)
    dev_bypass = DEV_MODE and supplied == "000000"
    if not real_otp_ok and not dev_bypass:
        raise HTTPException(status_code=401, detail="Invalid or expired OTP")

    _otp.pop(phone, None)

    u = (await db.execute(select(User).where(User.phone == phone))).scalar_one_or_none()
    if not u:
        u = User(phone=phone, role="worker", name="Worker")
        db.add(u)
        await db.commit()
        await db.refresh(u)

    return {
        "access_token": _make_token(phone, u.role),
        "token_type":   "bearer",
        "user": {"phone": u.phone, "role": u.role, "name": u.name},
    }


@app.get("/auth/me")
def me(user: dict = Depends(current_user)) -> dict:
    return {
        "phone":        user["phone"],
        "role":         user["role"],
        "name":         user.get("name"),
        "nid_verified": bool(user.get("nid_verified")),
        "has_nid":      user.get("nid") is not None,
        "has_face":     user.get("face") is not None,
    }


# ============================================================
# 10. ROUTES — KYC
# ============================================================

@app.post("/kyc/nid")
async def kyc_nid(
    nid_front: UploadFile = File(...),
    nid_back:  UploadFile = File(...),
    user: dict = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    front = await nid_front.read()
    back  = await nid_back.read()
    if not front or not back:
        raise HTTPException(status_code=400, detail="Both NID images are required")
    nid = extract_nid(front, back)

    u = (await db.execute(select(User).where(User.phone == user["phone"]))).scalar_one()
    u.nid_data = nid
    u.nid_verified = True
    await db.commit()
    return {"status": "NID_EXTRACTED", "nid": nid}


@app.post("/kyc/face")
async def kyc_face(
    selfie:    UploadFile = File(...),
    nid_photo: UploadFile = File(...),
    user: dict = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    s = await selfie.read()
    n = await nid_photo.read()
    if not s or not n:
        raise HTTPException(status_code=400, detail="Both images are required")
    face = match_face(s, n)

    u = (await db.execute(select(User).where(User.phone == user["phone"]))).scalar_one()
    u.face_data = face
    await db.commit()
    return {"status": "KYC_VERIFIED" if face.get("match") else "KYC_FAILED", "face": face}


# ============================================================
# 11. ROUTES — SCAN
# ============================================================

@app.post("/scan")
async def create_scan(
    request: Request,
    document: UploadFile = File(...),
    mock_scenario: Optional[str] = Form(None),
    user: dict = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    data = await document.read()
    if not data:
        raise HTTPException(status_code=400, detail="Document image required")

    t0 = time.time()
    doc = scan_document(data, mock_scenario)
    scan_id = uuid.uuid4().hex[:12]
    created_at = datetime.now(timezone.utc)
    image_sha = hashlib.sha256(data).hexdigest()

    base_url = PUBLIC_BASE_URL or str(request.base_url).rstrip("/")
    extras = {
        "image_sha256":  image_sha,
        "file_size":     len(data),
        "device_hint":   (request.headers.get("user-agent", "") or "")[:200],
        "ip_hash":       hashlib.sha256(
            (request.client.host if request.client else "unknown").encode()
        ).hexdigest()[:16],
        "processing_ms": int((time.time() - t0) * 1000),
        "model":         "gemini-2.5-flash" if not USE_MOCK else "mock",
    }

    # Build the in-memory scan dict for classify() and record_hash
    scan = {
        "id":           scan_id,
        "worker_phone": user["phone"],
        "worker_name":  (user.get("nid") or {}).get("name_en"),
        "created_at":   created_at.isoformat(),
        "document":     doc,
        "nid":          user.get("nid"),
        "face":         user.get("face"),
        "_extras":      extras,
        "review_status": "pending",
        "review_history": [],
        "notes":        [],
        "verify_url":   f"{base_url}/verify/{scan_id}",
    }
    tier, reasons, status_en, status_bn = classify(scan, user)
    scan["risk_tier"] = tier
    scan["reasons"]   = reasons
    scan["status_en"] = status_en
    scan["status_bn"] = status_bn

    record_hash = hashlib.sha256(
        f"{scan_id}|{tier}|{created_at.isoformat()}|{image_sha}".encode()
    ).hexdigest()[:32]
    scan["record_hash"] = record_hash

    new_scan = Scan(
        id=scan_id,
        worker_phone=user["phone"],
        created_at=created_at,
        risk_tier=tier,
        status_en=status_en,
        status_bn=status_bn,
        reasons=reasons,
        document_data=doc,
        review_status="pending",
        review_history=[],
        notes=[],
        image_sha256=image_sha,
        file_size=extras["file_size"],
        device_hint=extras["device_hint"],
        ip_hash=extras["ip_hash"],
        processing_ms=extras["processing_ms"],
        model=extras["model"],
        record_hash=record_hash,
        verify_url=scan["verify_url"],
    )
    db.add(new_scan)
    await db.commit()

    return _redact_scan(scan, "worker")


@app.get("/scans")
async def my_scans(
    user: dict = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> list:
    rows = (await db.execute(
        select(Scan).where(Scan.worker_phone == user["phone"]).order_by(Scan.created_at.desc())
    )).scalars().all()
    out = []
    for s in rows:
        d = scan_to_dict(s)
        out.append(_redact_scan(d, "worker"))
    return out


@app.get("/scan/{scan_id}")
async def get_scan(
    scan_id: str,
    user: dict = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    scan = await load_scan_with_user(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if user["role"] == "worker" and scan["worker_phone"] != user["phone"]:
        raise HTTPException(status_code=403, detail="Not your scan")
    viewer = "worker" if user["role"] == "worker" else "admin"
    return _redact_scan(scan, viewer)


@app.get("/scan/{scan_id}/pdf")
async def scan_pdf(
    scan_id: str,
    user: dict = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    scan = await load_scan_with_user(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if user["role"] == "worker" and scan["worker_phone"] != user["phone"]:
        raise HTTPException(status_code=403, detail="Not your scan")

    if user["role"] == "worker":
        scan_for_pdf = _redact_scan(scan, "worker")
        viewer = "worker"
    else:
        scan_for_pdf = scan
        viewer = "admin"

    pdf = build_pdf(scan_for_pdf, viewer)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="ProbashiGuard-{scan_id}.pdf"'},
    )


# ============================================================
# 12. ROUTES — ADMIN
# ============================================================

@app.get("/admin/scans")
async def admin_scans(
    tier:          Optional[int] = None,
    review_status: Optional[str] = None,
    agency:        Optional[str] = None,
    user: dict = Depends(staff_required),
    db: AsyncSession = Depends(get_db),
) -> dict:
    query = select(Scan)
    if tier:
        query = query.where(Scan.risk_tier == tier)
    if review_status:
        query = query.where(Scan.review_status == review_status)
    if agency:
        query = query.where(Scan.document_data["agency_rl"].astext == agency)
    query = query.order_by(Scan.created_at.desc())

    rows = (await db.execute(query)).scalars().all()

    total   = (await db.execute(select(func.count(Scan.id)))).scalar() or 0
    tier34  = (await db.execute(select(func.count(Scan.id)).where(Scan.risk_tier >= 3))).scalar() or 0
    pending = (await db.execute(select(func.count(Scan.id)).where(Scan.review_status == "pending"))).scalar() or 0

    summaries = []
    for s in rows:
        doc = s.document_data or {}
        summaries.append({
            "id":            s.id,
            "created_at":    s.created_at.isoformat() if s.created_at else None,
            "worker_phone":  _mask_phone(s.worker_phone),
            "tier":          s.risk_tier,
            "status_en":     s.status_en,
            "agency":        doc.get("agency", "—"),
            "country":       doc.get("country", "—"),
            "review_status": s.review_status,
        })

    return {
        "scans": summaries,
        "stats": {"total": total, "tier34": tier34, "pending": pending},
    }


@app.get("/admin/scans/{scan_id}")
async def admin_scan_detail(
    scan_id: str,
    user: dict = Depends(staff_required),
    db: AsyncSession = Depends(get_db),
) -> dict:
    scan = await load_scan_with_user(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _redact_scan(scan, "admin")


@app.post("/admin/scans/{scan_id}/review")
async def admin_review(
    scan_id: str,
    body: ReviewBody,
    user: dict = Depends(staff_required),
    db: AsyncSession = Depends(get_db),
) -> dict:
    s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")

    allowed = {"in_review", "escalate", "resolve", "confirm_fraud", "false_positive"}
    if body.action not in allowed:
        raise HTTPException(status_code=400, detail=f"action must be one of {sorted(allowed)}")
    if body.action in ("confirm_fraud", "false_positive") and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can confirm fraud / false positive")

    history = list(s.review_history or [])
    history.append({
        "ts":     now_iso(),
        "actor":  user["phone"],
        "role":   user["role"],
        "action": body.action,
        "note":   body.note,
    })
    s.review_history = history
    s.review_status = body.action

    add_audit(db, user, f"review:{body.action}", scan_id, body.note)
    await db.commit()
    return {"ok": True, "review_status": s.review_status}


@app.post("/admin/scans/{scan_id}/notes")
async def admin_note(
    scan_id: str,
    body: NoteBody,
    user: dict = Depends(staff_required),
    db: AsyncSession = Depends(get_db),
) -> dict:
    s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not body.note.strip():
        raise HTTPException(status_code=400, detail="Note cannot be empty")

    notes = list(s.notes or [])
    notes.append({"ts": now_iso(), "actor": user["phone"], "note": body.note.strip()})
    s.notes = notes

    add_audit(db, user, "note", scan_id, body.note.strip())
    await db.commit()
    return {"ok": True}


@app.get("/admin/audit")
async def admin_audit_log(
    user: dict = Depends(admin_required),
    db: AsyncSession = Depends(get_db),
) -> list:
    rows = (await db.execute(
        select(AdminAudit).order_by(AdminAudit.ts.desc()).limit(500)
    )).scalars().all()
    return [{
        "id":             str(a.id),
        "ts":             a.ts.isoformat() if a.ts else None,
        "actor_phone":    a.actor_phone,
        "actor_role":     a.actor_role,
        "action":         a.action,
        "target_scan_id": a.target_scan_id,
        "note":           a.note,
    } for a in rows]


# ============================================================
# 13. PUBLIC VERIFY
# ============================================================

@app.get("/verify/{scan_id}", response_class=HTMLResponse)
async def verify_scan(scan_id: str, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if not s:
        return HTMLResponse(
            "<html><body style='font-family:sans-serif;padding:2rem;text-align:center'>"
            "<h2>Report not found</h2><p>This report ID does not exist.</p>"
            "</body></html>", status_code=404,
        )
    color = LABELS[s.risk_tier]["color"]
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Verify — ProbashiGuard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{font-family:system-ui,sans-serif;background:#f8fafc;margin:0;padding:2rem;}}
.card{{max-width:520px;margin:0 auto;background:white;border-radius:12px;
padding:2rem;box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center;}}
.badge{{display:inline-block;padding:.5rem 1rem;border-radius:8px;color:white;
background:{color};font-weight:600;margin:1rem 0;}}
.hash{{font-family:monospace;font-size:.8rem;color:#64748b;word-break:break-all;}}
h1{{margin:0 0 .5rem 0;}}</style></head><body>
<div class="card">
<h1>✓ Genuine Report</h1>
<p>This is a real ProbashiGuard audit record.</p>
<div class="badge">Tier {s.risk_tier} — {s.status_en}</div>
<p style="color:#475569">{s.status_bn}</p>
<p><strong>Report ID:</strong> {s.id}<br>
<strong>Issued:</strong> {s.created_at.isoformat() if s.created_at else '—'}</p>
<p class="hash">Record hash: {s.record_hash}</p>
<p style="color:#94a3b8;font-size:.85rem;margin-top:2rem">
Worker personal information is not shown on this page.</p>
</div></body></html>"""
    return HTMLResponse(html)


# ============================================================
# 14. HTML ROUTES
# ============================================================

@app.get("/", response_class=HTMLResponse)
def worker_app() -> HTMLResponse:
    return HTMLResponse(WORKER_HTML)


@app.get("/admin", response_class=HTMLResponse)
def admin_app() -> HTMLResponse:
    return HTMLResponse(ADMIN_HTML)


# ============================================================
# 15. FRONTEND — WORKER APP
# ============================================================

WORKER_HTML = r"""<!doctype html>
<html lang="bn">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ProbashiGuard — শ্রমিক অ্যাপ</title>
<style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;background:#f1f5f9;color:#0f172a}
header{background:#0f172a;color:white;padding:1rem;text-align:center}
header h1{margin:0;font-size:1.1rem}
header p{margin:.25rem 0 0;font-size:.8rem;opacity:.75}
main{max-width:520px;margin:0 auto;padding:1rem}
.screen{display:none;background:white;border-radius:12px;padding:1.25rem;margin-bottom:1rem;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.screen.active{display:block}
h2{margin:0 0 1rem 0;font-size:1.1rem}
label{display:block;font-weight:600;margin:.75rem 0 .25rem;font-size:.9rem}
input,select,button{width:100%;padding:.75rem;font-size:1rem;border:1px solid #cbd5e1;border-radius:8px;background:white}
button{background:#0f172a;color:white;border:none;font-weight:600;cursor:pointer;margin-top:1rem}
button:disabled{opacity:.5;cursor:not-allowed}
button.secondary{background:#e2e8f0;color:#0f172a;margin-top:.5rem}
.hint{font-size:.8rem;color:#64748b;margin-top:.5rem}
.dev{background:#fef3c7;border:1px solid #f59e0b;padding:.75rem;border-radius:8px;margin-top:.75rem;font-size:.9rem}
.tier{display:inline-block;padding:.5rem 1rem;border-radius:8px;color:white;font-weight:700;margin:.5rem 0}
.reason{padding:.75rem;border-left:4px solid #f97316;background:#fff7ed;margin:.5rem 0;border-radius:4px;font-size:.9rem}
.reason.bn{color:#475569;font-size:.85rem;margin-top:.25rem}
.reason .code{font-family:monospace;font-size:.75rem;color:#94a3b8}
.bn{font-size:.85rem;color:#475569;margin-top:.25rem}
.link{background:none;border:none;color:#0f172a;text-decoration:underline;cursor:pointer;padding:0;font-size:.85rem;margin-top:.75rem;width:auto}
</style>
</head>
<body>
<header>
  <h1>ProbashiGuard</h1>
  <p>স্বপ্ন হোক বিদেশের, ভরসা থাকুক দেশের।</p>
</header>
<main id="app">
  <section id="screen-phone" class="screen active">
    <h2>শুরু করুন / Get started</h2>
    <label>মোবাইল নম্বর / Phone (+880)</label>
    <input id="phone" type="tel" placeholder="+88017XXXXXXXX" autocomplete="tel">
    <button onclick="requestOtp()">OTP পাঠান / Send OTP</button>
    <div id="dev-otp" class="dev" style="display:none"></div>
  </section>
  <section id="screen-otp" class="screen">
    <h2>OTP যাচাই / Verify OTP</h2>
    <label>৬ সংখ্যার কোড / 6-digit code</label>
    <input id="otp" type="text" inputmode="numeric" maxlength="6" placeholder="______">
    <button onclick="verifyOtp()">যাচাই করুন / Verify</button>
    <button class="secondary" onclick="show('screen-phone')">← ফিরে যান</button>
  </section>
  <section id="screen-kyc" class="screen">
    <h2>পরিচয় যাচাই / Identity verification</h2>
    <p class="bn">আপনার NID কার্ডের সামনের ও পিছনের ছবি আপলোড করুন।</p>
    <label>NID সামনে / NID front</label>
    <input id="nid-front" type="file" accept="image/*">
    <label>NID পিছনে / NID back</label>
    <input id="nid-back" type="file" accept="image/*">
    <button onclick="uploadNid()">NID যাচাই / Verify NID</button>
    <hr style="margin:1.25rem 0;border:none;border-top:1px solid #e2e8f0">
    <label>সেলফি / Selfie</label>
    <input id="selfie" type="file" accept="image/*" capture="user">
    <label>NID-এর ছবি / NID photo</label>
    <input id="nid-photo" type="file" accept="image/*">
    <button onclick="uploadFace()">মুখ যাচাই / Verify face</button>
    <div id="kyc-status" class="hint"></div>
  </section>
  <section id="screen-scan" class="screen">
    <h2>নথি স্ক্যান করুন / Scan document</h2>
    <p class="bn">ভিসা বা চুক্তিপত্রের ছবি তুলুন।</p>
    <label>ছবি / Document photo</label>
    <input id="doc" type="file" accept="image/*" capture="environment">
    <div id="mock-scenario" style="display:none">
      <label>ডেমো পরিস্থিতি / Demo scenario (MOCK mode)</label>
      <select id="scenario">
        <option value="tier1">Tier 1 — Clean</option>
        <option value="tier2">Tier 2 — Minor issues</option>
        <option value="tier3">Tier 3 — Suspicious</option>
        <option value="tier4">Tier 4 — Forged</option>
      </select>
    </div>
    <button onclick="doScan()">স্ক্যান করুন / Scan</button>
    <button class="link" onclick="loadHistory()">আমার রিপোর্ট / My reports</button>
  </section>
  <section id="screen-verdict" class="screen">
    <h2>ফলাফল / Verdict</h2>
    <div id="verdict-body"></div>
    <button onclick="downloadPdf()">PDF ডাউনলোড / Download PDF</button>
    <button class="secondary" onclick="show('screen-scan')">আরেকটি স্ক্যান / Scan another</button>
    <button class="link" onclick="loadHistory()">আমার রিপোর্ট / My reports</button>
  </section>
  <section id="screen-history" class="screen">
    <h2>আমার রিপোর্ট / My reports</h2>
    <div id="history-body"></div>
    <button class="secondary" onclick="show('screen-scan')">← ফিরে যান</button>
  </section>
</main>
<script>
const state = { token: localStorage.getItem('pg_token') || null, lastScan: null, mock: false };
function show(id){
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}
async function api(path, opts={}){
  const headers = Object.assign({}, opts.headers || {});
  if (state.token) headers['Authorization'] = 'Bearer ' + state.token;
  if (!(opts.body instanceof FormData) && opts.body && typeof opts.body === 'object'){
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  if (!res.ok){
    const txt = await res.text();
    let msg = txt;
    try { msg = JSON.parse(txt).detail || txt; } catch(e){}
    throw new Error(msg);
  }
  return res;
}
async function requestOtp(){
  try {
    const phone = document.getElementById('phone').value.trim();
    const r = await api('/auth/request-otp', { method:'POST', body:{ phone } });
    const j = await r.json();
    if (j.dev_otp){
      const el = document.getElementById('dev-otp');
      el.style.display = 'block';
      el.textContent = 'DEV OTP: ' + j.dev_otp + '  (or use 000000)';
    }
    show('screen-otp');
  } catch(e){ alert('Error: ' + e.message); }
}
async function verifyOtp(){
  try {
    const phone = document.getElementById('phone').value.trim();
    const otp = document.getElementById('otp').value.trim();
    const r = await api('/auth/verify-otp', { method:'POST', body:{ phone, otp } });
    const j = await r.json();
    state.token = j.access_token;
    localStorage.setItem('pg_token', state.token);
    await afterLogin();
  } catch(e){ alert('Error: ' + e.message); }
}
async function afterLogin(){
  const r = await api('/auth/me');
  const me = await r.json();
  if (me.role !== 'worker'){ location.href = '/admin'; return; }
  if (!me.has_nid || !me.has_face) show('screen-kyc');
  else show('screen-scan');
}
async function uploadNid(){
  try {
    const fd = new FormData();
    const f1 = document.getElementById('nid-front').files[0];
    const f2 = document.getElementById('nid-back').files[0];
    if (!f1 || !f2) return alert('Both NID images required');
    fd.append('nid_front', f1); fd.append('nid_back', f2);
    const r = await api('/kyc/nid', { method:'POST', body:fd });
    const j = await r.json();
    document.getElementById('kyc-status').textContent = '✓ NID extracted for ' + j.nid.name_en;
  } catch(e){ alert('Error: ' + e.message); }
}
async function uploadFace(){
  try {
    const fd = new FormData();
    const f1 = document.getElementById('selfie').files[0];
    const f2 = document.getElementById('nid-photo').files[0];
    if (!f1 || !f2) return alert('Both photos required');
    fd.append('selfie', f1); fd.append('nid_photo', f2);
    const r = await api('/kyc/face', { method:'POST', body:fd });
    const j = await r.json();
    if (j.status === 'KYC_VERIFIED'){
      document.getElementById('kyc-status').textContent = '✓ Face verified. Redirecting…';
      setTimeout(() => show('screen-scan'), 600);
    } else {
      document.getElementById('kyc-status').textContent = '✗ Face match failed';
    }
  } catch(e){ alert('Error: ' + e.message); }
}
async function doScan(){
  try {
    const f = document.getElementById('doc').files[0];
    if (!f) return alert('Choose a document image');
    const fd = new FormData();
    fd.append('document', f);
    if (state.mock){
      const sc = document.getElementById('scenario').value;
      fd.append('mock_scenario', sc);
    }
    const r = await api('/scan', { method:'POST', body:fd });
    state.lastScan = await r.json();
    renderVerdict(state.lastScan);
    show('screen-verdict');
  } catch(e){ alert('Error: ' + e.message); }
}
function renderVerdict(s){
  const colors = {1:'#16a34a',2:'#eab308',3:'#f97316',4:'#dc2626'};
  let html = `<div class="tier" style="background:${colors[s.risk_tier]}">Tier ${s.risk_tier} — ${s.status_en}</div>`;
  html += `<div class="bn">${s.status_bn}</div>`;
  html += `<p style="font-size:.8rem;color:#64748b;margin-top:.5rem">Report ID: ${s.id}</p>`;
  if (s.reasons && s.reasons.length){
    html += '<h3 style="margin-top:1rem;font-size:.95rem">কারণ / Reasons</h3>';
    for (const r of s.reasons){
      html += `<div class="reason"><div class="code">${r.code} · tier ${r.tier}</div>`
            + `<div>${r.message_en}</div><div class="reason bn">${r.message_bn}</div></div>`;
    }
  } else {
    html += '<p style="color:#16a34a;margin-top:1rem">✓ কোনো সমস্যা পাওয়া যায়নি / No issues found</p>';
  }
  document.getElementById('verdict-body').innerHTML = html;
}
async function downloadPdf(){
  if (!state.lastScan) return;
  const r = await api('/scan/' + state.lastScan.id + '/pdf');
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'ProbashiGuard-' + state.lastScan.id + '.pdf';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function loadHistory(){
  try {
    const r = await api('/scans');
    const list = await r.json();
    const body = document.getElementById('history-body');
    if (!list.length){ body.innerHTML = '<p>কোনো রিপোর্ট নেই / No reports yet.</p>'; }
    else {
      const colors = {1:'#16a34a',2:'#eab308',3:'#f97316',4:'#dc2626'};
      body.innerHTML = list.map(s =>
        `<div class="reason" style="border-left-color:${colors[s.risk_tier]}">
           <div style="font-weight:600">Tier ${s.risk_tier} — ${s.status_en}</div>
           <div class="code">${s.id} · ${s.created_at || ''}</div>
           <button class="link" onclick="viewScan('${s.id}')">দেখুন / View</button>
         </div>`).join('');
    }
    show('screen-history');
  } catch(e){ alert('Error: ' + e.message); }
}
async function viewScan(id){
  const r = await api('/scan/' + id);
  state.lastScan = await r.json();
  renderVerdict(state.lastScan);
  show('screen-verdict');
}
(async function init(){
  try {
    const r = await fetch('/config');
    const cfg = await r.json();
    state.mock = !!cfg.mock;
    document.getElementById('mock-scenario').style.display = state.mock ? 'block' : 'none';
  } catch(e){}
  if (state.token){
    try { await afterLogin(); } catch(e){ localStorage.removeItem('pg_token'); state.token = null; }
  }
})();
</script>
</body>
</html>
"""


# ============================================================
# 16. FRONTEND — ADMIN DASHBOARD
# ============================================================

ADMIN_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ProbashiGuard — Staff</title>
<style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;background:#f1f5f9;color:#0f172a}
header{background:#0f172a;color:white;padding:1rem 1.5rem;display:flex;justify-content:space-between;align-items:center}
header h1{margin:0;font-size:1rem}
header nav a{color:white;text-decoration:none;margin-left:1.5rem;font-size:.9rem;opacity:.8}
header nav a:hover{opacity:1}
main{max-width:1100px;margin:0 auto;padding:1.5rem}
.screen{display:none}
.screen.active{display:block}
.panel{background:white;border-radius:12px;padding:1.5rem;margin-bottom:1rem;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1rem}
.stat{background:white;border-radius:12px;padding:1rem 1.25rem;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.stat .num{font-size:1.8rem;font-weight:700}
.stat .lbl{font-size:.85rem;color:#64748b}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{padding:.6rem .5rem;text-align:left;border-bottom:1px solid #e2e8f0}
th{background:#f8fafc;font-weight:600;color:#475569;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em}
tr:hover td{background:#f8fafc;cursor:pointer}
.tier{display:inline-block;padding:.15rem .5rem;border-radius:4px;color:white;font-size:.75rem;font-weight:600}
.badge{padding:.15rem .5rem;border-radius:4px;font-size:.75rem;font-weight:600;background:#e2e8f0}
.badge.pending{background:#fef3c7;color:#92400e}
.badge.in_review{background:#dbeafe;color:#1e40af}
.badge.escalate{background:#fed7aa;color:#9a3412}
.badge.resolve{background:#dcfce7;color:#166534}
.badge.confirm_fraud{background:#fecaca;color:#991b1b}
.badge.false_positive{background:#e5e7eb;color:#374151}
button{padding:.6rem 1rem;border-radius:8px;border:none;font-weight:600;cursor:pointer;font-size:.9rem;background:#0f172a;color:white}
button.secondary{background:#e2e8f0;color:#0f172a}
button.small{padding:.35rem .75rem;font-size:.8rem}
input,select,textarea{width:100%;padding:.6rem;border:1px solid #cbd5e1;border-radius:8px;font-size:.9rem;font-family:inherit}
textarea{min-height:70px;resize:vertical}
label{display:block;font-weight:600;font-size:.85rem;margin:.75rem 0 .25rem}
.row{display:flex;gap:.5rem}
.row>*{flex:1}
.reason{padding:.6rem;border-left:4px solid #f97316;background:#fff7ed;margin:.35rem 0;border-radius:4px;font-size:.85rem}
.reason .code{font-family:monospace;font-size:.72rem;color:#94a3b8}
.note{padding:.5rem;background:#f8fafc;border-radius:4px;margin:.25rem 0;font-size:.85rem}
.mono{font-family:monospace;font-size:.78rem;color:#475569;word-break:break-all}
.dev{background:#fef3c7;border:1px solid #f59e0b;padding:.75rem;border-radius:8px;margin-top:.75rem;font-size:.9rem}
h2{margin:0 0 1rem;font-size:1.1rem}
h3{margin:1rem 0 .5rem;font-size:.95rem}
a{color:#0f172a}
</style>
</head>
<body>
<header>
  <h1>ProbashiGuard — Staff Dashboard</h1>
  <nav>
    <a href="#" onclick="go('screen-dashboard')">Scans</a>
    <a href="#" onclick="go('screen-audit')">Audit log</a>
    <a href="#" onclick="logout()">Logout</a>
  </nav>
</header>
<main>
  <section id="screen-login" class="screen active">
    <div class="panel" style="max-width:420px;margin:2rem auto">
      <h2>Staff login</h2>
      <label>Phone</label>
      <input id="phone" type="tel" placeholder="+880...">
      <button onclick="requestOtp()">Send OTP</button>
      <div id="dev-otp" class="dev" style="display:none"></div>
      <div id="otp-block" style="display:none">
        <label>OTP</label>
        <input id="otp" type="text" maxlength="6">
        <button onclick="verifyOtp()">Verify</button>
      </div>
    </div>
  </section>
  <section id="screen-dashboard" class="screen">
    <div class="stats">
      <div class="stat"><div class="num" id="stat-total">–</div><div class="lbl">Total scans</div></div>
      <div class="stat"><div class="num" id="stat-tier34">–</div><div class="lbl">Tier 3 / 4</div></div>
      <div class="stat"><div class="num" id="stat-pending">–</div><div class="lbl">Pending review</div></div>
    </div>
    <div class="panel">
      <h2>Scans</h2>
      <div class="row" style="margin-bottom:1rem">
        <select id="filter-tier" onchange="loadScans()">
          <option value="">All tiers</option>
          <option value="1">Tier 1</option><option value="2">Tier 2</option>
          <option value="3">Tier 3</option><option value="4">Tier 4</option>
        </select>
        <select id="filter-status" onchange="loadScans()">
          <option value="">All statuses</option>
          <option value="pending">Pending</option>
          <option value="in_review">In review</option>
          <option value="escalate">Escalated</option>
          <option value="resolve">Resolved</option>
          <option value="confirm_fraud">Confirmed fraud</option>
          <option value="false_positive">False positive</option>
        </select>
        <input id="filter-agency" placeholder="Filter by agency RL (e.g. RL-1234)" onchange="loadScans()">
      </div>
      <table>
        <thead><tr>
          <th>Scan ID</th><th>When</th><th>Worker</th><th>Tier</th>
          <th>Agency</th><th>Country</th><th>Review</th>
        </tr></thead>
        <tbody id="scan-table"></tbody>
      </table>
    </div>
  </section>
  <section id="screen-detail" class="screen">
    <div class="panel">
      <button class="secondary small" onclick="go('screen-dashboard')">← Back</button>
      <h2 id="detail-title" style="margin-top:1rem">Scan detail</h2>
      <div id="detail-body"></div>
    </div>
    <div class="panel">
      <h3>Review actions</h3>
      <div class="row">
        <select id="review-action">
          <option value="in_review">Mark in review</option>
          <option value="escalate">Escalate</option>
          <option value="resolve">Resolve</option>
          <option value="confirm_fraud">Confirm fraud (admin only)</option>
          <option value="false_positive">False positive (admin only)</option>
        </select>
        <input id="review-note" placeholder="Review note (optional)">
        <button onclick="submitReview()" style="flex:0 0 auto">Submit</button>
      </div>
      <h3 style="margin-top:1.5rem">Internal notes</h3>
      <textarea id="note-text" placeholder="Add an internal note..."></textarea>
      <button onclick="submitNote()" style="margin-top:.5rem">Add note</button>
      <h3 style="margin-top:1.5rem">Download</h3>
      <button onclick="downloadAdminPdf()">Download 9-page admin PDF</button>
    </div>
  </section>
  <section id="screen-audit" class="screen">
    <div class="panel">
      <h2>Audit log</h2>
      <table>
        <thead><tr><th>When</th><th>Actor</th><th>Role</th><th>Action</th><th>Scan</th><th>Note</th></tr></thead>
        <tbody id="audit-table"></tbody>
      </table>
    </div>
  </section>
</main>
<script>
const state = { token: localStorage.getItem('pg_token') || null, currentScan: null };
function go(id){
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  if (id === 'screen-dashboard') loadScans();
  if (id === 'screen-audit') loadAudit();
}
async function api(path, opts={}){
  const headers = Object.assign({}, opts.headers || {});
  if (state.token) headers['Authorization'] = 'Bearer ' + state.token;
  if (!(opts.body instanceof FormData) && opts.body && typeof opts.body === 'object'){
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  if (!res.ok){
    const txt = await res.text();
    let msg = txt;
    try { msg = JSON.parse(txt).detail || txt; } catch(e){}
    throw new Error(msg);
  }
  return res;
}
async function requestOtp(){
  try {
    const phone = document.getElementById('phone').value.trim();
    const r = await api('/auth/request-otp', { method:'POST', body:{ phone } });
    const j = await r.json();
    if (j.dev_otp){
      const el = document.getElementById('dev-otp');
      el.style.display = 'block';
      el.textContent = 'DEV OTP: ' + j.dev_otp + '  (or use 000000)';
    }
    document.getElementById('otp-block').style.display = 'block';
  } catch(e){ alert('Error: ' + e.message); }
}
async function verifyOtp(){
  try {
    const phone = document.getElementById('phone').value.trim();
    const otp = document.getElementById('otp').value.trim();
    const r = await api('/auth/verify-otp', { method:'POST', body:{ phone, otp } });
    const j = await r.json();
    if (j.user.role === 'worker'){ alert('Workers cannot access this dashboard'); return; }
    state.token = j.access_token;
    localStorage.setItem('pg_token', state.token);
    go('screen-dashboard');
  } catch(e){ alert('Error: ' + e.message); }
}
function logout(){
  localStorage.removeItem('pg_token'); state.token = null; go('screen-login');
}
async function loadScans(){
  try {
    const params = new URLSearchParams();
    const tier = document.getElementById('filter-tier').value;
    const st = document.getElementById('filter-status').value;
    const ag = document.getElementById('filter-agency').value.trim();
    if (tier) params.set('tier', tier);
    if (st) params.set('review_status', st);
    if (ag) params.set('agency', ag);
    const r = await api('/admin/scans?' + params.toString());
    const j = await r.json();
    document.getElementById('stat-total').textContent = j.stats.total;
    document.getElementById('stat-tier34').textContent = j.stats.tier34;
    document.getElementById('stat-pending').textContent = j.stats.pending;
    const colors = {1:'#16a34a',2:'#eab308',3:'#f97316',4:'#dc2626'};
    document.getElementById('scan-table').innerHTML = j.scans.map(s => `
      <tr onclick="openDetail('${s.id}')">
        <td class="mono">${s.id}</td>
        <td>${s.created_at ? new Date(s.created_at).toLocaleString() : ''}</td>
        <td>${s.worker_phone}</td>
        <td><span class="tier" style="background:${colors[s.tier]}">T${s.tier}</span></td>
        <td>${s.agency}</td>
        <td>${s.country}</td>
        <td><span class="badge ${s.review_status}">${s.review_status}</span></td>
      </tr>`).join('') || '<tr><td colspan="7" style="text-align:center;color:#94a3b8">No scans</td></tr>';
  } catch(e){
    if (e.message.includes('403') || e.message.includes('401')) { logout(); }
    else alert('Error: ' + e.message);
  }
}
async function openDetail(id){
  try {
    const r = await api('/admin/scans/' + id);
    const s = await r.json();
    state.currentScan = s;
    document.getElementById('detail-title').textContent = 'Scan ' + s.id;
    const colors = {1:'#16a34a',2:'#eab308',3:'#f97316',4:'#dc2626'};
    let html = `<div><span class="tier" style="background:${colors[s.risk_tier]};padding:.35rem .75rem;font-size:.9rem">Tier ${s.risk_tier}</span> <strong>${s.status_en}</strong></div>`;
    html += `<p style="color:#64748b;font-size:.85rem;margin:.5rem 0">${s.status_bn}</p>`;
    html += `<h3>Worker</h3><table>`;
    html += `<tr><td style="width:180px;color:#64748b">Phone</td><td>${s.worker_phone}</td></tr>`;
    html += `<tr><td style="color:#64748b">Name (e-KYC)</td><td>${(s.nid||{}).name_en || '—'}</td></tr>`;
    html += `<tr><td style="color:#64748b">NID</td><td>${(s.nid||{}).nid_number || '—'}</td></tr>`;
    html += `<tr><td style="color:#64748b">Face match</td><td>${(s.face||{}).match ? '✓ ' + (s.face.score||'') : '✗'}</td></tr>`;
    html += `</table>`;
    html += `<h3>Document</h3><table>`;
    html += `<tr><td style="width:180px;color:#64748b">Type</td><td>${s.document.document_type || '—'}</td></tr>`;
    html += `<tr><td style="color:#64748b">Country</td><td>${s.document.country || '—'}</td></tr>`;
    html += `<tr><td style="color:#64748b">Visa type</td><td>${s.document.visa_type || '—'}</td></tr>`;
    html += `<tr><td style="color:#64748b">Employer</td><td>${s.document.employer || '—'}</td></tr>`;
    html += `<tr><td style="color:#64748b">Agency</td><td>${s.document.agency || '—'} (${s.document.agency_rl || '—'})</td></tr>`;
    html += `<tr><td style="color:#64748b">Salary</td><td>${s.document.salary || '—'} ${s.document.currency || ''}</td></tr>`;
    html += `</table>`;
    html += `<h3>Risk reasons</h3>`;
    if (!s.reasons.length){ html += '<p style="color:#16a34a">No reasons triggered (Tier 1).</p>'; }
    else {
      for (const r of s.reasons){
        html += `<div class="reason"><div class="code">${r.code} · tier ${r.tier}</div><div>${r.message_en}</div><div style="color:#64748b;font-size:.8rem">${r.message_bn}</div></div>`;
      }
    }
    if (s.document.forensic_findings && s.document.forensic_findings.length){
      html += `<h3>Forensic findings</h3>`;
      for (const f of s.document.forensic_findings){
        html += `<div class="note"><strong>[${f.severity}]</strong> ${f.code}: ${f.message} <span class="mono">bbox=${JSON.stringify(f.bbox)}</span></div>`;
      }
    }
    if (s._extras){
      html += `<h3>Chain of custody</h3><table>`;
      for (const [k,v] of Object.entries(s._extras)){
        html += `<tr><td style="width:180px;color:#64748b">${k}</td><td class="mono">${v}</td></tr>`;
      }
      html += `</table>`;
    }
    if (s.review_history && s.review_history.length){
      html += `<h3>Review history</h3>`;
      for (const h of s.review_history){
        html += `<div class="note"><strong>${h.actor}</strong> (${h.role}) — ${h.action} @ ${h.ts}${h.note ? ' — ' + h.note : ''}</div>`;
      }
    }
    if (s.notes && s.notes.length){
      html += `<h3>Internal notes</h3>`;
      for (const n of s.notes){
        html += `<div class="note"><strong>${n.actor}</strong> @ ${n.ts}: ${n.note}</div>`;
      }
    }
    document.getElementById('detail-body').innerHTML = html;
    go('screen-detail');
  } catch(e){ alert('Error: ' + e.message); }
}
async function submitReview(){
  try {
    const action = document.getElementById('review-action').value;
    const note = document.getElementById('review-note').value.trim();
    const r = await api('/admin/scans/' + state.currentScan.id + '/review',
      { method:'POST', body:{ action, note } });
    const j = await r.json();
    document.getElementById('review-note').value = '';
    await openDetail(state.currentScan.id);
    alert('Review status: ' + j.review_status);
  } catch(e){ alert('Error: ' + e.message); }
}
async function submitNote(){
  try {
    const note = document.getElementById('note-text').value.trim();
    if (!note) return;
    await api('/admin/scans/' + state.currentScan.id + '/notes',
      { method:'POST', body:{ note } });
    document.getElementById('note-text').value = '';
    await openDetail(state.currentScan.id);
  } catch(e){ alert('Error: ' + e.message); }
}
async function downloadAdminPdf(){
  if (!state.currentScan) return;
  const r = await api('/scan/' + state.currentScan.id + '/pdf');
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'ProbashiGuard-admin-' + state.currentScan.id + '.pdf';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function loadAudit(){
  try {
    const r = await api('/admin/audit');
    const rows = await r.json();
    document.getElementById('audit-table').innerHTML = rows.map(x => `
      <tr>
        <td>${x.ts ? new Date(x.ts).toLocaleString() : ''}</td>
        <td>${x.actor_phone}</td>
        <td>${x.actor_role}</td>
        <td>${x.action}</td>
        <td class="mono">${x.target_scan_id || '—'}</td>
        <td>${x.note || ''}</td>
      </tr>`).join('') || '<tr><td colspan="6" style="text-align:center;color:#94a3b8">No entries</td></tr>';
  } catch(e){
    if (e.message.includes('403')) { alert('Admin only'); go('screen-dashboard'); }
    else alert('Error: ' + e.message);
  }
}
(async function init(){
  if (state.token){
    try {
      const r = await api('/auth/me');
      const me = await r.json();
      if (me.role === 'worker') { logout(); return; }
      go('screen-dashboard');
    } catch(e){ logout(); }
  }
})();
</script>
</body>
</html>
"""


# ============================================================
# 17. MAIN (local dev only — Vercel uses api/index.py)
# ============================================================

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    print(f"ProbashiGuard starting — MOCK={USE_MOCK}  DEV_MODE={DEV_MODE}")
    print(f"  Worker app : http://localhost:{port}/")
    print(f"  Admin app  : http://localhost:{port}/admin")
    uvicorn.run(app, host="0.0.0.0", port=port)
