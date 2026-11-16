# models.py
from sqlalchemy import Column, String, Integer, Boolean, BigInteger, DateTime, ForeignKey, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import declarative_base
import uuid

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    phone = Column(String, primary_key=True)
    role = Column(String, nullable=False, default="worker")
    name = Column(String)
    nid_verified = Column(Boolean, default=False)
    nid_data = Column(JSONB)
    face_data = Column(JSONB)
    created_at = Column(DateTime(timezone=True), server_default=text("now()"))

class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True)
    worker_phone = Column(String, ForeignKey("users.phone", ondelete="CASCADE"))
    created_at = Column(DateTime(timezone=True), server_default=text("now()"))
    risk_tier = Column(Integer, nullable=False)
    status_en = Column(String, nullable=False)
    status_bn = Column(String, nullable=False)
    reasons = Column(JSONB, default=list)
    document_data = Column(JSONB, nullable=False)
    review_status = Column(String, default="pending")
    review_history = Column(JSONB, default=list)
    notes = Column(JSONB, default=list)
    image_sha256 = Column(String)
    file_size = Column(BigInteger)
    device_hint = Column(String)
    ip_hash = Column(String)
    processing_ms = Column(Integer)
    model = Column(String)
    record_hash = Column(String, nullable=False)
    verify_url = Column(String)

class AdminAudit(Base):
    __tablename__ = "admin_audit"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ts = Column(DateTime(timezone=True), server_default=text("now()"))
    actor_phone = Column(String, ForeignKey("users.phone"))
    actor_role = Column(String)
    action = Column(String, nullable=False)
    target_scan_id = Column(String, ForeignKey("scans.id"))
    note = Column(String)
