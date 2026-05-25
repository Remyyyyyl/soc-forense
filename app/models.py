from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Float, ForeignKey, Index
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="viewer", nullable=False)  # 'admin' o 'viewer'
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relaciones
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    evidences = relationship("Evidence", back_populates="upload_user")


class Session(Base):
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    session_token = Column(String(500), unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relaciones
    user = relationship("User", back_populates="sessions")


class Evidence(Base):
    __tablename__ = "evidences"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    original_path = Column(String(500))
    log_type = Column(String(50), nullable=False)  # 'sudo', 'auth', 'audit'
    file_size = Column(Integer)
    sha256_hash = Column(String(64), unique=True, nullable=False, index=True)
    stored_path = Column(String(500), nullable=False)
    
    upload_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String(50), default="ingested", index=True)  # ingested, parsed, analyzed, error
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    parsed_at = Column(DateTime)
    analyzed_at = Column(DateTime)
    error_message = Column(Text)
    
    # Relaciones
    upload_user = relationship("User", back_populates="evidences")
    parsed_logs = relationship("ParsedLog", back_populates="evidence", cascade="all, delete-orphan")
    analysis_results = relationship("AnalysisResult", back_populates="evidence", cascade="all, delete-orphan")


class ParsedLog(Base):
    __tablename__ = "parsed_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(Integer, ForeignKey("evidences.id"), nullable=False, index=True)
    chunk_number = Column(Integer)
    
    # Campos genéricos parseados
    timestamp = Column(DateTime, index=True)
    hostname = Column(String(255))
    service = Column(String(100))
    pid = Column(Integer)
    raw_log = Column(Text)
    
    # Campos específicos por tipo
    parsed_user = Column(String(255), index=True)
    parsed_action = Column(String(255))
    parsed_target = Column(String(255))
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Índice compuesto
    __table_args__ = (
        Index('idx_evidence_chunk', 'evidence_id', 'chunk_number'),
    )
    
    # Relaciones
    evidence = relationship("Evidence", back_populates="parsed_logs")
    analysis_results = relationship("AnalysisResult", back_populates="parsed_log")


class AnalysisResult(Base):
    __tablename__ = "analysis_results"
    
    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(Integer, ForeignKey("evidences.id"), nullable=False, index=True)
    parsed_log_id = Column(Integer, ForeignKey("parsed_logs.id"))
    
    severity = Column(String(20), nullable=False, index=True)  # low, medium, high, critical
    threat_type = Column(String(100))
    threat_description = Column(Text)
    indicators = Column(Text)  # JSON array
    
    ai_explanation = Column(Text)
    confidence_score = Column(Float)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Índice compuesto
    __table_args__ = (
        Index('idx_evidence_severity', 'evidence_id', 'severity'),
    )
    
    # Relaciones
    evidence = relationship("Evidence", back_populates="analysis_results")
    parsed_log = relationship("ParsedLog", back_populates="analysis_results")


class DashboardStats(Base):
    __tablename__ = "dashboard_stats"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    total_evidences = Column(Integer, default=0)
    total_critical_threats = Column(Integer, default=0)
    total_high_threats = Column(Integer, default=0)
    total_medium_threats = Column(Integer, default=0)
    total_low_threats = Column(Integer, default=0)
    
    last_update = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
