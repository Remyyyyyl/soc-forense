from sqlalchemy.orm import Session
from app.models import Evidence
from app.schemas import AnalysisResultCreate, StatusEnum
from datetime import datetime
import json


class EvidenceCRUD:
    """CRUD operations para evidencias"""
    
    @staticmethod
    def create_evidence(
        db: Session,
        filename: str,
        log_type: str,
        file_size: int,
        sha256_hash: str,
        stored_path: str,
        upload_user_id: int,
        original_path: str = None
    ) -> Evidence:
        """Crear nuevo registro de evidencia"""
        db_evidence = Evidence(
            filename=filename,
            original_path=original_path,
            log_type=log_type,
            file_size=file_size,
            sha256_hash=sha256_hash,
            stored_path=stored_path,
            upload_user_id=upload_user_id,
            status="ingested"
        )
        db.add(db_evidence)
        db.commit()
        db.refresh(db_evidence)
        return db_evidence
    
    @staticmethod
    def get_evidence_by_id(db: Session, evidence_id: int) -> Evidence | None:
        """Obtener evidencia por ID"""
        return db.query(Evidence).filter(Evidence.id == evidence_id).first()
    
    @staticmethod
    def get_evidence_by_hash(db: Session, sha256_hash: str) -> Evidence | None:
        """Obtener evidencia por SHA-256 (evitar duplicados)"""
        return db.query(Evidence).filter(Evidence.sha256_hash == sha256_hash).first()
    
    @staticmethod
    def get_all_evidences(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        status: str = None,
        log_type: str = None
    ) -> list[Evidence]:
        """Obtener lista de evidencias con filtros opcionales"""
        query = db.query(Evidence)
        
        if status:
            query = query.filter(Evidence.status == status)
        if log_type:
            query = query.filter(Evidence.log_type == log_type)
        
        return query.offset(skip).limit(limit).all()
    
    @staticmethod
    def get_evidences_by_user(
        db: Session,
        user_id: int,
        skip: int = 0,
        limit: int = 50
    ) -> list[Evidence]:
        """Obtener evidencias subidas por un usuario específico"""
        return db.query(Evidence).filter(
            Evidence.upload_user_id == user_id
        ).offset(skip).limit(limit).all()
    
    @staticmethod
    def update_evidence_status(
        db: Session,
        evidence_id: int,
        status: str,
        error_message: str = None
    ) -> Evidence | None:
        """Actualizar estado de evidencia"""
        db_evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
        if db_evidence:
            db_evidence.status = status
            if error_message:
                db_evidence.error_message = error_message
            
            # Actualizar timestamps según estado
            if status == "parsed":
                db_evidence.parsed_at = datetime.utcnow()
            elif status == "analyzed":
                db_evidence.analyzed_at = datetime.utcnow()
            
            db.commit()
            db.refresh(db_evidence)
        return db_evidence
    
    @staticmethod
    def delete_evidence(db: Session, evidence_id: int) -> bool:
        """Eliminar evidencia (y sus relaciones)"""
        db_evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
        if db_evidence:
            db.delete(db_evidence)
            db.commit()
            return True
        return False
    
    @staticmethod
    def get_evidence_stats(db: Session) -> dict:
        """Obtener estadísticas de evidencias"""
        total = db.query(Evidence).count()
        by_status = {
            "ingested": db.query(Evidence).filter(Evidence.status == "ingested").count(),
            "parsed": db.query(Evidence).filter(Evidence.status == "parsed").count(),
            "analyzed": db.query(Evidence).filter(Evidence.status == "analyzed").count(),
            "error": db.query(Evidence).filter(Evidence.status == "error").count(),
        }
        return {
            "total": total,
            "by_status": by_status
        }
