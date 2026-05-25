from sqlalchemy.orm import Session
from app.models import AnalysisResult
from app.schemas import AnalysisResultCreate, SeverityEnum


class AnalysisResultCRUD:
    """CRUD operations para resultados de análisis"""
    
    @staticmethod
    def create_result(
        db: Session,
        evidence_id: int = None,
        parsed_log_id: int = None,
        severity: str = "low",
        threat_type: str = "unknown",
        threat_description: str = None,
        indicators: list = None,
        ai_explanation: str = None,
        confidence_score: float = 0.5,
        result_data: AnalysisResultCreate = None
    ) -> AnalysisResult:
        """Crear nuevo resultado de análisis"""
        # Soportar ambas formas de llamar: con AnalysisResultCreate o con parámetros individuales
        if result_data:
            db_result = AnalysisResult(
                evidence_id=result_data.evidence_id,
                parsed_log_id=result_data.parsed_log_id,
                severity=result_data.severity,
                threat_type=result_data.threat_type,
                threat_description=result_data.threat_description,
                indicators=result_data.indicators,
                ai_explanation=result_data.ai_explanation,
                confidence_score=result_data.confidence_score
            )
        else:
            db_result = AnalysisResult(
                evidence_id=evidence_id,
                parsed_log_id=parsed_log_id,
                severity=severity,
                threat_type=threat_type,
                threat_description=threat_description,
                indicators=indicators or [],
                ai_explanation=ai_explanation,
                confidence_score=confidence_score
            )
        
        db.add(db_result)
        db.commit()
        db.refresh(db_result)
        return db_result
    
    @staticmethod
    def get_result_by_id(db: Session, result_id: int) -> AnalysisResult | None:
        """Obtener resultado por ID"""
        return db.query(AnalysisResult).filter(AnalysisResult.id == result_id).first()
    
    @staticmethod
    def get_results_by_evidence(
        db: Session,
        evidence_id: int,
        skip: int = 0,
        limit: int = 50,
        severity: str = None
    ) -> list[AnalysisResult]:
        """Obtener resultados de una evidencia específica con filtros"""
        query = db.query(AnalysisResult).filter(
            AnalysisResult.evidence_id == evidence_id
        )
        
        if severity and severity != "all":
            query = query.filter(AnalysisResult.severity == severity)
        
        return query.offset(skip).limit(limit).all()
    
    @staticmethod
    def get_critical_threats(
        db: Session,
        skip: int = 0,
        limit: int = 50
    ) -> list[AnalysisResult]:
        """Obtener todas las amenazas críticas"""
        return db.query(AnalysisResult).filter(
            AnalysisResult.severity == "critical"
        ).order_by(AnalysisResult.created_at.desc()).offset(skip).limit(limit).all()
    
    @staticmethod
    def get_threats_by_severity(
        db: Session,
        severity: str,
        skip: int = 0,
        limit: int = 50
    ) -> list[AnalysisResult]:
        """Obtener amenazas por nivel de severidad"""
        return db.query(AnalysisResult).filter(
            AnalysisResult.severity == severity
        ).order_by(AnalysisResult.created_at.desc()).offset(skip).limit(limit).all()
    
    @staticmethod
    def count_by_severity(db: Session) -> dict:
        """Contar amenazas por severidad"""
        return {
            "critical": db.query(AnalysisResult).filter(
                AnalysisResult.severity == "critical"
            ).count(),
            "high": db.query(AnalysisResult).filter(
                AnalysisResult.severity == "high"
            ).count(),
            "medium": db.query(AnalysisResult).filter(
                AnalysisResult.severity == "medium"
            ).count(),
            "low": db.query(AnalysisResult).filter(
                AnalysisResult.severity == "low"
            ).count(),
        }
    
    @staticmethod
    def count_by_evidence_severity(db: Session, evidence_id: int) -> dict:
        """Contar amenazas de una evidencia por severidad"""
        return {
            "critical": db.query(AnalysisResult).filter(
                AnalysisResult.evidence_id == evidence_id,
                AnalysisResult.severity == "critical"
            ).count(),
            "high": db.query(AnalysisResult).filter(
                AnalysisResult.evidence_id == evidence_id,
                AnalysisResult.severity == "high"
            ).count(),
            "medium": db.query(AnalysisResult).filter(
                AnalysisResult.evidence_id == evidence_id,
                AnalysisResult.severity == "medium"
            ).count(),
            "low": db.query(AnalysisResult).filter(
                AnalysisResult.evidence_id == evidence_id,
                AnalysisResult.severity == "low"
            ).count(),
        }
    
    @staticmethod
    def delete_result(db: Session, result_id: int) -> bool:
        """Eliminar resultado de análisis"""
        db_result = db.query(AnalysisResult).filter(AnalysisResult.id == result_id).first()
        if db_result:
            db.delete(db_result)
            db.commit()
            return True
        return False
