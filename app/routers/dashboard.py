from fastapi import APIRouter, HTTPException, status
from app.dependencies import DbSession, CurrentUser, AdminUser
from app.crud.analysis_results import AnalysisResultCRUD
from app.models import Evidence, AnalysisResult
from app.schemas import AnalysisResultResponse, DashboardOverview, SeverityDistribution
import logging
from sqlalchemy import func

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/dashboard/overview", response_model=DashboardOverview)
async def get_dashboard_overview(current_user: CurrentUser, db: DbSession):
    """
    Obtener resumen general del dashboard.
    - Total de evidencias
    - Amenazas por severidad
    """
    # Contar evidencias
    total_evidences = db.query(func.count(Evidence.id)).scalar() or 0
    
    # Contar amenazas por severidad
    severity_counts = AnalysisResultCRUD.count_by_severity(db)
    
    return DashboardOverview(
        total_evidences=total_evidences,
        total_critical_threats=severity_counts["critical"],
        total_high_threats=severity_counts["high"],
        total_medium_threats=severity_counts["medium"],
        total_low_threats=severity_counts["low"]
    )


@router.get("/severity-distribution", response_model=SeverityDistribution)
async def get_severity_distribution(current_user: CurrentUser, db: DbSession):
    """
    Obtener distribución de amenazas por severidad.
    """
    counts = AnalysisResultCRUD.count_by_severity(db)
    return SeverityDistribution(**counts)


@router.get("/critical-threats", response_model=list[AnalysisResultResponse])
async def get_critical_threats(
    current_user: CurrentUser,
    db: DbSession,
    skip: int = 0,
    limit: int = 50
):
    """
    Obtener todas las amenazas críticas (últimas primero).
    """
    threats = AnalysisResultCRUD.get_critical_threats(db, skip, limit)
    return [AnalysisResultResponse.from_orm(t) for t in threats]
