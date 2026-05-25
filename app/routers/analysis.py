from fastapi import APIRouter, HTTPException, status
from fastapi.responses import HTMLResponse
from app.dependencies import DbSession, CurrentUser
from app.crud.analysis_results import AnalysisResultCRUD
from app.schemas import AnalysisResultResponse
import logging
import os

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/results-page/{evidence_id}", response_class=HTMLResponse)
async def analysis_results_page(
    evidence_id: int,
    current_user: CurrentUser
):
    """Mostrar página de resultados de análisis"""
    from jinja2 import Environment, FileSystemLoader
    templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
    jinja_env = Environment(loader=FileSystemLoader(templates_dir))
    template = jinja_env.get_template("analysis/results.html")
    return template.render(current_user=current_user, evidence_id=evidence_id)


@router.get("/results/{evidence_id}", response_model=list[AnalysisResultResponse])
async def get_analysis_results(
    evidence_id: int,
    current_user: CurrentUser,
    db: DbSession,
    skip: int = 0,
    limit: int = 50,
    severity: str = "all"
):
    """
    Obtener resultados de análisis de una evidencia.
    
    - **evidence_id**: ID de la evidencia
    - **severity**: Filtrar por severidad (all, low, medium, high, critical)
    """
    results = AnalysisResultCRUD.get_results_by_evidence(
        db,
        evidence_id,
        skip,
        limit,
        severity if severity != "all" else None
    )
    
    return [AnalysisResultResponse.from_orm(r) for r in results]


@router.get("/result/{result_id}", response_model=AnalysisResultResponse)
async def get_analysis_result(
    result_id: int,
    current_user: CurrentUser,
    db: DbSession
):
    """
    Obtener detalle de un resultado de análisis específico.
    """
    result = AnalysisResultCRUD.get_result_by_id(db, result_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis result not found"
        )
    
    return AnalysisResultResponse.from_orm(result)


@router.get("/status/{evidence_id}")
async def get_analysis_status(
    evidence_id: int,
    current_user: CurrentUser,
    db: DbSession
):
    """
    Obtener estado de análisis de una evidencia.
    Endpoint para polling durante procesamiento.
    """
    # Por ahora, devolver estado simple
    # En Fase 2 se integraría con el procesamiento asíncrono
    return {
        "evidence_id": evidence_id,
        "status": "pending",  # pending, processing, completed
        "progress_percent": 0,
        "eta_seconds": None
    }


@router.post("/start/{evidence_id}")
async def start_analysis(
    evidence_id: int,
    current_user: CurrentUser,
    db: DbSession
):
    """
    Iniciar análisis de una evidencia.
    El procesamiento se realiza en background.
    """
    # Por ahora, solo devolver confirmación
    # En Fase 2 se conectaría con el servicio de procesamiento
    
    return {
        "evidence_id": evidence_id,
        "status": "processing",
        "message": "Analysis started"
    }
