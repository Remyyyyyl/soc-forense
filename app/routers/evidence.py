from fastapi import APIRouter, HTTPException, status, UploadFile, File, Form
from fastapi.responses import FileResponse, HTMLResponse
from app.dependencies import DbSession, AdminUser, CurrentUser
from app.crud.evidence import EvidenceCRUD
from app.crud.users import UserCRUD
from app.schemas import EvidenceResponse, EvidenceDetail, EvidenceUpload
import hashlib
import os
import shutil
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

EVIDENCE_DIR = os.getenv("EVIDENCE_DIR", "./evidence")
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", "10485760"))  # 10MB


def calculate_file_hash(file_path: str) -> str:
    """Calcular SHA-256 de un archivo"""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


@router.get("/upload", response_class=HTMLResponse)
async def upload_page(current_user: CurrentUser):
    """Mostrar página de upload de evidencias"""
    from jinja2 import Environment, FileSystemLoader
    templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
    jinja_env = Environment(loader=FileSystemLoader(templates_dir))
    template = jinja_env.get_template("evidence/upload.html")
    return template.render(current_user=current_user, error=None, success_message=None)


@router.post("/upload", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    file: UploadFile = File(...),
    log_type: str = Form(...),
    admin_user: AdminUser = None,
    current_user: CurrentUser = None,
    db: DbSession = None
):
    """
    Subir un archivo de log para análisis.
    
    Solo usuarios con rol admin pueden subir archivos.
    
    - **file**: Archivo .log
    - **log_type**: Tipo de log (sudo, auth, audit)
    """
    # Usar admin_user si está disponible, si no current_user
    user = admin_user or current_user
    
    # Validar extensión
    if not file.filename.endswith('.log'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must have .log extension"
        )
    
    # Leer contenido del archivo
    content = await file.read()
    file_size = len(content)
    
    # Validar tamaño
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size exceeds limit of {MAX_FILE_SIZE} bytes"
        )
    
    # Calcular SHA-256
    sha256_hash = hashlib.sha256(content).hexdigest()
    
    # Verificar que no exista evidencia con este hash (evitar duplicados)
    existing = EvidenceCRUD.get_evidence_by_hash(db, sha256_hash)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This file has already been uploaded"
        )
    
    # Crear directorios si no existen
    raw_dir = os.path.join(EVIDENCE_DIR, "raw")
    image_dir = os.path.join(EVIDENCE_DIR, "image")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(image_dir, exist_ok=True)
    
    # Guardar archivo original en evidence/raw/
    stored_filename = f"{sha256_hash}_{file.filename}"
    raw_path = os.path.join(raw_dir, stored_filename)
    image_path = os.path.join(image_dir, stored_filename)
    
    try:
        # Guardar archivo original en raw
        with open(raw_path, 'wb') as f:
            f.write(content)
        
        # Hacer copia en image
        shutil.copy2(raw_path, image_path)
        
    except Exception as e:
        logger.error(f"Error saving file: {e}")
        # Limpiar si falla
        try:
            if os.path.exists(raw_path):
                os.remove(raw_path)
            if os.path.exists(image_path):
                os.remove(image_path)
        except:
            pass
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error saving file"
        )
    
    # Guardar metadata en BD (apuntando a image_path)
    try:
        evidence = EvidenceCRUD.create_evidence(
            db,
            filename=file.filename,
            log_type=log_type,
            file_size=file_size,
            sha256_hash=sha256_hash,
            stored_path=image_path,
            upload_user_id=user.id,
            original_path=file.filename
        )
        logger.info(f"Evidence uploaded: {evidence.filename} (hash: {sha256_hash})")
        
        return EvidenceResponse.from_orm(evidence)
    
    except Exception as e:
        logger.error(f"Error creating evidence record: {e}")
        # Intentar eliminar archivos si falla la BD
        try:
            if os.path.exists(raw_path):
                os.remove(raw_path)
            if os.path.exists(image_path):
                os.remove(image_path)
        except:
            pass
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error creating evidence record"
        )


@router.get("/list-page", response_class=HTMLResponse)
async def list_evidences_page(current_user: CurrentUser):
    """Mostrar página de listado de evidencias"""
    from jinja2 import Environment, FileSystemLoader
    templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
    jinja_env = Environment(loader=FileSystemLoader(templates_dir))
    template = jinja_env.get_template("evidence/list.html")
    return template.render(current_user=current_user)


@router.get("/list", response_model=list[EvidenceResponse])
async def list_evidences(
    current_user: CurrentUser,
    db: DbSession,
    skip: int = 0,
    limit: int = 50,
    status: str = None,
    log_type: str = None
):
    """
    Obtener lista de evidencias.
    
    - **skip**: Número de registros a saltar (paginación)
    - **limit**: Número de registros a devolver
    - **status**: Filtrar por estado (ingested, parsed, analyzed, error)
    - **log_type**: Filtrar por tipo de log (sudo, auth, audit)
    """
    evidences = EvidenceCRUD.get_all_evidences(
        db,
        skip=skip,
        limit=limit,
        status=status,
        log_type=log_type
    )
    
    return [EvidenceResponse.from_orm(e) for e in evidences]


@router.get("/stats", response_model=dict)
async def get_evidence_stats(
    current_user: CurrentUser,
    db: DbSession
):
    """
    Obtener estadísticas de evidencias.
    """
    stats = EvidenceCRUD.get_evidence_stats(db)
    return stats


@router.get("/{evidence_id}", response_model=EvidenceDetail)
async def get_evidence(
    evidence_id: int,
    current_user: CurrentUser,
    db: DbSession
):
    """
    Obtener detalle de una evidencia específica.
    """
    evidence = EvidenceCRUD.get_evidence_by_id(db, evidence_id)
    
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found"
        )
    
    return EvidenceDetail.from_orm(evidence)


@router.delete("/{evidence_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_evidence(
    evidence_id: int,
    admin_user: AdminUser,
    db: DbSession
):
    """
    Eliminar una evidencia (solo para admins).
    También elimina el archivo físico y todos los análisis asociados.
    """
    evidence = EvidenceCRUD.get_evidence_by_id(db, evidence_id)
    
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found"
        )
    
    # Intentar eliminar archivo físico de image
    if os.path.exists(evidence.stored_path):
        try:
            os.remove(evidence.stored_path)
        except Exception as e:
            logger.warning(f"Could not delete file {evidence.stored_path}: {e}")
    
    # Intentar eliminar archivo físico de raw
    raw_path = evidence.stored_path.replace(os.sep + "image" + os.sep, os.sep + "raw" + os.sep)
    if os.path.exists(raw_path):
        try:
            os.remove(raw_path)
        except Exception as e:
            logger.warning(f"Could not delete raw file {raw_path}: {e}")
    
    # Eliminar de BD (cascada elimina relaciones)
    EvidenceCRUD.delete_evidence(db, evidence_id)
    logger.info(f"Evidence deleted: {evidence.filename}")
    
    return None


@router.get("/{evidence_id}/download")
async def download_evidence(
    evidence_id: int,
    current_user: CurrentUser,
    db: DbSession
):
    """
    Descargar archivo de evidencia original.
    """
    evidence = EvidenceCRUD.get_evidence_by_id(db, evidence_id)
    
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found"
        )
    
    if not os.path.exists(evidence.stored_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence file not found on disk"
        )
    
    return FileResponse(
        path=evidence.stored_path,
        filename=evidence.filename,
        media_type="application/octet-stream"
    )


@router.post("/{evidence_id}/parse", response_model=dict)
async def parse_evidence_file(
    evidence_id: int,
    admin_user: AdminUser,
    db: DbSession
):
    """
    Parsear archivo de evidencia con LM Studio.
    Solo para admins.
    
    Retorna estado de parsing.
    """
    evidence = EvidenceCRUD.get_evidence_by_id(db, evidence_id)
    
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found"
        )
    
    if evidence.status == 'parsed' or evidence.status == 'analyzed':
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Evidence already {evidence.status}"
        )
    
    if not os.path.exists(evidence.stored_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence file not found on disk"
        )
    
    try:
        from app.services.log_parser import LogParser
        
        parser = LogParser()
        result = await parser.parse_evidence(db, evidence_id, evidence.stored_path)
        
        logger.info(f"Evidence {evidence_id} parsed: {result}")
        
        return result
    
    except Exception as e:
        logger.error(f"Error parsing evidence {evidence_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error parsing evidence: {str(e)}"
        )


@router.post("/{evidence_id}/analyze", response_model=dict)
async def analyze_evidence_file(
    evidence_id: int,
    admin_user: AdminUser,
    db: DbSession
):
    """
    Analizar evidencia parseada para detectar amenazas.
    Solo para admins.
    
    La evidencia debe estar en estado 'parsed' o 'ingested'.
    
    Retorna estado de análisis.
    """
    evidence = EvidenceCRUD.get_evidence_by_id(db, evidence_id)
    
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found"
        )
    
    if evidence.status == 'analyzed':
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Evidence already analyzed"
        )
    
    try:
        # Si aún no está parseado, parsearlo primero
        if evidence.status != 'parsed':
            logger.info(f"Evidence {evidence_id} needs parsing first")
            from app.services.log_parser import LogParser
            
            parser = LogParser()
            parse_result = await parser.parse_evidence(db, evidence_id, evidence.stored_path)
            
            if not parse_result['success']:
                raise Exception(f"Parsing failed: {parse_result['errors']}")
        
        # Ahora analizar
        from app.services.log_parser import LogAnalyzer
        
        analyzer = LogAnalyzer()
        result = await analyzer.analyze_evidence(db, evidence_id)
        
        logger.info(f"Evidence {evidence_id} analyzed: {result}")
        
        return result
    
    except Exception as e:
        logger.error(f"Error analyzing evidence {evidence_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error analyzing evidence: {str(e)}"
        )
