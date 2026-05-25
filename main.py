import logging
import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from jinja2 import Environment, FileSystemLoader
from dotenv import load_dotenv

from app.database import init_db
from app.routers import auth, evidence, analysis, dashboard, test
from app.dependencies import get_current_user
from sqlalchemy.orm import Session

# Configuración
load_dotenv()
DEBUG = os.getenv("DEBUG", "False") == "True"

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Jinja2 environment
templates_dir = os.path.join(os.path.dirname(__file__), "app", "templates")
jinja_env = Environment(loader=FileSystemLoader(templates_dir))

# Inicializar FastAPI
app = FastAPI(
    title="Analizador de Logs Forense",
    description="Aplicación web para análisis forense de logs Linux con IA local",
    version="0.1.0",
    debug=DEBUG
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inicializar BD
@app.on_event("startup")
async def startup_event():
    """Ejecutado al iniciar la aplicación"""
    logger.info("Inicializando aplicación...")
    init_db()
    logger.info("Base de datos inicializada")


@app.on_event("shutdown")
async def shutdown_event():
    """Ejecutado al cerrar la aplicación"""
    logger.info("Cerrando aplicación...")


# Incluir routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(evidence.router, prefix="/evidence", tags=["Evidence"])
app.include_router(analysis.router, prefix="/analysis", tags=["Analysis"])
app.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
app.include_router(test.router, prefix="/test", tags=["Test"])


# Health check
@app.get("/health", tags=["Health"])
async def health():
    """Health check endpoint"""
    return {"status": "ok"}


# Raíz - Dashboard o Login
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Dashboard o redirigir a login"""
    from app.database import SessionLocal
    from app.crud.users import SessionCRUD, UserCRUD
    from app.security import verify_session_token
    
    session_token = request.cookies.get("session_token")
    
    if not session_token:
        logger.debug("No session token in root endpoint, redirecting to login")
        return RedirectResponse(url="/auth/login", status_code=302)
    
    # Verificar sesión
    db = SessionLocal()
    try:
        session = SessionCRUD.get_session_by_token(db, session_token)
        if not session:
            logger.debug(f"Session token not found in DB: {session_token}")
            response = RedirectResponse(url="/auth/login", status_code=302)
            response.delete_cookie("session_token")
            return response
        
        if not verify_session_token(session_token, session.expires_at):
            logger.debug("Session token expired")
            SessionCRUD.delete_session(db, session_token)
            response = RedirectResponse(url="/auth/login", status_code=302)
            response.delete_cookie("session_token")
            return response
        
        # Obtener usuario
        user = UserCRUD.get_user_by_id(db, session.user_id)
        if not user:
            logger.debug(f"User not found for session")
            response = RedirectResponse(url="/auth/login", status_code=302)
            response.delete_cookie("session_token")
            return response
        
        logger.debug(f"User {user.username} authenticated, rendering dashboard")
        
        # Obtener datos del dashboard
        from app.models import Evidence, AnalysisResult
        from sqlalchemy import func
        
        total_evidences = db.query(func.count(Evidence.id)).scalar() or 0
        
        severity_counts = db.query(
            AnalysisResult.severity,
            func.count(AnalysisResult.id).label('count')
        ).group_by(AnalysisResult.severity).all()
        
        threat_dict = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        for severity, count in severity_counts:
            threat_dict[severity] = count
        
        # Obtener amenazas recientes
        recent_threats = db.query(AnalysisResult).order_by(
            AnalysisResult.created_at.desc()
        ).limit(5).all()
        
        # Obtener evidencias recientes
        recent_evidences = db.query(Evidence).order_by(
            Evidence.created_at.desc()
        ).limit(5).all()
        
        # Renderizar dashboard
        template = jinja_env.get_template("dashboard/overview.html")
        return template.render(
            current_user=user,
            error=None,
            success_message=None,
            total_evidences=total_evidences,
            critical_threats=threat_dict['critical'],
            high_threats=threat_dict['high'],
            medium_threats=threat_dict['medium'],
            low_threats=threat_dict['low'],
            recent_threats=recent_threats,
            recent_evidences=recent_evidences
        )
    
    except Exception as e:
        logger.error(f"Error in root endpoint: {e}")
        return RedirectResponse(url="/auth/login", status_code=302)
    
    finally:
        db.close()


@app.get("/auth/logout", response_class=HTMLResponse)
async def logout_page(request: Request):
    """Logout y redirigir a login"""
    from fastapi import Response
    from app.database import SessionLocal
    from app.crud.users import SessionCRUD
    
    session_token = request.cookies.get("session_token")
    
    db = SessionLocal()
    try:
        if session_token:
            SessionCRUD.delete_session(db, session_token)
    finally:
        db.close()
    
    response = RedirectResponse(url="/auth/login", status_code=303)
    response.delete_cookie(key="session_token")
    return response


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=DEBUG,
    )
