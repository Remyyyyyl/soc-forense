from fastapi import APIRouter, HTTPException, status, Response, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas import UserRegister, UserLogin, UserResponse, AuthToken, AuthMessage
from app.crud.users import UserCRUD, SessionCRUD
from app.security import verify_password
from app.dependencies import CurrentUser, DbSession
import logging
import os

logger = logging.getLogger(__name__)

# Jinja2 environment
templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
jinja_env = Environment(loader=FileSystemLoader(templates_dir))

router = APIRouter()


@router.get("/register", response_class=HTMLResponse)
async def register_page():
    """Mostrar página de registro"""
    template = jinja_env.get_template("auth/register.html")
    return template.render(current_user=None, error=None, success_message=None)


@router.post("/register", response_class=HTMLResponse)
async def register(
    db: DbSession,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    """
    Registrar nuevo usuario.
    """
    # Validaciones básicas
    if len(username) < 3 or len(username) > 255:
        template = jinja_env.get_template("auth/register.html")
        return template.render(error="Username debe tener entre 3 y 255 caracteres", current_user=None, success_message=None)
    
    if len(password) < 6:
        template = jinja_env.get_template("auth/register.html")
        return template.render(error="Password debe tener al menos 6 caracteres", current_user=None, success_message=None)
    
    # Verificar que no exista el usuario
    if UserCRUD.get_user_by_username(db, username):
        template = jinja_env.get_template("auth/register.html")
        return template.render(error="Username ya está registrado", current_user=None, success_message=None)
    
    if UserCRUD.get_user_by_email(db, email):
        template = jinja_env.get_template("auth/register.html")
        return template.render(error="Email ya está registrado", current_user=None, success_message=None)
    
    try:
        # Crear usuario
        user = UserCRUD.create_user(db, UserRegister(username=username, email=email, password=password))
        logger.info(f"New user registered: {user.username}")
        
        # Redirigir a login
        return RedirectResponse(url="/auth/login?success=Usuario%20registrado%20exitosamente", status_code=303)
    
    except Exception as e:
        logger.error(f"Registration error: {e}")
        template = jinja_env.get_template("auth/register.html")
        return template.render(error="Error al registrar usuario", current_user=None, success_message=None)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Mostrar página de login"""
    template = jinja_env.get_template("auth/login.html")
    success_msg = request.query_params.get("success", "")
    return template.render(
        current_user=None,
        success_message=success_msg if success_msg else None
    )


@router.post("/login", response_class=HTMLResponse)
async def login(
    db: DbSession,
    username: str = Form(...),
    password: str = Form(...)
):
    """
    Login de usuario.
    """
    # Obtener usuario
    user = UserCRUD.get_user_by_username(db, username)
    
    if not user:
        template = jinja_env.get_template("auth/login.html")
        return template.render(error="Usuario o contraseña inválidos", current_user=None, success_message=None)
    
    # Verificar password
    if not verify_password(password, user.hashed_password):
        template = jinja_env.get_template("auth/login.html")
        return template.render(error="Usuario o contraseña inválidos", current_user=None, success_message=None)
    
    # Verificar que usuario esté activo
    if not user.is_active:
        template = jinja_env.get_template("auth/login.html")
        return template.render(error="Usuario inactivo", current_user=None, success_message=None)
    
    # Crear sesión
    session = SessionCRUD.create_session(db, user.id)
    
    # Crear redirect response
    response = RedirectResponse(url="/", status_code=302)
    
    # Establecer cookie EN la respuesta
    response.set_cookie(
        key="session_token",
        value=session.session_token,
        httponly=True,
        secure=False,
        samesite="lax",
        path="/",
        max_age=86400  # 24 horas
    )
    
    logger.info(f"User logged in: {user.username}, Session token: {session.session_token[:20]}...")
    
    return response


@router.post("/logout", response_model=AuthMessage)
async def logout(
    request: Request,
    response: Response,
    db: DbSession
):
    """
    Logout de usuario.
    Invalida la sesión actual.
    """
    session_token = request.cookies.get("session_token")
    
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No session token found"
        )
    
    # Eliminar sesión de BD
    success = SessionCRUD.delete_session(db, session_token)
    
    # Eliminar cookie
    response.delete_cookie(key="session_token")
    
    if success:
        logger.info("User logged out")
        return AuthMessage(message="Logged out successfully")
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session not found"
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: CurrentUser):
    """
    Obtener información del usuario autenticado.
    Requiere autenticación.
    """
    return UserResponse.from_orm(current_user)


@router.post("/logout-all", response_model=AuthMessage)
async def logout_all(current_user: CurrentUser, db: DbSession):
    """
    Logout de todas las sesiones del usuario.
    Invalida todos los tokens del usuario actual.
    """
    deleted = SessionCRUD.delete_user_sessions(db, current_user.id)
    logger.info(f"User {current_user.username} logged out from all sessions ({deleted} sessions deleted)")
    
    return AuthMessage(message=f"Logged out from all sessions ({deleted} devices)")
