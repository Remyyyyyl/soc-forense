import os
import secrets
from datetime import datetime, timedelta
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()

# Configuración de hashing de passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
SESSION_TIMEOUT_HOURS = int(os.getenv("SESSION_TIMEOUT_HOURS", "24"))


# ============ Password Hashing ============
def hash_password(password: str) -> str:
    """Hash de password con bcrypt"""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verificar password contra hash"""
    return pwd_context.verify(plain_password, hashed_password)


# ============ Token Management ============
def generate_session_token() -> str:
    """Generar token de sesión seguro"""
    return secrets.token_urlsafe(32)


def get_session_expiration() -> datetime:
    """Calcular fecha de expiración de sesión"""
    return datetime.utcnow() + timedelta(hours=SESSION_TIMEOUT_HOURS)


# ============ Auth Utilities ============
def verify_session_token(session_token: str, expires_at: datetime) -> bool:
    """Verificar que el token de sesión sea válido y no haya expirado"""
    return datetime.utcnow() <= expires_at
