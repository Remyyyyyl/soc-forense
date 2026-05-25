from typing import Annotated
from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, Session as SessionModel
from app.security import verify_session_token

# Type hints para inyección
DbSession = Annotated[Session, Depends(get_db)]


def get_current_user(request: Request, db: DbSession) -> User:
    """
    Obtener usuario actual desde cookie de sesión.
    Lanza excepción 401 si no está autenticado.
    """
    # Obtener token de cookie
    session_token = request.cookies.get("session_token")
    
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No session token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Buscar sesión en BD
    session = db.query(SessionModel).filter(
        SessionModel.session_token == session_token
    ).first()
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session token",
        )
    
    # Verificar que no haya expirado
    if not verify_session_token(session_token, session.expires_at):
        db.delete(session)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired",
        )
    
    # Obtener usuario
    user = db.query(User).filter(User.id == session.user_id).first()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    
    return user


def get_admin_user(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    """
    Verificar que el usuario actual sea admin.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    return current_user


# Type hints para usar en endpoints
CurrentUser = Annotated[User, Depends(get_current_user)]
AdminUser = Annotated[User, Depends(get_admin_user)]
