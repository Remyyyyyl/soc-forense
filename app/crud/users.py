from sqlalchemy.orm import Session
from app.models import User, Session as SessionModel
from app.schemas import UserRegister, UserResponse
from app.security import hash_password, generate_session_token, get_session_expiration
from datetime import datetime


class UserCRUD:
    """CRUD operations para usuarios"""
    
    @staticmethod
    def create_user(db: Session, user_data: UserRegister) -> User:
        """Crear nuevo usuario"""
        db_user = User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=hash_password(user_data.password),
            role="viewer"  # Por defecto viewer, solo admin puede cambiar
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    
    @staticmethod
    def get_user_by_username(db: Session, username: str) -> User | None:
        """Obtener usuario por username"""
        return db.query(User).filter(User.username == username).first()
    
    @staticmethod
    def get_user_by_email(db: Session, email: str) -> User | None:
        """Obtener usuario por email"""
        return db.query(User).filter(User.email == email).first()
    
    @staticmethod
    def get_user_by_id(db: Session, user_id: int) -> User | None:
        """Obtener usuario por ID"""
        return db.query(User).filter(User.id == user_id).first()
    
    @staticmethod
    def get_all_users(db: Session, skip: int = 0, limit: int = 100) -> list[User]:
        """Obtener lista de usuarios (paginado)"""
        return db.query(User).offset(skip).limit(limit).all()
    
    @staticmethod
    def update_user(db: Session, user_id: int, **kwargs) -> User | None:
        """Actualizar usuario"""
        db_user = db.query(User).filter(User.id == user_id).first()
        if db_user:
            for key, value in kwargs.items():
                if hasattr(db_user, key) and key != "hashed_password":
                    setattr(db_user, key, value)
            db.commit()
            db.refresh(db_user)
        return db_user
    
    @staticmethod
    def delete_user(db: Session, user_id: int) -> bool:
        """Eliminar usuario"""
        db_user = db.query(User).filter(User.id == user_id).first()
        if db_user:
            db.delete(db_user)
            db.commit()
            return True
        return False


class SessionCRUD:
    """CRUD operations para sesiones"""
    
    @staticmethod
    def create_session(db: Session, user_id: int) -> SessionModel:
        """Crear nueva sesión"""
        session_token = generate_session_token()
        expires_at = get_session_expiration()
        
        db_session = SessionModel(
            user_id=user_id,
            session_token=session_token,
            expires_at=expires_at
        )
        db.add(db_session)
        db.commit()
        db.refresh(db_session)
        return db_session
    
    @staticmethod
    def get_session_by_token(db: Session, session_token: str) -> SessionModel | None:
        """Obtener sesión por token"""
        return db.query(SessionModel).filter(
            SessionModel.session_token == session_token
        ).first()
    
    @staticmethod
    def get_sessions_by_user(db: Session, user_id: int) -> list[SessionModel]:
        """Obtener todas las sesiones de un usuario"""
        return db.query(SessionModel).filter(SessionModel.user_id == user_id).all()
    
    @staticmethod
    def delete_session(db: Session, session_token: str) -> bool:
        """Eliminar sesión (logout)"""
        db_session = db.query(SessionModel).filter(
            SessionModel.session_token == session_token
        ).first()
        if db_session:
            db.delete(db_session)
            db.commit()
            return True
        return False
    
    @staticmethod
    def delete_expired_sessions(db: Session) -> int:
        """Eliminar sesiones expiradas (limpieza)"""
        deleted = db.query(SessionModel).filter(
            SessionModel.expires_at <= datetime.utcnow()
        ).delete()
        db.commit()
        return deleted
    
    @staticmethod
    def delete_user_sessions(db: Session, user_id: int) -> int:
        """Eliminar todas las sesiones de un usuario (logout de todos lados)"""
        deleted = db.query(SessionModel).filter(
            SessionModel.user_id == user_id
        ).delete()
        db.commit()
        return deleted
