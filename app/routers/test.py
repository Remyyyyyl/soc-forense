from fastapi import APIRouter, HTTPException
from app.dependencies import DbSession
from app.crud.users import SessionCRUD
from sqlalchemy.orm import Session

router = APIRouter()


@router.get("/test/sessions")
async def test_list_sessions(db: DbSession):
    """Endpoint de prueba para ver todas las sesiones"""
    query = db.query(db.models.Session) if hasattr(db, 'models') else None
    # Alternativa:
    from app.models import Session as SessionModel
    sessions = db.query(SessionModel).all()
    return [
        {
            "id": s.id,
            "user_id": s.user_id,
            "token": s.session_token[:20] + "...",
            "expires_at": s.expires_at.isoformat(),
            "created_at": s.created_at.isoformat()
        }
        for s in sessions
    ]


@router.get("/test/cookie-info")
async def test_cookie_info():
    """Endpoint que devuelve info sobre cookies"""
    from fastapi import Request
    def get_request():
        from fastapi import Request
        return Request
    
    return {
        "message": "Use this endpoint to check cookies from the browser's developer tools"
    }
