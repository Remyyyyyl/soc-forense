import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

load_dotenv()

# Configuración de la base de datos
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database.db")

# Para SQLite, permitir que diferentes threads usen la misma conexión
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    echo=False,  # Cambiar a True para debug SQL
)

# SessionLocal para inyectar en endpoints
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

# Base para declarar modelos
Base = declarative_base()


def get_db():
    """Dependencia para inyectar BD en endpoints"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Crear todas las tablas"""
    Base.metadata.create_all(bind=engine)
