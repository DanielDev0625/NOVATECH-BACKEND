import enum
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from sqlalchemy import Boolean, Column, DateTime, Enum, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import NullPool

load_dotenv()

# ---------------------------------------------------------------------------
# CONEXIÓN A NEON (PostgreSQL)
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./novatech_local.db")

# Normaliza la URL y fuerza el driver psycopg2 (el de requirements.txt),
# sin importar cómo venga escrita ni qué versión de SQLAlchemy se instale.
for prefijo in ("postgres://", "postgresql+psycopg://", "postgresql://"):
    if DATABASE_URL.startswith(prefijo):
        DATABASE_URL = "postgresql+psycopg2://" + DATABASE_URL[len(prefijo):]
        break

_es_sqlite = DATABASE_URL.startswith("sqlite")

# Vercel es sin servidor: sin pool propio; Neon ya trae su pool (cadena "pooled").
engine = create_engine(
    DATABASE_URL,
    poolclass=NullPool,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False} if _es_sqlite else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


# ---------------------------------------------------------------------------
# CLASE BASE (herencia): todas las tablas heredan id y fecha de creación
# ---------------------------------------------------------------------------
class ModeloBase(Base):
    __abstract__ = True

    id = Column(Integer, primary_key=True, index=True)
    creado_en = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# ROLES
# ---------------------------------------------------------------------------
class Rol(str, enum.Enum):
    usuario = "usuario"              # cliente (app del cliente)
    operario = "operario"
    transportista = "transportista"
    gerente = "gerente"
    administrador = "administrador"


ROLES_PERSONAL = {Rol.operario, Rol.transportista, Rol.gerente, Rol.administrador}


# ---------------------------------------------------------------------------
# USUARIOS
# ---------------------------------------------------------------------------
class Usuario(ModeloBase):
    __tablename__ = "usuarios"

    nombre = Column(String(100), nullable=False)
    usuario = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    rol = Column(Enum(Rol, native_enum=False, length=20), nullable=False)
    activo = Column(Boolean, default=True, nullable=False)

    @property
    def es_personal(self) -> bool:
        return self.rol in ROLES_PERSONAL