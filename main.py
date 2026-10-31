import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import List

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session


from models import ROLES_PERSONAL, Base, Rol, SessionLocal, Usuario, engine

# ===========================================================================
# CONFIGURACIÓN (variables de entorno)
# ===========================================================================
load_dotenv()
JWT_SECRET = os.getenv("JWT_SECRET", "cambia-esto-en-vercel")
JWT_ALGORITMO = "HS256"
# Duración base del token. En B6 se limitará a la hora de salida de la jornada.
TOKEN_HORAS = int(os.getenv("TOKEN_HORAS", "12"))
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",")]

ADMIN_USUARIO = os.getenv("ADMIN_USUARIO", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
ADMIN_NOMBRE = os.getenv("ADMIN_NOMBRE", "Administrador")


# ===========================================================================
# BASE DE DATOS
# ===========================================================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def crear_tablas_y_admin():
    """Crea las tablas y, si no existe ningún administrador, crea el primero
    con ADMIN_USUARIO / ADMIN_PASSWORD (variables de entorno)."""
    Base.metadata.create_all(bind=engine)
    if not ADMIN_PASSWORD:
        return
    db = SessionLocal()
    try:
        hay_admin = db.query(Usuario).filter(Usuario.rol == Rol.administrador).first()
        if not hay_admin:
            db.add(Usuario(
                nombre=ADMIN_NOMBRE,
                usuario=ADMIN_USUARIO.lower(),
                password_hash=hash_password(ADMIN_PASSWORD),
                rol=Rol.administrador,
            ))
            db.commit()
    finally:
        db.close()


# ===========================================================================
# SEGURIDAD: hash, JWT y roles
# ===========================================================================
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verificar_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def crear_token(usuario: Usuario) -> str:
    ahora = datetime.now(timezone.utc)
    payload = {
        "sub": str(usuario.id),
        "rol": usuario.rol.value,
        "iat": ahora,
        "exp": ahora + timedelta(hours=TOKEN_HORAS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITMO)


bearer = HTTPBearer(auto_error=False)


def usuario_actual(
    credenciales: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db),
) -> Usuario:
    """Lee el token, busca al usuario en la base y verifica que siga activo.
    El rol se toma de la base de datos en cada petición, no del token."""
    if credenciales is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Falta iniciar sesión")
    try:
        datos = jwt.decode(credenciales.credentials, JWT_SECRET, algorithms=[JWT_ALGORITMO])
        usuario = db.get(Usuario, int(datos["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sesión inválida o vencida")
    if usuario is None or not usuario.activo:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Cuenta inexistente o desactivada")
    return usuario


def requiere_roles(*roles: Rol):
    """Dependencia que deja pasar solo a los roles indicados."""
    def verificador(usuario: Usuario = Depends(usuario_actual)) -> Usuario:
        if usuario.rol not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "No tienes permiso para esta acción")
        return usuario
    return verificador


# ===========================================================================
# ESQUEMAS (validaciones de entrada y salida)
# ===========================================================================
class LoginIn(BaseModel):
    usuario: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=1, max_length=72)

    @field_validator("usuario")
    @classmethod
    def usuario_en_minuscula(cls, v: str) -> str:
        return v.strip().lower()


class UsuarioOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    nombre: str
    usuario: str
    rol: Rol
    activo: bool


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    usuario: UsuarioOut


class UsuarioCrear(BaseModel):
    nombre: str = Field(min_length=2, max_length=100)
    usuario: str = Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9._-]+$")
    password: str = Field(min_length=8, max_length=72)
    rol: Rol

    @field_validator("usuario")
    @classmethod
    def usuario_en_minuscula(cls, v: str) -> str:
        return v.lower()

    @field_validator("rol")
    @classmethod
    def solo_personal(cls, v: Rol) -> Rol:
        # Los clientes se registran solos desde su app (fase C1), no los crea el administrador.
        if v not in ROLES_PERSONAL:
            raise ValueError("Solo se crean cuentas del personal")
        return v


class EstadoIn(BaseModel):
    activo: bool


# ===========================================================================
# APP
# ===========================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    crear_tablas_y_admin()
    yield


app = FastAPI(title="NovaTech API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["estado"])
def estado():
    return {"servicio": "NovaTech API", "version": app.version, "estado": "ok"}


# ===========================================================================
# MÓDULO: AUTH
# ===========================================================================
@app.post("/auth/login", response_model=TokenOut, tags=["auth"])
def login_personal(datos: LoginIn, db: Session = Depends(get_db)):
    """Login de la app del personal. Un cliente no puede entrar por aquí."""
    usuario = db.query(Usuario).filter(Usuario.usuario == datos.usuario).first()
    if usuario is None or not verificar_password(datos.password, usuario.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuario o contraseña incorrectos")
    if not usuario.activo:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cuenta desactivada")
    if not usuario.es_personal:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Esta cuenta no pertenece al personal")
    return TokenOut(access_token=crear_token(usuario), usuario=usuario)


@app.get("/auth/perfil", response_model=UsuarioOut, tags=["auth"])
def perfil(usuario: Usuario = Depends(usuario_actual)):
    return usuario


# ===========================================================================
# MÓDULO: USUARIOS (solo administrador)
# ===========================================================================
@app.post("/usuarios", response_model=UsuarioOut, status_code=201, tags=["usuarios"])
def crear_usuario(
    datos: UsuarioCrear,
    db: Session = Depends(get_db),
    _: Usuario = Depends(requiere_roles(Rol.administrador)),
):
    if db.query(Usuario).filter(Usuario.usuario == datos.usuario).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Ese usuario ya existe")
    nuevo = Usuario(
        nombre=datos.nombre.strip(),
        usuario=datos.usuario,
        password_hash=hash_password(datos.password),
        rol=datos.rol,
    )
    db.add(nuevo)
    db.commit()
    db.refresh(nuevo)
    return nuevo


@app.get("/usuarios", response_model=List[UsuarioOut], tags=["usuarios"])
def listar_usuarios(
    db: Session = Depends(get_db),
    _: Usuario = Depends(requiere_roles(Rol.administrador)),
):
    return db.query(Usuario).order_by(Usuario.id).all()


@app.patch("/usuarios/{usuario_id}/estado", response_model=UsuarioOut, tags=["usuarios"])
def cambiar_estado(
    usuario_id: int,
    datos: EstadoIn,
    db: Session = Depends(get_db),
    admin: Usuario = Depends(requiere_roles(Rol.administrador)),
):
    objetivo = db.get(Usuario, usuario_id)
    if objetivo is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuario no encontrado")
    if objetivo.id == admin.id and not datos.activo:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No puedes desactivar tu propia cuenta")
    objetivo.activo = datos.activo
    db.commit()
    db.refresh(objetivo)
    return objetivo