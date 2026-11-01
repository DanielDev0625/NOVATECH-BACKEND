"""
NovaTech API - main.py
App, seguridad (hash, JWT, roles) y rutas.
  B1: base del proyecto, login con roles y despliegue en Vercel.
  B2: catálogo, importación de Excel y lotes con código autogenerado.
"""
import io
import os
import re
import secrets
import traceback
import unicodedata
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import List, Literal, Optional

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from openpyxl import Workbook, load_workbook
from openpyxl.styles import Font, PatternFill
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models import (
    ROLES_PERSONAL,
    AsignacionLote,
    Base,
    Categoria,
    Configuracion,
    Direccion,
    Lote,
    LoteEstado,
    Pedido,
    PedidoDetalle,
    PedidoEstado,
    PedidoEvento,
    Producto,
    Rol,
    SessionLocal,
    Usuario,
    engine,
)

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

# Margen de ganancia por defecto (en %). El administrador lo cambia desde la API.
MARGEN_POR_DEFECTO = Decimal("20")
STOCK_MINIMO_POR_DEFECTO = 5
# Plazo de entrega prometido al cliente (en días). El administrador lo cambia desde la API.
PLAZO_ENTREGA_DIAS_POR_DEFECTO = 2

MAX_BYTES_EXCEL = 5 * 1024 * 1024
MAX_FILAS_EXCEL = 2000


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
    """Crea las tablas, las categorías base y, si no existe ningún administrador,
    crea el primero con ADMIN_USUARIO / ADMIN_PASSWORD (variables de entorno)."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for nombre in CATEGORIAS:
            if not db.query(Categoria).filter(Categoria.nombre == nombre).first():
                db.add(Categoria(nombre=nombre))
        db.commit()

        if ADMIN_PASSWORD:
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


# Grupos de roles que se repiten en varias rutas
SOLO_ADMIN = (Rol.administrador,)
ADMIN_Y_GERENTE = (Rol.administrador, Rol.gerente)
PERSONAL_DE_BODEGA = (Rol.operario, Rol.gerente, Rol.administrador)
SOLO_CLIENTE = (Rol.usuario,)
TODO_PERSONAL = (Rol.operario, Rol.transportista, Rol.gerente, Rol.administrador)


# ===========================================================================
# ESQUEMAS (validaciones de entrada y salida)
# ===========================================================================
# --- Auth y usuarios (B1) ---
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


# --- Catálogo (B2) ---
class CategoriaOut(BaseModel):
    id: int
    nombre: str


class ProductoCatalogoOut(BaseModel):
    """Lo que ve el cliente: sin costos ni datos internos."""
    id: int
    sku: str
    nombre: str
    marca: Optional[str]
    categoria: str
    precio: float
    stock: int


class ProductoStaffOut(BaseModel):
    """Lo que ve el personal autorizado."""
    id: int
    sku: str
    nombre: str
    marca: Optional[str]
    categoria: str
    costo: float
    precio: float
    stock: int
    stock_minimo: int
    stock_bajo: bool
    activo: bool


class ProductoCrear(BaseModel):
    sku: str = Field(min_length=1, max_length=50)
    nombre: str = Field(min_length=2, max_length=150)
    marca: Optional[str] = Field(default=None, max_length=80)
    costo: float = Field(gt=0)
    stock_minimo: int = Field(default=STOCK_MINIMO_POR_DEFECTO, ge=0, le=100000)
    categoria: Optional[str] = None    # si no se envía, se asigna sola por el nombre

    @field_validator("categoria")
    @classmethod
    def categoria_valida(cls, v):
        if v is not None and v not in CATEGORIAS:
            raise ValueError("Categoría no válida")
        return v


class ProductoEditar(BaseModel):
    nombre: Optional[str] = Field(default=None, min_length=2, max_length=150)
    marca: Optional[str] = Field(default=None, max_length=80)
    categoria: Optional[str] = None
    costo: Optional[float] = Field(default=None, gt=0)
    stock_minimo: Optional[int] = Field(default=None, ge=0, le=100000)
    activo: Optional[bool] = None

    @field_validator("categoria")
    @classmethod
    def categoria_valida(cls, v):
        if v is not None and v not in CATEGORIAS:
            raise ValueError("Categoría no válida")
        return v


class MargenIn(BaseModel):
    margen: float = Field(ge=0, le=500)    # porcentaje sobre el costo


# --- Lotes (B2) ---
class LoteCrear(BaseModel):
    producto_id: int
    cantidad: int = Field(gt=0, le=100000)
    costo_unitario: Optional[float] = Field(default=None, gt=0)   # si no se envía, usa el costo del producto
    proveedor: Optional[str] = Field(default=None, max_length=100)


class LoteOut(BaseModel):
    id: int
    codigo: str
    producto_id: int
    producto: str
    sku: str
    cantidad_inicial: int
    cantidad_restante: int
    costo_unitario: float
    proveedor: Optional[str]
    fecha_recepcion: Optional[datetime]
    estado: LoteEstado


# ===========================================================================
# APP
# ===========================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        crear_tablas_y_admin()
    except Exception:
        # Si la base falla, la app sigue viva y el error queda en los registros.
        traceback.print_exc()
    yield


app = FastAPI(title="NovaTech API", version="0.2.0", lifespan=lifespan)

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
    _: Usuario = Depends(requiere_roles(*SOLO_ADMIN)),
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
    _: Usuario = Depends(requiere_roles(*SOLO_ADMIN)),
):
    return db.query(Usuario).order_by(Usuario.id).all()


@app.patch("/usuarios/{usuario_id}/estado", response_model=UsuarioOut, tags=["usuarios"])
def cambiar_estado(
    usuario_id: int,
    datos: EstadoIn,
    db: Session = Depends(get_db),
    admin: Usuario = Depends(requiere_roles(*SOLO_ADMIN)),
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


# ===========================================================================
# CATÁLOGO: categorías automáticas, precios y stock
# ===========================================================================
CATEGORIAS = [
    "Procesadores",
    "Tarjetas gráficas",
    "Memoria RAM",
    "SSD",
    "Tarjetas madre",
    "Fuentes de poder",
    "Otros",
]

# Se evalúan en orden: la primera que coincide con el nombre del producto gana.
# (Fuentes y tarjetas madre van antes porque sus nombres suelen mencionar RAM, SSD o procesadores.)
REGLAS_CATEGORIA = [
    ("Fuentes de poder", r"fuente|\bpsu\b|power supply|80 ?plus|80\+"),
    ("Tarjetas madre", r"tarjeta madre|placa madre|motherboard|mainboard|\b[abhxzq]\d{3}[a-z]{0,2}\b"),
    ("Tarjetas gráficas", r"\brtx|\bgtx|geforce|radeon|\brx ?\d{3,4}|tarjeta grafica|tarjeta de video|video card|\bgpu\b|\barc ?a\d{3}"),
    ("Procesadores", r"ryzen|core i\d|core ultra|intel core|procesador|processor|\bcpu\b|threadripper|xeon|celeron|pentium|athlon|\bi[3579]-\d{4}"),
    ("SSD", r"\bssd\b|nvme|\bm\.?2\b|disco solido"),
    ("Memoria RAM", r"\bram\b|\bddr[2345]\b|memoria|\bdimm\b|sodimm"),
]


def normalizar_texto(texto: str) -> str:
    """Minúsculas y sin tildes, para comparar nombres."""
    sin_tildes = unicodedata.normalize("NFKD", str(texto))
    sin_tildes = "".join(c for c in sin_tildes if not unicodedata.combining(c))
    return sin_tildes.lower().strip()


def clasificar_categoria(nombre: str) -> str:
    """Asigna la categoría sola, a partir del nombre del producto."""
    texto = normalizar_texto(nombre)
    for categoria, patron in REGLAS_CATEGORIA:
        if re.search(patron, texto):
            return categoria
    return "Otros"


def obtener_categoria(db: Session, nombre: str) -> Categoria:
    categoria = db.query(Categoria).filter(Categoria.nombre == nombre).first()
    if categoria is None:
        categoria = Categoria(nombre=nombre)
        db.add(categoria)
        db.flush()
    return categoria


def obtener_margen(db: Session) -> Decimal:
    fila = db.query(Configuracion).filter(Configuracion.clave == "margen").first()
    if fila is None:
        return MARGEN_POR_DEFECTO
    try:
        return Decimal(fila.valor)
    except InvalidOperation:
        return MARGEN_POR_DEFECTO


def stock_por_producto(db: Session) -> dict:
    """Stock disponible = suma de lo que queda en los lotes que no están agotados."""
    filas = (
        db.query(Lote.producto_id, func.coalesce(func.sum(Lote.cantidad_restante), 0))
        .filter(Lote.estado != LoteEstado.agotado)
        .group_by(Lote.producto_id)
        .all()
    )
    return {producto_id: int(total) for producto_id, total in filas}


def producto_staff(p: Producto, stock: int) -> ProductoStaffOut:
    return ProductoStaffOut(
        id=p.id, sku=p.sku, nombre=p.nombre, marca=p.marca, categoria=p.categoria.nombre,
        costo=float(p.costo), precio=float(p.precio), stock=stock,
        stock_minimo=p.stock_minimo, stock_bajo=stock <= p.stock_minimo, activo=p.activo,
    )


@app.get("/categorias", response_model=List[CategoriaOut], tags=["catalogo"])
def listar_categorias(db: Session = Depends(get_db), _: Usuario = Depends(usuario_actual)):
    return [
        CategoriaOut(id=c.id, nombre=c.nombre)
        for c in db.query(Categoria).order_by(Categoria.nombre).all()
    ]


@app.get("/catalogo", response_model=List[ProductoCatalogoOut], tags=["catalogo"])
def catalogo(
    categoria: Optional[str] = None,
    db: Session = Depends(get_db),
    _: Usuario = Depends(usuario_actual),
):
    """Catálogo para el cliente: solo productos activos que tienen stock."""
    stock = stock_por_producto(db)
    consulta = db.query(Producto).filter(Producto.activo.is_(True))
    if categoria:
        consulta = consulta.join(Categoria).filter(Categoria.nombre == categoria)
    salida = []
    for p in consulta.order_by(Producto.nombre).all():
        disponible = stock.get(p.id, 0)
        if disponible > 0:
            salida.append(ProductoCatalogoOut(
                id=p.id, sku=p.sku, nombre=p.nombre, marca=p.marca,
                categoria=p.categoria.nombre, precio=float(p.precio), stock=disponible,
            ))
    return salida


@app.get("/productos", response_model=List[ProductoStaffOut], tags=["catalogo"])
def listar_productos(
    solo_stock_bajo: bool = False,
    db: Session = Depends(get_db),
    _: Usuario = Depends(requiere_roles(*PERSONAL_DE_BODEGA)),
):
    stock = stock_por_producto(db)
    salida = [producto_staff(p, stock.get(p.id, 0)) for p in db.query(Producto).order_by(Producto.nombre).all()]
    if solo_stock_bajo:
        salida = [p for p in salida if p.stock_bajo]
    return salida


@app.post("/productos", response_model=ProductoStaffOut, status_code=201, tags=["catalogo"])
def crear_producto(
    datos: ProductoCrear,
    db: Session = Depends(get_db),
    _: Usuario = Depends(requiere_roles(*SOLO_ADMIN)),
):
    sku = datos.sku.strip().upper()
    if db.query(Producto).filter(Producto.sku == sku).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Ya existe un producto con ese SKU")
    nombre = datos.nombre.strip()
    categoria = obtener_categoria(db, datos.categoria or clasificar_categoria(nombre))
    costo = Decimal(str(datos.costo)).quantize(Decimal("0.01"))
    producto = Producto(
        sku=sku, nombre=nombre, marca=(datos.marca or "").strip() or None,
        categoria_id=categoria.id, costo=costo,
        precio=Producto.precio_con_margen(costo, obtener_margen(db)),
        stock_minimo=datos.stock_minimo,
    )
    db.add(producto)
    db.commit()
    db.refresh(producto)
    return producto_staff(producto, 0)


@app.patch("/productos/{producto_id}", response_model=ProductoStaffOut, tags=["catalogo"])
def editar_producto(
    producto_id: int,
    datos: ProductoEditar,
    db: Session = Depends(get_db),
    _: Usuario = Depends(requiere_roles(*SOLO_ADMIN)),
):
    producto = db.get(Producto, producto_id)
    if producto is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Producto no encontrado")
    if datos.nombre is not None:
        producto.nombre = datos.nombre.strip()
    if datos.marca is not None:
        producto.marca = datos.marca.strip() or None
    if datos.categoria is not None:
        producto.categoria_id = obtener_categoria(db, datos.categoria).id
    if datos.stock_minimo is not None:
        producto.stock_minimo = datos.stock_minimo
    if datos.activo is not None:
        producto.activo = datos.activo
    if datos.costo is not None:
        producto.costo = Decimal(str(datos.costo)).quantize(Decimal("0.01"))
        producto.precio = Producto.precio_con_margen(producto.costo, obtener_margen(db))
    db.commit()
    db.refresh(producto)
    return producto_staff(producto, stock_por_producto(db).get(producto.id, 0))


# ===========================================================================
# CONFIGURACIÓN: margen de ganancia
# ===========================================================================
@app.get("/configuracion", tags=["configuracion"])
def ver_configuracion(
    db: Session = Depends(get_db),
    _: Usuario = Depends(requiere_roles(*ADMIN_Y_GERENTE)),
):
    return {"margen": float(obtener_margen(db)), "plazo_entrega_dias": obtener_plazo_entrega(db)}


@app.put("/configuracion/margen", tags=["configuracion"])
def cambiar_margen(
    datos: MargenIn,
    db: Session = Depends(get_db),
    _: Usuario = Depends(requiere_roles(*SOLO_ADMIN)),
):
    """Cambia el margen y recalcula el precio de todos los productos (precio = costo + margen)."""
    margen = Decimal(str(datos.margen))
    fila = db.query(Configuracion).filter(Configuracion.clave == "margen").first()
    if fila is None:
        db.add(Configuracion(clave="margen", valor=str(margen)))
    else:
        fila.valor = str(margen)
    productos = db.query(Producto).all()
    for p in productos:
        p.precio = Producto.precio_con_margen(p.costo, margen)
    db.commit()
    return {"margen": float(margen), "productos_actualizados": len(productos)}


# ===========================================================================
# LOTES: código autogenerado LOT-AAAA-NNNN
# ===========================================================================
def siguiente_codigo(db: Session, columna, base: str) -> str:
    """Código autoincremental por año: BASE-AAAA-NNNN (por ejemplo LOT-2026-0001)."""
    anio = datetime.now(timezone.utc).year
    prefijo = f"{base}-{anio}-"
    ultimo = (
        db.query(columna)
        .filter(columna.like(prefijo + "%"))
        .order_by(func.length(columna).desc(), columna.desc())
        .first()
    )
    siguiente = int(ultimo[0].split("-")[-1]) + 1 if ultimo else 1
    return f"{prefijo}{siguiente:04d}"


def generar_codigo_lote(db: Session) -> str:
    return siguiente_codigo(db, Lote.codigo, "LOT")


def crear_lote(db: Session, producto: Producto, cantidad: int, costo_unitario: Decimal,
               proveedor: Optional[str]) -> Lote:
    lote = Lote(
        codigo=generar_codigo_lote(db),
        producto_id=producto.id,
        cantidad_inicial=cantidad,
        cantidad_restante=cantidad,
        costo_unitario=costo_unitario,
        proveedor=proveedor,
        estado=LoteEstado.recibido,
    )
    db.add(lote)
    db.flush()    # asigna el código ya, para que el siguiente lote tome el número que sigue
    return lote


def lote_a_out(lote: Lote) -> LoteOut:
    return LoteOut(
        id=lote.id, codigo=lote.codigo, producto_id=lote.producto_id,
        producto=lote.producto.nombre, sku=lote.producto.sku,
        cantidad_inicial=lote.cantidad_inicial, cantidad_restante=lote.cantidad_restante,
        costo_unitario=float(lote.costo_unitario), proveedor=lote.proveedor,
        fecha_recepcion=lote.fecha_recepcion, estado=lote.estado,
    )


@app.post("/lotes", response_model=LoteOut, status_code=201, tags=["lotes"])
def recibir_lote(
    datos: LoteCrear,
    db: Session = Depends(get_db),
    _: Usuario = Depends(requiere_roles(*PERSONAL_DE_BODEGA)),
):
    """Recepción de mercancía: el sistema genera el código del lote y el stock sube."""
    producto = db.get(Producto, datos.producto_id)
    if producto is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Producto no encontrado")
    costo = Decimal(str(datos.costo_unitario)).quantize(Decimal("0.01")) if datos.costo_unitario else producto.costo
    proveedor = (datos.proveedor or "").strip() or None
    try:
        lote = crear_lote(db, producto, datos.cantidad, costo, proveedor)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "No se pudo generar el código del lote; intenta de nuevo")
    db.refresh(lote)
    return lote_a_out(lote)


@app.get("/lotes", response_model=List[LoteOut], tags=["lotes"])
def listar_lotes(
    producto_id: Optional[int] = None,
    estado: Optional[LoteEstado] = None,
    db: Session = Depends(get_db),
    _: Usuario = Depends(requiere_roles(*PERSONAL_DE_BODEGA)),
):
    consulta = db.query(Lote)
    if producto_id is not None:
        consulta = consulta.filter(Lote.producto_id == producto_id)
    if estado is not None:
        consulta = consulta.filter(Lote.estado == estado)
    return [lote_a_out(l) for l in consulta.order_by(Lote.id.desc()).all()]


@app.get("/lotes/{lote_id}", response_model=LoteOut, tags=["lotes"])
def ver_lote(
    lote_id: int,
    db: Session = Depends(get_db),
    _: Usuario = Depends(requiere_roles(*PERSONAL_DE_BODEGA)),
):
    lote = db.get(Lote, lote_id)
    if lote is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Lote no encontrado")
    return lote_a_out(lote)


@app.patch("/lotes/{lote_id}/almacenar", response_model=LoteOut, tags=["lotes"])
def almacenar_lote(
    lote_id: int,
    db: Session = Depends(get_db),
    _: Usuario = Depends(requiere_roles(*PERSONAL_DE_BODEGA)),
):
    """Avanza el lote de Recibido a Almacenado. Los estados avanzan en orden."""
    lote = db.get(Lote, lote_id)
    if lote is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Lote no encontrado")
    if lote.estado != LoteEstado.recibido:
        raise HTTPException(status.HTTP_409_CONFLICT, f"El lote ya está en estado «{lote.estado.value}»")
    lote.estado = LoteEstado.almacenado
    db.commit()
    db.refresh(lote)
    return lote_a_out(lote)


# ===========================================================================
# IMPORTACIÓN DE EXCEL (una sola vez, con vista previa)
# ===========================================================================
COLUMNAS_EXCEL = {
    "sku": "sku",
    "nombre": "nombre",
    "marca": "marca",
    "costo": "costo",
    "stock_minimo": "stock_minimo",
    "cantidad_inicial": "cantidad_inicial",
    "cantidad": "cantidad_inicial",
    "proveedor": "proveedor",
}
COLUMNAS_OBLIGATORIAS = ("sku", "nombre", "costo")


def normalizar_encabezado(titulo: str) -> str:
    return re.sub(r"[\s\-]+", "_", normalizar_texto(titulo))


def a_decimal(valor) -> Optional[Decimal]:
    """Convierte la celda a número. Acepta números y textos como «$1.500.000» o «1500,50»."""
    if valor is None or isinstance(valor, bool):
        return None
    if isinstance(valor, (int, float)):
        return Decimal(str(valor))
    texto = str(valor).strip().replace("$", "").replace(" ", "")
    if not texto:
        return None
    if "," in texto and "." in texto:
        texto = texto.replace(".", "").replace(",", ".")
    elif "," in texto:
        texto = texto.replace(",", ".")
    elif texto.count(".") > 1:
        texto = texto.replace(".", "")
    try:
        return Decimal(texto)
    except InvalidOperation:
        return None


def a_entero(valor, por_defecto: int) -> int:
    """Entero mayor o igual a cero; si la celda está vacía devuelve el valor por defecto."""
    if valor is None or str(valor).strip() == "":
        return por_defecto
    numero = a_decimal(valor)
    if numero is None or numero != numero.to_integral_value() or numero < 0:
        raise ValueError("debe ser un número entero mayor o igual a cero")
    return int(numero)


def leer_excel(contenido: bytes) -> list:
    """Devuelve una lista de (número de fila, datos) con las filas que tienen contenido."""
    try:
        libro = load_workbook(io.BytesIO(contenido), read_only=True, data_only=True)
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "El archivo no es un Excel (.xlsx) válido")
    try:
        filas = libro.active.iter_rows(values_only=True)
        try:
            encabezado = next(filas)
        except StopIteration:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "El archivo está vacío")

        indices = {}
        for posicion, titulo in enumerate(encabezado):
            if titulo is None:
                continue
            clave = COLUMNAS_EXCEL.get(normalizar_encabezado(titulo))
            if clave and clave not in indices:
                indices[clave] = posicion
        faltan = [c for c in COLUMNAS_OBLIGATORIAS if c not in indices]
        if faltan:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"Faltan columnas obligatorias: {', '.join(faltan)}. Descarga la plantilla en /catalogo/plantilla",
            )

        resultado = []
        for numero, fila in enumerate(filas, start=2):
            if numero - 1 > MAX_FILAS_EXCEL:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, f"El archivo supera {MAX_FILAS_EXCEL} filas")
            if fila is None or all(c is None or str(c).strip() == "" for c in fila):
                continue
            datos = {clave: (fila[i] if i < len(fila) else None) for clave, i in indices.items()}
            resultado.append((numero, datos))
        return resultado
    finally:
        libro.close()


def validar_filas(db: Session, filas: list, margen: Decimal) -> list:
    """Valida cada fila (SKU repetidos, precios vacíos, números) y calcula categoría y precio."""
    skus = [str(d.get("sku") or "").strip().upper() for _, d in filas]
    existentes = {
        s for (s,) in db.query(Producto.sku).filter(Producto.sku.in_([s for s in skus if s])).all()
    }
    vistos = {}
    resultado = []
    for numero, d in filas:
        errores = []
        sku = str(d.get("sku") or "").strip().upper()
        nombre = str(d.get("nombre") or "").strip()
        marca = str(d.get("marca") or "").strip() or None
        proveedor = str(d.get("proveedor") or "").strip() or None

        if not sku:
            errores.append("SKU vacío")
        elif len(sku) > 50:
            errores.append("SKU demasiado largo (máximo 50 caracteres)")
        elif sku in vistos:
            errores.append(f"SKU repetido en el archivo (ya aparece en la fila {vistos[sku]})")
        else:
            vistos[sku] = numero

        if len(nombre) < 2:
            errores.append("Nombre vacío o demasiado corto")

        costo = a_decimal(d.get("costo"))
        if costo is None or costo <= 0:
            errores.append("Costo vacío o no es un número mayor que cero")
            costo = None
        else:
            costo = costo.quantize(Decimal("0.01"))

        try:
            stock_minimo = a_entero(d.get("stock_minimo"), STOCK_MINIMO_POR_DEFECTO)
        except ValueError as e:
            errores.append(f"Stock mínimo: {e}")
            stock_minimo = STOCK_MINIMO_POR_DEFECTO
        try:
            cantidad = a_entero(d.get("cantidad_inicial"), 0)
        except ValueError as e:
            errores.append(f"Cantidad inicial: {e}")
            cantidad = 0

        precio = Producto.precio_con_margen(costo, margen) if costo is not None else None
        resultado.append({
            "fila": numero,
            "sku": sku,
            "nombre": nombre,
            "marca": marca,
            "categoria": clasificar_categoria(nombre) if nombre else None,
            "costo": float(costo) if costo is not None else None,
            "precio": float(precio) if precio is not None else None,
            "stock_minimo": stock_minimo,
            "cantidad_inicial": cantidad,
            "proveedor": proveedor,
            "accion": "existente" if sku in existentes else "crear",
            "errores": errores,
            "_costo": costo,
            "_precio": precio,
        })
    return resultado


def aplicar_importacion(db: Session, filas: list) -> dict:
    productos_creados = 0
    lotes_creados = 0
    for f in filas:
        if f["accion"] == "crear":
            producto = Producto(
                sku=f["sku"], nombre=f["nombre"], marca=f["marca"],
                categoria_id=obtener_categoria(db, f["categoria"]).id,
                costo=f["_costo"], precio=f["_precio"], stock_minimo=f["stock_minimo"],
            )
            db.add(producto)
            db.flush()
            productos_creados += 1
        else:
            producto = db.query(Producto).filter(Producto.sku == f["sku"]).first()
        if f["cantidad_inicial"] > 0:
            crear_lote(db, producto, f["cantidad_inicial"], f["_costo"], f["proveedor"])
            lotes_creados += 1
    return {"productos_creados": productos_creados, "lotes_creados": lotes_creados}


def fila_publica(fila: dict) -> dict:
    return {k: v for k, v in fila.items() if not k.startswith("_")}


@app.get("/catalogo/plantilla", tags=["catalogo"])
def descargar_plantilla(_: Usuario = Depends(requiere_roles(*SOLO_ADMIN))):
    """Plantilla de Excel con las columnas que espera la importación."""
    libro = Workbook()
    hoja = libro.active
    hoja.title = "Catalogo"
    encabezado = ["SKU", "Nombre", "Marca", "Costo", "Stock minimo", "Cantidad inicial", "Proveedor"]
    hoja.append(encabezado)
    for celda in hoja[1]:
        celda.font = Font(bold=True, color="FFFFFF")
        celda.fill = PatternFill("solid", fgColor="0B1F3A")
    ejemplos = [
        ["CPU-R5-5600", "Procesador AMD Ryzen 5 5600 3.5GHz", "AMD", 540000, 3, 10, "Proveedor de ejemplo"],
        ["GPU-RTX4060-8G", "Tarjeta gráfica NVIDIA GeForce RTX 4060 8GB", "NVIDIA", 1450000, 3, 6, "Proveedor de ejemplo"],
        ["RAM-DDR4-16G", "Memoria RAM Kingston Fury 16GB DDR4 3200MHz", "Kingston", 165000, 5, 20, "Proveedor de ejemplo"],
        ["SSD-NVME-1T", "SSD NVMe M.2 Kingston NV2 1TB", "Kingston", 310000, 5, 15, "Proveedor de ejemplo"],
        ["MB-B550M", "Tarjeta madre ASUS Prime B550M-A", "ASUS", 520000, 2, 8, "Proveedor de ejemplo"],
        ["PSU-650W", "Fuente de poder Corsair CV650 650W 80 Plus Bronze", "Corsair", 290000, 3, 12, "Proveedor de ejemplo"],
    ]
    for fila in ejemplos:
        hoja.append(fila)
    for columna, ancho in zip("ABCDEFG", (18, 52, 14, 14, 14, 16, 24)):
        hoja.column_dimensions[columna].width = ancho
    buffer = io.BytesIO()
    libro.save(buffer)
    return Response(
        content=buffer.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="plantilla_catalogo.xlsx"'},
    )


@app.post("/catalogo/importar", tags=["catalogo"])
def importar_catalogo(
    archivo: UploadFile = File(...),
    confirmar: bool = False,
    db: Session = Depends(get_db),
    _: Usuario = Depends(requiere_roles(*SOLO_ADMIN)),
):
    """Importa productos y lotes iniciales desde Excel.
    Con confirmar=false (por defecto) solo muestra la vista previa; con confirmar=true guarda."""
    if not (archivo.filename or "").lower().endswith(".xlsx"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Sube un archivo Excel con extensión .xlsx")
    contenido = archivo.file.read(MAX_BYTES_EXCEL + 1)
    if len(contenido) > MAX_BYTES_EXCEL:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "El archivo supera los 5 MB")

    filas = leer_excel(contenido)
    if not filas:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "El archivo no tiene filas con datos")
    validadas = validar_filas(db, filas, obtener_margen(db))
    con_errores = [f for f in validadas if f["errores"]]

    resumen = {
        "filas": len(validadas),
        "con_errores": len(con_errores),
        "productos_nuevos": sum(1 for f in validadas if f["accion"] == "crear"),
        "productos_existentes": sum(1 for f in validadas if f["accion"] == "existente"),
        "lotes_a_crear": sum(1 for f in validadas if f["cantidad_inicial"] > 0),
    }

    if not confirmar:
        return {"confirmado": False, "resumen": resumen, "filas": [fila_publica(f) for f in validadas]}

    if con_errores:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "mensaje": "Corrige las filas con errores y vuelve a subir el archivo",
                "filas_con_error": [fila_publica(f) for f in con_errores],
            },
        )
    try:
        resultado = aplicar_importacion(db, validadas)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "No se pudo guardar la importación; intenta de nuevo")
    return {"confirmado": True, "resumen": resumen, **resultado}


# ===========================================================================
# B3: ESQUEMAS DE DIRECCIONES Y PEDIDOS
# ===========================================================================
class ClienteRegistro(BaseModel):
    nombre: str = Field(min_length=2, max_length=100)
    usuario: str = Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9._-]+$")
    password: str = Field(min_length=8, max_length=72)

    @field_validator("usuario")
    @classmethod
    def usuario_en_minuscula(cls, v: str) -> str:
        return v.lower()


class PlazoIn(BaseModel):
    dias: int = Field(ge=1, le=30)


class DireccionCrear(BaseModel):
    etiqueta: Literal["casa", "oficina", "otra"] = "casa"
    texto: str = Field(min_length=5, max_length=255)
    latitud: float = Field(ge=-90, le=90)
    longitud: float = Field(ge=-180, le=180)
    indicaciones: Optional[str] = Field(default=None, max_length=255)    # apartamento, portería (opcional)
    principal: bool = False


class DireccionOut(BaseModel):
    id: int
    etiqueta: str
    texto: str
    latitud: float
    longitud: float
    indicaciones: Optional[str]
    principal: bool


class ItemPedido(BaseModel):
    producto_id: int
    cantidad: int = Field(gt=0, le=1000)


class PedidoCrear(BaseModel):
    direccion_id: Optional[int] = None     # si no se envía, usa la dirección principal
    items: List[ItemPedido] = Field(min_length=1, max_length=50)


class PosicionIn(BaseModel):
    latitud: Optional[float] = Field(default=None, ge=-90, le=90)
    longitud: Optional[float] = Field(default=None, ge=-180, le=180)


class ListoIn(BaseModel):
    escaneados: List[ItemPedido] = Field(min_length=1, max_length=50)


class RecibirIn(PosicionIn):
    codigo: str = Field(min_length=1, max_length=30)     # QR del paquete (código del pedido)


class EntregarIn(PosicionIn):
    qr: str = Field(min_length=1, max_length=64)         # QR que muestra el cliente


class LineaOut(BaseModel):
    producto_id: int
    sku: str
    nombre: str
    cantidad: int
    precio_unitario: float
    subtotal: float


class EventoOut(BaseModel):
    estado: PedidoEstado
    por: str
    fecha: Optional[datetime]
    latitud: Optional[float]
    longitud: Optional[float]
    nota: Optional[str]


class PedidoOut(BaseModel):
    id: int
    codigo: str
    estado: PedidoEstado
    cliente: Optional[str]
    total: float
    fecha_prometida: Optional[datetime]
    creado_en: Optional[datetime]
    direccion: DireccionOut
    lineas: List[LineaOut]
    eventos: List[EventoOut]
    qr_entrega: Optional[str]


class PedidoResumenOut(BaseModel):
    id: int
    codigo: str
    estado: PedidoEstado
    cliente: Optional[str]
    total: float
    unidades: int
    fecha_prometida: Optional[datetime]
    creado_en: Optional[datetime]


ESTADOS_ACTIVOS = (
    PedidoEstado.registrado,
    PedidoEstado.alistando,
    PedidoEstado.en_zona_envios,
    PedidoEstado.recibido_transportista,
    PedidoEstado.en_ruta,
)


# ===========================================================================
# CLIENTE (provisional hasta la fase C1: Google o celular)
# ===========================================================================
@app.post("/auth/registro-cliente", response_model=TokenOut, status_code=201, tags=["auth"])
def registro_cliente(datos: ClienteRegistro, db: Session = Depends(get_db)):
    if db.query(Usuario).filter(Usuario.usuario == datos.usuario).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Ese usuario ya existe")
    cliente = Usuario(
        nombre=datos.nombre.strip(),
        usuario=datos.usuario,
        password_hash=hash_password(datos.password),
        rol=Rol.usuario,
    )
    db.add(cliente)
    db.commit()
    db.refresh(cliente)
    return TokenOut(access_token=crear_token(cliente), usuario=cliente)


@app.post("/auth/login-cliente", response_model=TokenOut, tags=["auth"])
def login_cliente(datos: LoginIn, db: Session = Depends(get_db)):
    """Login de la app del cliente. Una cuenta del personal no puede entrar por aquí."""
    usuario = db.query(Usuario).filter(Usuario.usuario == datos.usuario).first()
    if usuario is None or not verificar_password(datos.password, usuario.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuario o contraseña incorrectos")
    if not usuario.activo:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cuenta desactivada")
    if usuario.rol != Rol.usuario:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Esta cuenta no es de cliente")
    return TokenOut(access_token=crear_token(usuario), usuario=usuario)


# ===========================================================================
# CONFIGURACIÓN: plazo de entrega
# ===========================================================================
def obtener_plazo_entrega(db: Session) -> int:
    fila = db.query(Configuracion).filter(Configuracion.clave == "plazo_entrega_dias").first()
    try:
        return int(fila.valor) if fila else PLAZO_ENTREGA_DIAS_POR_DEFECTO
    except ValueError:
        return PLAZO_ENTREGA_DIAS_POR_DEFECTO


@app.put("/configuracion/plazo-entrega", tags=["configuracion"])
def cambiar_plazo_entrega(
    datos: PlazoIn,
    db: Session = Depends(get_db),
    _: Usuario = Depends(requiere_roles(*SOLO_ADMIN)),
):
    """Días que se le prometen al cliente para la entrega (afecta a los pedidos nuevos)."""
    fila = db.query(Configuracion).filter(Configuracion.clave == "plazo_entrega_dias").first()
    if fila is None:
        db.add(Configuracion(clave="plazo_entrega_dias", valor=str(datos.dias)))
    else:
        fila.valor = str(datos.dias)
    db.commit()
    return {"plazo_entrega_dias": datos.dias}


# ===========================================================================
# MÓDULO: DIRECCIONES (cliente) — se guardan una sola vez y los pedidos la heredan
# ===========================================================================
MAX_DIRECCIONES = 10


def direccion_a_out(d: Direccion) -> DireccionOut:
    return DireccionOut(
        id=d.id, etiqueta=d.etiqueta, texto=d.texto, latitud=d.latitud, longitud=d.longitud,
        indicaciones=d.indicaciones, principal=d.principal,
    )


@app.post("/direcciones", response_model=DireccionOut, status_code=201, tags=["direcciones"])
def agregar_direccion(
    datos: DireccionCrear,
    db: Session = Depends(get_db),
    cliente: Usuario = Depends(requiere_roles(*SOLO_CLIENTE)),
):
    existentes = db.query(Direccion).filter(Direccion.usuario_id == cliente.id).all()
    if len(existentes) >= MAX_DIRECCIONES:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Máximo {MAX_DIRECCIONES} direcciones guardadas")
    # La primera dirección siempre queda como principal.
    sera_principal = datos.principal or not existentes
    if sera_principal:
        for d in existentes:
            d.principal = False
    nueva = Direccion(
        usuario_id=cliente.id, etiqueta=datos.etiqueta, texto=datos.texto.strip(),
        latitud=datos.latitud, longitud=datos.longitud,
        indicaciones=(datos.indicaciones or "").strip() or None, principal=sera_principal,
    )
    db.add(nueva)
    db.commit()
    db.refresh(nueva)
    return direccion_a_out(nueva)


@app.get("/direcciones", response_model=List[DireccionOut], tags=["direcciones"])
def listar_direcciones(
    db: Session = Depends(get_db),
    cliente: Usuario = Depends(requiere_roles(*SOLO_CLIENTE)),
):
    filas = (
        db.query(Direccion)
        .filter(Direccion.usuario_id == cliente.id)
        .order_by(Direccion.principal.desc(), Direccion.id)
        .all()
    )
    return [direccion_a_out(d) for d in filas]


@app.patch("/direcciones/{direccion_id}/principal", response_model=DireccionOut, tags=["direcciones"])
def marcar_principal(
    direccion_id: int,
    db: Session = Depends(get_db),
    cliente: Usuario = Depends(requiere_roles(*SOLO_CLIENTE)),
):
    direccion = db.get(Direccion, direccion_id)
    if direccion is None or direccion.usuario_id != cliente.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Dirección no encontrada")
    for d in db.query(Direccion).filter(Direccion.usuario_id == cliente.id).all():
        d.principal = d.id == direccion.id
    db.commit()
    db.refresh(direccion)
    return direccion_a_out(direccion)


# ===========================================================================
# MÓDULO: PEDIDOS — construcción de respuestas y reglas comunes
# ===========================================================================
def registrar_evento(db: Session, pedido: Pedido, estado: PedidoEstado, usuario: Usuario,
                     latitud: Optional[float] = None, longitud: Optional[float] = None,
                     nota: Optional[str] = None) -> None:
    """Deja constancia en la cadena de custodia: quién, cuándo (automático) y dónde."""
    db.add(PedidoEvento(
        pedido_id=pedido.id, estado=estado, usuario_id=usuario.id,
        latitud=latitud, longitud=longitud, nota=nota,
    ))


def pedido_a_out(pedido: Pedido, quien: Usuario) -> PedidoOut:
    es_cliente = quien.rol == Rol.usuario
    # El QR de entrega solo lo ve su dueño y mientras el pedido siga en camino.
    ver_qr = es_cliente and pedido.estado in ESTADOS_ACTIVOS
    lineas = [
        LineaOut(
            producto_id=d.producto_id, sku=d.producto.sku, nombre=d.producto.nombre,
            cantidad=d.cantidad, precio_unitario=float(d.precio_unitario),
            subtotal=float(d.precio_unitario * d.cantidad),
        )
        for d in pedido.detalles
    ]
    eventos = [
        EventoOut(
            estado=e.estado,
            por=e.usuario.rol.value if es_cliente else e.usuario.nombre,
            fecha=e.creado_en, latitud=e.latitud, longitud=e.longitud, nota=e.nota,
        )
        for e in pedido.eventos
    ]
    return PedidoOut(
        id=pedido.id, codigo=pedido.codigo, estado=pedido.estado,
        cliente=None if es_cliente else pedido.cliente.nombre,
        total=float(pedido.total), fecha_prometida=pedido.fecha_prometida,
        creado_en=pedido.creado_en, direccion=direccion_a_out(pedido.direccion),
        lineas=lineas, eventos=eventos, qr_entrega=pedido.qr_entrega if ver_qr else None,
    )


def pedido_a_resumen(pedido: Pedido, quien: Usuario) -> PedidoResumenOut:
    return PedidoResumenOut(
        id=pedido.id, codigo=pedido.codigo, estado=pedido.estado,
        cliente=None if quien.rol == Rol.usuario else pedido.cliente.nombre,
        total=float(pedido.total), unidades=sum(d.cantidad for d in pedido.detalles),
        fecha_prometida=pedido.fecha_prometida, creado_en=pedido.creado_en,
    )


def cargar_pedido(db: Session, pedido_id: int, bloquear: bool = False) -> Pedido:
    consulta = db.query(Pedido).filter(Pedido.id == pedido_id)
    if bloquear:
        consulta = consulta.with_for_update()    # evita que dos personas cambien el mismo pedido a la vez
    pedido = consulta.first()
    if pedido is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Pedido no encontrado")
    return pedido


def exigir_estado(pedido: Pedido, esperado: PedidoEstado) -> None:
    """Los estados avanzan en orden: solo se permite el paso que sigue."""
    if pedido.estado != esperado:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"El pedido está en «{pedido.estado.value}»; para esta acción debe estar en «{esperado.value}»",
        )


def exigir_responsable(responsable_id: Optional[int], usuario: Usuario, mensaje: str) -> None:
    if responsable_id != usuario.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, mensaje)


# ===========================================================================
# RESERVA DE STOCK POR FIFO
# ===========================================================================
def reservar_fifo(db: Session, producto: Producto, cantidad: int, detalle: PedidoDetalle) -> None:
    """Descuenta del lote más antiguo primero y registra de qué lote salió cada unidad.
    Si no alcanza el stock, falla y todo el pedido se deshace."""
    lotes = (
        db.query(Lote)
        .filter(
            Lote.producto_id == producto.id,
            Lote.estado != LoteEstado.agotado,
            Lote.cantidad_restante > 0,
        )
        .order_by(Lote.fecha_recepcion, Lote.id)
        .with_for_update()
        .all()
    )
    disponible = sum(l.cantidad_restante for l in lotes)
    if disponible < cantidad:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={
                "mensaje": f"Stock insuficiente de «{producto.nombre}»",
                "producto_id": producto.id,
                "pedido": cantidad,
                "disponible": disponible,
            },
        )
    faltante = cantidad
    for lote in lotes:
        if faltante == 0:
            break
        tomar = min(lote.cantidad_restante, faltante)
        lote.cantidad_restante -= tomar
        if lote.cantidad_restante == 0:
            lote.estado = LoteEstado.agotado
        db.add(AsignacionLote(detalle_id=detalle.id, lote_id=lote.id, cantidad=tomar))
        faltante -= tomar


def liberar_stock(pedido: Pedido) -> None:
    """Devuelve a los lotes lo que el pedido había reservado (al cancelarlo)."""
    for detalle in pedido.detalles:
        for asignacion in detalle.asignaciones:
            lote = asignacion.lote
            lote.cantidad_restante += asignacion.cantidad
            if lote.estado == LoteEstado.agotado:
                lote.estado = LoteEstado.almacenado


# ===========================================================================
# MÓDULO: PEDIDOS — cliente
# ===========================================================================
@app.post("/pedidos", response_model=PedidoOut, status_code=201, tags=["pedidos"])
def crear_pedido(
    datos: PedidoCrear,
    db: Session = Depends(get_db),
    cliente: Usuario = Depends(requiere_roles(*SOLO_CLIENTE)),
):
    """El cliente confirma su pedido: se valida el stock y se reserva por FIFO.
    Cliente, dirección, productos y precios salen del sistema; nadie digita nada."""
    # Dirección: la indicada o, si no, la principal. Un pedido sin dirección no se puede hacer.
    if datos.direccion_id is not None:
        direccion = db.get(Direccion, datos.direccion_id)
        if direccion is None or direccion.usuario_id != cliente.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Dirección no encontrada")
    else:
        direccion = (
            db.query(Direccion)
            .filter(Direccion.usuario_id == cliente.id, Direccion.principal.is_(True))
            .first()
        )
        if direccion is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Agrega una dirección antes de hacer un pedido")

    # Si el mismo producto viene repetido, se suman las cantidades.
    cantidades = {}
    for item in datos.items:
        cantidades[item.producto_id] = cantidades.get(item.producto_id, 0) + item.cantidad
    productos = {
        p.id: p for p in db.query(Producto).filter(Producto.id.in_(list(cantidades))).all()
    }
    for producto_id in cantidades:
        producto = productos.get(producto_id)
        if producto is None or not producto.activo:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"El producto {producto_id} no está disponible")

    pedido = Pedido(
        codigo=siguiente_codigo(db, Pedido.codigo, "PED"),
        cliente_id=cliente.id,
        direccion_id=direccion.id,
        estado=PedidoEstado.registrado,
        total=Decimal("0"),
        fecha_prometida=datetime.now(timezone.utc) + timedelta(days=obtener_plazo_entrega(db)),
        qr_entrega=secrets.token_urlsafe(16),
    )
    try:
        db.add(pedido)
        db.flush()
        total = Decimal("0")
        for producto_id in sorted(cantidades):    # orden fijo para evitar bloqueos cruzados
            producto = productos[producto_id]
            cantidad = cantidades[producto_id]
            detalle = PedidoDetalle(
                pedido_id=pedido.id, producto_id=producto.id,
                cantidad=cantidad, precio_unitario=producto.precio,
            )
            db.add(detalle)
            db.flush()
            reservar_fifo(db, producto, cantidad, detalle)
            total += producto.precio * cantidad
        pedido.total = total
        registrar_evento(db, pedido, PedidoEstado.registrado, cliente)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "No se pudo registrar el pedido; intenta de nuevo")
    db.refresh(pedido)
    return pedido_a_out(pedido, cliente)


@app.get("/pedidos/mios", response_model=List[PedidoResumenOut], tags=["pedidos"])
def mis_pedidos(
    db: Session = Depends(get_db),
    cliente: Usuario = Depends(requiere_roles(*SOLO_CLIENTE)),
):
    pedidos = db.query(Pedido).filter(Pedido.cliente_id == cliente.id).order_by(Pedido.id.desc()).all()
    return [pedido_a_resumen(p, cliente) for p in pedidos]


@app.post("/pedidos/{pedido_id}/cancelar", response_model=PedidoOut, tags=["pedidos"])
def cancelar_pedido(
    pedido_id: int,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(usuario_actual),
):
    """El cliente puede cancelar mientras el pedido siga «registrado». Gerencia y administración
    pueden cancelar hasta que esté en la zona de envíos. El stock reservado vuelve a los lotes."""
    pedido = cargar_pedido(db, pedido_id, bloquear=True)
    if usuario.rol == Rol.usuario:
        if pedido.cliente_id != usuario.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Pedido no encontrado")
        permitidos = (PedidoEstado.registrado,)
    elif usuario.rol in ADMIN_Y_GERENTE:
        permitidos = (PedidoEstado.registrado, PedidoEstado.alistando, PedidoEstado.en_zona_envios)
    else:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "No tienes permiso para esta acción")
    if pedido.estado not in permitidos:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Un pedido en «{pedido.estado.value}» ya no se puede cancelar",
        )
    liberar_stock(pedido)
    pedido.estado = PedidoEstado.cancelado
    registrar_evento(db, pedido, PedidoEstado.cancelado, usuario)
    db.commit()
    db.refresh(pedido)
    return pedido_a_out(pedido, usuario)


# ===========================================================================
# MÓDULO: PEDIDOS — consulta (cliente y personal)
# ===========================================================================
@app.get("/pedidos", response_model=List[PedidoResumenOut], tags=["pedidos"])
def listar_pedidos(
    estado: Optional[PedidoEstado] = None,
    mios: bool = False,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(requiere_roles(*TODO_PERSONAL)),
):
    """Lista para el personal. La cola de alistamiento es estado=registrado (los más antiguos primero).
    Con mios=true solo se ven los pedidos que atiende esta persona."""
    consulta = db.query(Pedido)
    if estado is not None:
        consulta = consulta.filter(Pedido.estado == estado)
    if mios:
        consulta = consulta.filter(
            (Pedido.operario_id == usuario.id) | (Pedido.transportista_id == usuario.id)
        )
    orden = Pedido.id.asc() if estado == PedidoEstado.registrado else Pedido.id.desc()
    return [pedido_a_resumen(p, usuario) for p in consulta.order_by(orden).all()]


@app.get("/pedidos/{pedido_id}", response_model=PedidoOut, tags=["pedidos"])
def ver_pedido(
    pedido_id: int,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(usuario_actual),
):
    pedido = cargar_pedido(db, pedido_id)
    if usuario.rol == Rol.usuario and pedido.cliente_id != usuario.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Pedido no encontrado")
    return pedido_a_out(pedido, usuario)


# ===========================================================================
# MÓDULO: PEDIDOS — pasos del personal (cada uno es una acción real y en orden)
# ===========================================================================
@app.post("/pedidos/{pedido_id}/tomar", response_model=PedidoOut, tags=["pedidos"])
def tomar_pedido(
    pedido_id: int,
    db: Session = Depends(get_db),
    operario: Usuario = Depends(requiere_roles(Rol.operario)),
):
    """Registrado → Alistando: el operario toma la tarea de la cola."""
    pedido = cargar_pedido(db, pedido_id, bloquear=True)
    exigir_estado(pedido, PedidoEstado.registrado)
    pedido.estado = PedidoEstado.alistando
    pedido.operario_id = operario.id
    registrar_evento(db, pedido, PedidoEstado.alistando, operario)
    db.commit()
    db.refresh(pedido)
    return pedido_a_out(pedido, operario)


@app.post("/pedidos/{pedido_id}/listo", response_model=PedidoOut, tags=["pedidos"])
def listo_para_envio(
    pedido_id: int,
    datos: ListoIn,
    db: Session = Depends(get_db),
    operario: Usuario = Depends(requiere_roles(Rol.operario)),
):
    """Alistando → En zona de envíos: el operario confirma lo que escaneó.
    Las cantidades escaneadas deben coincidir exactamente con las del pedido."""
    pedido = cargar_pedido(db, pedido_id, bloquear=True)
    exigir_estado(pedido, PedidoEstado.alistando)
    exigir_responsable(pedido.operario_id, operario, "Este pedido lo alista otro operario")

    esperado = {d.producto_id: d.cantidad for d in pedido.detalles}
    escaneado = {}
    for item in datos.escaneados:
        escaneado[item.producto_id] = escaneado.get(item.producto_id, 0) + item.cantidad
    faltan = {pid: esperado[pid] - escaneado.get(pid, 0)
              for pid in esperado if escaneado.get(pid, 0) < esperado[pid]}
    sobran = {pid: escaneado[pid] - esperado.get(pid, 0)
              for pid in escaneado if escaneado[pid] > esperado.get(pid, 0)}
    if faltan or sobran:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "mensaje": "Lo escaneado no coincide con el pedido",
                "faltan": [{"producto_id": pid, "cantidad": c} for pid, c in faltan.items()],
                "sobran": [{"producto_id": pid, "cantidad": c} for pid, c in sobran.items()],
            },
        )
    pedido.estado = PedidoEstado.en_zona_envios
    registrar_evento(db, pedido, PedidoEstado.en_zona_envios, operario)
    db.commit()
    db.refresh(pedido)
    return pedido_a_out(pedido, operario)


@app.post("/pedidos/{pedido_id}/recibir-transportista", response_model=PedidoOut, tags=["pedidos"])
def recibir_transportista(
    pedido_id: int,
    datos: RecibirIn,
    db: Session = Depends(get_db),
    transportista: Usuario = Depends(requiere_roles(Rol.transportista)),
):
    """En zona de envíos → Recibido por transportista: escanea el QR del paquete (traspaso de custodia)."""
    pedido = cargar_pedido(db, pedido_id, bloquear=True)
    exigir_estado(pedido, PedidoEstado.en_zona_envios)
    if datos.codigo.strip().upper() != pedido.codigo:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "El QR no corresponde a este pedido")
    pedido.estado = PedidoEstado.recibido_transportista
    pedido.transportista_id = transportista.id
    registrar_evento(db, pedido, PedidoEstado.recibido_transportista, transportista,
                     datos.latitud, datos.longitud)
    db.commit()
    db.refresh(pedido)
    return pedido_a_out(pedido, transportista)


@app.post("/pedidos/{pedido_id}/iniciar-ruta", response_model=PedidoOut, tags=["pedidos"])
def iniciar_ruta(
    pedido_id: int,
    datos: Optional[PosicionIn] = None,
    db: Session = Depends(get_db),
    transportista: Usuario = Depends(requiere_roles(Rol.transportista)),
):
    """Recibido por transportista → En ruta."""
    pedido = cargar_pedido(db, pedido_id, bloquear=True)
    exigir_estado(pedido, PedidoEstado.recibido_transportista)
    exigir_responsable(pedido.transportista_id, transportista, "Este pedido lo lleva otro transportista")
    pedido.estado = PedidoEstado.en_ruta
    registrar_evento(db, pedido, PedidoEstado.en_ruta, transportista,
                     datos.latitud if datos else None, datos.longitud if datos else None)
    db.commit()
    db.refresh(pedido)
    return pedido_a_out(pedido, transportista)


@app.post("/pedidos/{pedido_id}/entregar", response_model=PedidoOut, tags=["pedidos"])
def entregar_pedido(
    pedido_id: int,
    datos: EntregarIn,
    db: Session = Depends(get_db),
    transportista: Usuario = Depends(requiere_roles(Rol.transportista)),
):
    """En ruta → Entregado: el transportista escanea el QR que le muestra el cliente."""
    pedido = cargar_pedido(db, pedido_id, bloquear=True)
    exigir_estado(pedido, PedidoEstado.en_ruta)
    exigir_responsable(pedido.transportista_id, transportista, "Este pedido lo lleva otro transportista")
    if not secrets.compare_digest(datos.qr.strip(), pedido.qr_entrega):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "El QR de entrega no es válido")
    pedido.estado = PedidoEstado.entregado
    registrar_evento(db, pedido, PedidoEstado.entregado, transportista, datos.latitud, datos.longitud)
    db.commit()
    db.refresh(pedido)
    return pedido_a_out(pedido, transportista)