import enum
import os
from datetime import datetime, timezone
from decimal import Decimal

from dotenv import load_dotenv
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    Numeric,
    String,
    create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
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


# ---------------------------------------------------------------------------
# CONFIGURACIÓN (un solo lugar para los parámetros: margen, tarifa kWh, etc.)
# ---------------------------------------------------------------------------
class Configuracion(ModeloBase):
    __tablename__ = "configuracion"

    clave = Column(String(50), unique=True, nullable=False)
    valor = Column(String(255), nullable=False)


# ---------------------------------------------------------------------------
# CATÁLOGO: categorías y productos
# ---------------------------------------------------------------------------
class Categoria(ModeloBase):
    __tablename__ = "categorias"

    nombre = Column(String(60), unique=True, nullable=False)


class Producto(ModeloBase):
    __tablename__ = "productos"

    sku = Column(String(50), unique=True, index=True, nullable=False)
    nombre = Column(String(150), nullable=False)
    marca = Column(String(80))
    categoria_id = Column(Integer, ForeignKey("categorias.id"), nullable=False)
    costo = Column(Numeric(14, 2), nullable=False)
    precio = Column(Numeric(14, 2), nullable=False)   # costo + margen configurado
    stock_minimo = Column(Integer, default=5, nullable=False)
    activo = Column(Boolean, default=True, nullable=False)

    categoria = relationship("Categoria")

    @staticmethod
    def precio_con_margen(costo, margen_porcentaje) -> Decimal:
        """Precio de venta = costo + margen (en porcentaje), a 2 decimales."""
        costo = Decimal(str(costo))
        margen = Decimal(str(margen_porcentaje))
        return (costo * (1 + margen / 100)).quantize(Decimal("0.01"))


# ---------------------------------------------------------------------------
# LOTES (base de la trazabilidad y del FIFO)
# ---------------------------------------------------------------------------
class LoteEstado(str, enum.Enum):
    recibido = "recibido"
    almacenado = "almacenado"
    agotado = "agotado"


class Lote(ModeloBase):
    __tablename__ = "lotes"

    codigo = Column(String(20), unique=True, index=True, nullable=False)   # LOT-AAAA-NNNN
    producto_id = Column(Integer, ForeignKey("productos.id"), index=True, nullable=False)
    cantidad_inicial = Column(Integer, nullable=False)
    cantidad_restante = Column(Integer, nullable=False)
    costo_unitario = Column(Numeric(14, 2), nullable=False)
    proveedor = Column(String(100))     # solo es un dato del lote; no hay comunicación con el proveedor
    fecha_recepcion = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    estado = Column(
        Enum(LoteEstado, native_enum=False, length=20),
        default=LoteEstado.recibido,
        nullable=False,
    )

    producto = relationship("Producto")


# ---------------------------------------------------------------------------
# B3: DIRECCIONES Y PEDIDOS
# ---------------------------------------------------------------------------
class Direccion(ModeloBase):
    __tablename__ = "direcciones"

    usuario_id = Column(Integer, ForeignKey("usuarios.id"), index=True, nullable=False)
    etiqueta = Column(String(20), nullable=False, default="casa")     # casa, oficina u otra
    texto = Column(String(255), nullable=False)
    latitud = Column(Float, nullable=False)
    longitud = Column(Float, nullable=False)
    indicaciones = Column(String(255))                                 # apartamento, portería (opcional)
    principal = Column(Boolean, default=False, nullable=False)


class PedidoEstado(str, enum.Enum):
    registrado = "registrado"
    alistando = "alistando"
    en_zona_envios = "en_zona_envios"
    recibido_transportista = "recibido_transportista"
    en_ruta = "en_ruta"
    entregado = "entregado"
    cancelado = "cancelado"


class Pedido(ModeloBase):
    __tablename__ = "pedidos"

    codigo = Column(String(20), unique=True, index=True, nullable=False)    # PED-AAAA-NNNN
    cliente_id = Column(Integer, ForeignKey("usuarios.id"), index=True, nullable=False)
    direccion_id = Column(Integer, ForeignKey("direcciones.id"), nullable=False)
    estado = Column(
        Enum(PedidoEstado, native_enum=False, length=30),
        default=PedidoEstado.registrado,
        index=True,
        nullable=False,
    )
    total = Column(Numeric(14, 2), nullable=False, default=0)
    fecha_prometida = Column(DateTime(timezone=True))
    qr_entrega = Column(String(64), nullable=False)       # lo muestra el cliente al transportista
    operario_id = Column(Integer, ForeignKey("usuarios.id"))
    transportista_id = Column(Integer, ForeignKey("usuarios.id"))

    cliente = relationship("Usuario", foreign_keys=[cliente_id])
    direccion = relationship("Direccion")
    detalles = relationship("PedidoDetalle", back_populates="pedido", order_by="PedidoDetalle.id")
    eventos = relationship("PedidoEvento", back_populates="pedido", order_by="PedidoEvento.id")


class PedidoDetalle(ModeloBase):
    __tablename__ = "pedido_detalles"

    pedido_id = Column(Integer, ForeignKey("pedidos.id"), index=True, nullable=False)
    producto_id = Column(Integer, ForeignKey("productos.id"), nullable=False)
    cantidad = Column(Integer, nullable=False)
    precio_unitario = Column(Numeric(14, 2), nullable=False)

    pedido = relationship("Pedido", back_populates="detalles")
    producto = relationship("Producto")
    asignaciones = relationship("AsignacionLote", back_populates="detalle")


class AsignacionLote(ModeloBase):
    """De qué lote salió cada producto del pedido (garantías y trazabilidad)."""
    __tablename__ = "asignaciones_lote"

    detalle_id = Column(Integer, ForeignKey("pedido_detalles.id"), index=True, nullable=False)
    lote_id = Column(Integer, ForeignKey("lotes.id"), index=True, nullable=False)
    cantidad = Column(Integer, nullable=False)

    detalle = relationship("PedidoDetalle", back_populates="asignaciones")
    lote = relationship("Lote")


class PedidoEvento(ModeloBase):
    """Cadena de custodia: cada cambio de estado queda con quién, cuándo y dónde."""
    __tablename__ = "pedido_eventos"

    pedido_id = Column(Integer, ForeignKey("pedidos.id"), index=True, nullable=False)
    estado = Column(Enum(PedidoEstado, native_enum=False, length=30), nullable=False)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), nullable=False)
    latitud = Column(Float)
    longitud = Column(Float)
    nota = Column(String(255))

    pedido = relationship("Pedido", back_populates="eventos")
    usuario = relationship("Usuario")