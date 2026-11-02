
import enum
import os
from datetime import datetime, timezone
from decimal import Decimal
 
from dotenv import load_dotenv
from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
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
 
 
# ---------------------------------------------------------------------------
# B4: COMPRAS SUGERIDAS Y RECEPCIÓN (registro interno; no se envía al proveedor)
# ---------------------------------------------------------------------------
class CompraEstado(str, enum.Enum):
    sugerida = "sugerida"              # la generó el sistema; espera al gerente
    aprobada = "aprobada"              # el gerente aprobó; se espera la mercancía
    rechazada = "rechazada"            # el gerente no la aprobó
    recibida = "recibida"              # llegó bien y el stock ya subió
    con_diferencias = "con_diferencias"  # llegó distinto a lo aprobado; stock retenido
    descartada = "descartada"          # el gerente decidió no ingresar lo recibido
 
 
class CompraSugerida(ModeloBase):
    __tablename__ = "compras"
 
    codigo = Column(String(20), unique=True, index=True, nullable=False)    # COM-AAAA-NNNN
    producto_id = Column(Integer, ForeignKey("productos.id"), index=True, nullable=False)
    cantidad_sugerida = Column(Integer, nullable=False)
    estado = Column(
        Enum(CompraEstado, native_enum=False, length=20),
        default=CompraEstado.sugerida,
        index=True,
        nullable=False,
    )
    proveedor = Column(String(100))            # solo un dato; no hay comunicación con el proveedor
    aprobada_por_id = Column(Integer, ForeignKey("usuarios.id"))
    fecha_aprobacion = Column(DateTime(timezone=True))
    fecha_estimada = Column(DateTime(timezone=True))
    recibida_por_id = Column(Integer, ForeignKey("usuarios.id"))
    fecha_recepcion = Column(DateTime(timezone=True))
    cantidad_buena = Column(Integer)
    cantidad_danada = Column(Integer)
    resuelta_por_id = Column(Integer, ForeignKey("usuarios.id"))
    nota = Column(String(255))
    lote_id = Column(Integer, ForeignKey("lotes.id"))
 
    producto = relationship("Producto")
    lote = relationship("Lote")
    aprobada_por = relationship("Usuario", foreign_keys=[aprobada_por_id])
    recibida_por = relationship("Usuario", foreign_keys=[recibida_por_id])
    resuelta_por = relationship("Usuario", foreign_keys=[resuelta_por_id])
 
 
# ---------------------------------------------------------------------------
# B5: VEHÍCULOS, POSICIÓN DEL TRANSPORTISTA Y LIQUIDACIÓN
# ---------------------------------------------------------------------------
class Vehiculo(ModeloBase):
    __tablename__ = "vehiculos"
 
    placa = Column(String(10), unique=True, index=True, nullable=False)
    tipo = Column(String(20), nullable=False)               # moto, carro, camioneta o camion
    descripcion = Column(String(100))
    transportista_id = Column(Integer, ForeignKey("usuarios.id"), unique=True)   # un vehículo por transportista
    activo = Column(Boolean, default=True, nullable=False)
 
    transportista = relationship("Usuario")
 
 
class PosicionTransportista(ModeloBase):
    """Última posición conocida de cada transportista (se actualiza; no guarda historial)."""
    __tablename__ = "posiciones_transportista"
 
    transportista_id = Column(Integer, ForeignKey("usuarios.id"), unique=True, index=True, nullable=False)
    latitud = Column(Float, nullable=False)
    longitud = Column(Float, nullable=False)
    actualizada_en = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                            onupdate=lambda: datetime.now(timezone.utc))
 
 
class Liquidacion(ModeloBase):
    """Una por entrega: guarda la tarifa y la comisión vigentes en el momento de entregar."""
    __tablename__ = "liquidaciones"
 
    pedido_id = Column(Integer, ForeignKey("pedidos.id"), unique=True, index=True, nullable=False)
    transportista_id = Column(Integer, ForeignKey("usuarios.id"), index=True, nullable=False)
    tarifa = Column(Numeric(14, 2), nullable=False)
    comision_porcentaje = Column(Numeric(5, 2), nullable=False)
    comision = Column(Numeric(14, 2), nullable=False)        # lo que gana el transportista
    pagada = Column(Boolean, default=False, nullable=False)
    fecha_pago = Column(DateTime(timezone=True))
 
    pedido = relationship("Pedido")
    transportista = relationship("Usuario")
 
 
# ---------------------------------------------------------------------------
# B6: JORNADA, HORAS EXTRA, BITÁCORA Y ENERGÍA
# ---------------------------------------------------------------------------
class Horario(ModeloBase):
    """Hora de inicio y de salida configuradas para una persona (formato HH:MM)."""
    __tablename__ = "horarios"
 
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), unique=True, index=True, nullable=False)
    hora_inicio = Column(String(5), nullable=False)
    hora_salida = Column(String(5), nullable=False)
 
    usuario = relationship("Usuario")
 
 
class Jornada(ModeloBase):
    """Una por persona y día. Guarda el horario con el que se trabajó ese día y la actividad real."""
    __tablename__ = "jornadas"
    __table_args__ = (UniqueConstraint("usuario_id", "fecha", name="uq_jornada_usuario_fecha"),)
 
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), index=True, nullable=False)
    fecha = Column(Date, nullable=False, index=True)
    inicio_programado = Column(DateTime(timezone=True), nullable=False)
    salida_programada = Column(DateTime(timezone=True), nullable=False)
    entrada_real = Column(DateTime(timezone=True))
    ultima_actividad = Column(DateTime(timezone=True))
    salida_real = Column(DateTime(timezone=True))
 
    usuario = relationship("Usuario")
 
 
class HoraExtraEstado(str, enum.Enum):
    solicitada = "solicitada"
    aprobada = "aprobada"
    rechazada = "rechazada"
 
 
class HoraExtra(ModeloBase):
    """Horas extra de una persona en un día. Solo cuentan si el gerente las aprobó o las programó."""
    __tablename__ = "horas_extra"
    __table_args__ = (UniqueConstraint("usuario_id", "fecha", name="uq_hora_extra_usuario_fecha"),)
 
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), index=True, nullable=False)
    fecha = Column(Date, nullable=False, index=True)
    hora_fin = Column(String(5), nullable=False)
    estado = Column(
        Enum(HoraExtraEstado, native_enum=False, length=20),
        default=HoraExtraEstado.solicitada,
        nullable=False,
    )
    motivo = Column(String(40))
    es_correccion = Column(Boolean, default=False, nullable=False)    # pedida después de que pasó el día
    creada_por_id = Column(Integer, ForeignKey("usuarios.id"))
    resuelta_por_id = Column(Integer, ForeignKey("usuarios.id"))
 
    usuario = relationship("Usuario", foreign_keys=[usuario_id])
    resuelta_por = relationship("Usuario", foreign_keys=[resuelta_por_id])
 
 
class Bitacora(ModeloBase):
    """Registro de aprobaciones e intentos de ingreso fuera de horario."""
    __tablename__ = "bitacora"
 
    usuario_id = Column(Integer, ForeignKey("usuarios.id"))
    accion = Column(String(40), index=True, nullable=False)
    detalle = Column(String(255))
 
    usuario = relationship("Usuario")
 
 
class Zona(ModeloBase):
    __tablename__ = "zonas"
 
    nombre = Column(String(80), unique=True, nullable=False)
    umbral_kwh_mensual = Column(Numeric(14, 2))        # si se supera en el mes, genera alerta
    activa = Column(Boolean, default=True, nullable=False)
 
    equipos = relationship("Equipo", back_populates="zona", order_by="Equipo.id")
 
 
class Equipo(ModeloBase):
    __tablename__ = "equipos"
 
    zona_id = Column(Integer, ForeignKey("zonas.id"), index=True, nullable=False)
    nombre = Column(String(100), nullable=False)
    potencia_kw = Column(Numeric(10, 2), nullable=False)
    tipo = Column(String(10), nullable=False)          # "jornada" (solo en horas de trabajo) o "continuo" (24 h)
    activo = Column(Boolean, default=True, nullable=False)
 
    zona = relationship("Zona", back_populates="equipos")