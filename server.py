import os
import math
import json
import queue
import sqlite3
import datetime
import hmac
import secrets
import time
import threading
import re
from collections import defaultdict
from typing import List
from flask import Flask, request, jsonify, send_from_directory, render_template_string, Response, redirect

app = Flask(__name__, static_folder=".", static_url_path="")

DB_PATH = os.path.join(os.path.dirname(__file__), "mandados.db")

# =========================================================
# CORS HEADER (PERMITE ACCESO MULTI-ORIGEN SEGURO)
# =========================================================
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization,X-Driver-Token,X-Session-Token,X-Admin-Key"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response

# =========================================================
# RATE LIMITING ANTI-SPOOFING & TTL DE MANDADOS
# =========================================================
def get_client_ip() -> str:
    # 1. Si nginx está configurado con proxy_set_header X-Real-IP $remote_addr, esta cabecera es confiable
    real_ip = request.headers.get("X-Real-IP", "").strip()
    if real_ip:
        return real_ip

    # 2. Si solo hay XFF, tomamos el ÚLTIMO hop confiable (servidor adyacente), NUNCA el primero falsificable
    xff = request.headers.get("X-Forwarded-For", "").strip()
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[-1]

    # 3. Fallback directo a la dirección de socket local
    return request.remote_addr or "127.0.0.1"

class InMemoryRateLimiter:
    def __init__(self, max_requests: int = 5, window_sec: int = 60):
        self.max_requests = max_requests
        self.window_sec = window_sec
        self.requests = defaultdict(list)
        self.lock = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        with self.lock:
            timestamps = self.requests[key]
            valid = [t for t in timestamps if now - t < self.window_sec]
            if len(valid) >= self.max_requests:
                self.requests[key] = valid
                return False
            valid.append(now)
            self.requests[key] = valid
            return True

viaje_rate_limiter = InMemoryRateLimiter(max_requests=5, window_sec=60)
recarga_rate_limiter = InMemoryRateLimiter(max_requests=5, window_sec=60)
registro_rate_limiter = InMemoryRateLimiter(max_requests=10, window_sec=60)

def registrar_evento_bitacora(viaje_id: int, anterior: str, nuevo: str, actor: str = "sistema", detalles: str = ""):
    """Registra de forma inmutable cada cambio de estado en la tabla bitacora_estados (caja negra de auditoría)."""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO bitacora_estados (viaje_id, estado_anterior, estado_nuevo, actor, detalles)
                VALUES (?, ?, ?, ?, ?)
            """, (viaje_id, anterior, nuevo, actor, detalles))
            conn.commit()
    except Exception:
        pass

def purge_expired_trips():
    """Barre encargos en estado 'buscando' que superan el TTL y los marca como 'expirado'."""
    try:
        ttl_sec = int(os.getenv("MANDADOS_VIAJE_TTL_SEC", "900"))
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id FROM viajes
                WHERE estado = 'buscando'
                  AND (strftime('%s', 'now') - strftime('%s', created_at)) > ?
            """, (ttl_sec,))
            expired_ids = [r["id"] for r in cursor.fetchall()]
            for x_id in expired_ids:
                registrar_evento_bitacora(x_id, "buscando", "expirado", actor="sistema", detalles="TTL de búsqueda expirado")

            cursor.execute("""
                UPDATE viajes
                SET estado = 'expirado', updated_at = CURRENT_TIMESTAMP
                WHERE estado = 'buscando'
                  AND (strftime('%s', 'now') - strftime('%s', created_at)) > ?
            """, (ttl_sec,))
            conn.commit()
    except Exception:
        pass

@app.before_request
def before_request_hook():
    purge_expired_trips()


# =========================================================
# BASE DE DATOS Y CONEXIONES (MODO WAL)
# =========================================================
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. Repartidores / Conductores
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS conductores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                cedula TEXT,
                telefono TEXT NOT NULL UNIQUE,
                unidad TEXT NOT NULL,
                placa TEXT,
                driver_token TEXT UNIQUE,
                suspendido INTEGER DEFAULT 0,
                reglas_aceptadas INTEGER DEFAULT 0,
                lat REAL DEFAULT 12.1364,
                lng REAL DEFAULT -86.2514,
                is_online INTEGER DEFAULT 0,
                plan_activo INTEGER DEFAULT 1,
                plan_nombre TEXT DEFAULT 'Pionero (15 Días Gratis)',
                plan_expira TEXT,
                is_demo INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        for col, col_def in [
            ("cedula", "TEXT"),
            ("placa", "TEXT"),
            ("suspendido", "INTEGER DEFAULT 0"),
            ("reglas_aceptadas", "INTEGER DEFAULT 0"),
            ("driver_token", "TEXT"),
            ("is_demo", "INTEGER DEFAULT 0")
        ]:
            try:
                cursor.execute(f"ALTER TABLE conductores ADD COLUMN {col} {col_def};")
            except sqlite3.OperationalError:
                pass

        # Generar driver_token para repartidores existentes sin token
        cursor.execute("SELECT id FROM conductores WHERE driver_token IS NULL OR driver_token = ''")
        for row in cursor.fetchall():
            cursor.execute("UPDATE conductores SET driver_token = ? WHERE id = ?", (f"MD-DRV-{secrets.token_hex(12)}", row["id"]))
        
        # 2. Mandados / Encargos (Viajes)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS viajes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT,
                pasajero_nombre TEXT DEFAULT 'Cliente',
                cliente_telefono TEXT DEFAULT '',
                origen TEXT NOT NULL,
                destino TEXT NOT NULL,
                paquete_desc TEXT DEFAULT '',
                tarifa REAL NOT NULL,
                lat_origen REAL,
                lng_origen REAL,
                estado TEXT DEFAULT 'buscando',
                conductor_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (conductor_id) REFERENCES conductores(id)
            )
        """)
        for col, col_def in [
            ("session_token", "TEXT"),
            ("paquete_desc", "TEXT DEFAULT ''"),
            ("cliente_telefono", "TEXT DEFAULT ''")
        ]:
            try:
                cursor.execute(f"ALTER TABLE viajes ADD COLUMN {col} {col_def};")
            except sqlite3.OperationalError:
                pass
        
        # 3. Recargas Banpro
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS recargas_banpro (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conductor_id INTEGER NOT NULL,
                plan_nombre TEXT NOT NULL,
                monto REAL NOT NULL,
                referencia TEXT,
                estado TEXT DEFAULT 'pendiente',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (conductor_id) REFERENCES conductores(id)
            )
        """)
        
        # 4. Registro de Visitas y Analítica
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS visitas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                user_agent TEXT,
                origen_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 5. Bitácora de Estados (Caja Negra de Auditoría)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bitacora_estados (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                viaje_id INTEGER NOT NULL,
                estado_anterior TEXT,
                estado_nuevo TEXT NOT NULL,
                actor TEXT DEFAULT 'sistema',
                detalles TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (viaje_id) REFERENCES viajes(id)
            )
        """)
        
        # Insertar repartidores iniciales si la tabla está vacía Y MANDADOS_SEED_DEMO == "1"
        cursor.execute("SELECT COUNT(*) FROM conductores")
        if cursor.fetchone()[0] == 0 and os.getenv("MANDADOS_SEED_DEMO", "0") == "1":
            is_launch_free = os.environ.get("PLAN_GRATIS_LAUNCH", "").strip() == "1"
            exp_days = 365 if is_launch_free else 15
            plan_seed_nom = "Lanzamiento (Gratis)" if is_launch_free else "Pionero (15 Días Gratis)"
            exp_date = (datetime.datetime.now() + datetime.timedelta(days=exp_days)).strftime("%Y-%m-%d")
            initial_drivers = [
                ("Carlos Ruiz", "001-280590-0001A", "50589130414", "Unidad #1 · Moto Reparto Express", "MY-10293", f"MD-DRV-{secrets.token_hex(12)}", 0, 1, 12.1370, -86.2520, 1, 1, plan_seed_nom, exp_date, 1),
                ("Kevin Morales", "001-140292-0002B", "50588881111", "Unidad #4 · Mensajería Ágil", "MY-40912", f"MD-DRV-{secrets.token_hex(12)}", 0, 1, 12.1390, -86.2490, 1, 1, plan_seed_nom, exp_date, 1),
                ("Pedro Dávila", "001-091195-0003C", "50588882222", "Unidad #9 · Moto Envíos", "MY-99214", f"MD-DRV-{secrets.token_hex(12)}", 0, 1, 12.1340, -86.2540, 1, 1, plan_seed_nom, exp_date, 1)
            ]
            cursor.executemany("""
                INSERT INTO conductores (nombre, cedula, telefono, unidad, placa, driver_token, suspendido, reglas_aceptadas, lat, lng, is_online, plan_activo, plan_nombre, plan_expira, is_demo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, initial_drivers)
            
        conn.commit()

init_db()

# Cálculo de distancia Haversine en KM
def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    try:
        R = 6371.0
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return round(R * c, 2)
    except Exception:
        return 1.0

# =========================================================
# AUTENTICACIÓN DEL REPARTIDOR (TOKEN EN TIEMPO CONSTANTE)
# =========================================================
def get_authenticated_driver(expected_conductor_id=None):
    token = request.headers.get("X-Driver-Token", "").strip()
    if not token:
        return None, (jsonify({"success": False, "error": "Autenticación requerida: Header X-Driver-Token ausente"}), 403)

    with get_db() as conn:
        cursor = conn.cursor()
        if expected_conductor_id is not None:
            try:
                cid = int(expected_conductor_id)
            except (ValueError, TypeError):
                return None, (jsonify({"success": False, "error": "ID de conductor inválido"}), 400)
            cursor.execute("SELECT * FROM conductores WHERE id = ?", (cid,))
            driver = cursor.fetchone()
            if not driver or not driver["driver_token"] or not hmac.compare_digest(token, driver["driver_token"]):
                return None, (jsonify({"success": False, "error": "Acceso denegado: X-Driver-Token no coincide con el conductor"}), 403)
            driver_dict = dict(driver)
            if driver_dict.get("suspendido") == 1:
                return None, (jsonify({"success": False, "error": "Acceso denegado: Cuenta de repartidor suspendida por el operador"}), 403)
            return driver_dict, None
        else:
            cursor.execute("SELECT * FROM conductores WHERE driver_token IS NOT NULL AND driver_token != ''")
            for d in cursor.fetchall():
                if hmac.compare_digest(token, d["driver_token"]):
                    driver_dict = dict(d)
                    if driver_dict.get("suspendido") == 1:
                        return None, (jsonify({"success": False, "error": "Acceso denegado: Cuenta de repartidor suspendida por el operador"}), 403)
                    return driver_dict, None
            return None, (jsonify({"success": False, "error": "Acceso denegado: X-Driver-Token inválido"}), 403)

# =========================================================
# RUTAS ESTÁTICAS Y PWA
# =========================================================
@app.route("/")
def index():
    try:
        ip = get_client_ip()
        ua = request.headers.get('User-Agent', '')[:255]
        ref = request.headers.get('Referer', '')[:255]
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO visitas (ip, user_agent, origen_url) VALUES (?, ?, ?)", (ip, ua, ref))
            conn.commit()
    except Exception:
        pass
    return send_from_directory(".", "index.html")

@app.route("/manifest.json")
def manifest():
    return send_from_directory(".", "manifest.json", mimetype="application/manifest+json")

@app.route("/sw.js")
def service_worker():
    return send_from_directory(".", "sw.js", mimetype="application/javascript")

def get_app_version():
    if os.getenv("APP_VERSION"):
        return os.getenv("APP_VERSION")
    if os.path.exists("version.txt"):
        try:
            with open("version.txt", "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    return content
        except Exception:
            pass
    try:
        import subprocess
        ver = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL).decode("utf-8").strip()
        if ver:
            return ver
    except Exception:
        pass
    return "1.0.0-mandados-r1"

@app.route("/api/version", methods=["GET"])
@app.route("/health", methods=["GET"])
def get_version():
    return jsonify({
        "app": "mandados-app",
        "version": get_app_version(),
        "status": "healthy"
    })

@app.route("/privacidad")
@app.route("/privacidad.html")
def privacy_page():
    return send_from_directory(".", "privacidad.html")

@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(".", filename)


# =========================================================
# RUTAS API: CONFIGURACIÓN Y SERVICIO
# =========================================================
@app.route("/api/config", methods=["GET"])
def get_config():
    ciudad = os.getenv("MANDADOS_CIUDAD", "Masaya")
    try:
        tarifa_min = float(os.getenv("MANDADOS_TARIFA_MIN", "20.0"))
    except ValueError:
        tarifa_min = 20.0
    try:
        tarifa_max = float(os.getenv("MANDADOS_TARIFA_MAX", "300.0"))
    except ValueError:
        tarifa_max = 300.0

    zonas_env = os.getenv("MANDADOS_ZONAS", "")
    if zonas_env:
        zonas = [z.strip() for z in zonas_env.split(",") if z.strip()]
    else:
        zonas = [
            f"Mercado Municipal de {ciudad}",
            f"Parque Central de {ciudad}",
            f"Malecón de {ciudad}",
            "Monimbó",
            "San Jerónimo",
            "Las 7 Esquinas"
        ]
    return jsonify({
        "ciudad": ciudad,
        "tarifa_min": tarifa_min,
        "tarifa_max": tarifa_max,
        "zonas": zonas
    })

# =========================================================
# RUTAS API: REPARTIDORES / CONDUCTORES
# =========================================================
@app.route("/api/conductores", methods=["GET"])
@app.route("/api/conductores/activos", methods=["GET"])
def get_conductores():
    lat = request.args.get("lat", type=float)
    lng = request.args.get("lng", type=float)
    seed_demo = os.getenv("MANDADOS_SEED_DEMO", "0") == "1"
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        if seed_demo:
            query = "SELECT id, nombre, unidad, lat, lng, is_online, updated_at FROM conductores WHERE is_online = 1 AND (suspendido IS NULL OR suspendido = 0)"
            cursor.execute(query)
        else:
            query = "SELECT id, nombre, unidad, lat, lng, is_online, updated_at FROM conductores WHERE is_online = 1 AND is_demo = 0 AND (suspendido IS NULL OR suspendido = 0)"
            cursor.execute(query)
            
        rows = cursor.fetchall()
        
    drivers = []
    for r in rows:
        d = dict(r)
        if lat is not None and lng is not None and d["lat"] is not None and d["lng"] is not None:
            d["distancia_km"] = calculate_distance(lat, lng, d["lat"], d["lng"])
        else:
            d["distancia_km"] = None
        drivers.append(d)
        
    if lat is not None and lng is not None:
        drivers.sort(key=lambda x: (x["distancia_km"] if x["distancia_km"] is not None else 999))
        
    return jsonify(drivers)

@app.route("/api/conductor/registro", methods=["POST"])
def registrar_conductor():
    client_ip = get_client_ip()
    if not registro_rate_limiter.is_allowed(client_ip):
        return jsonify({"success": False, "error": "Demasiadas solicitudes de registro. Espere un momento (HTTP 429)"}), 429

    data = request.get_json(silent=True) or {}
    nombre = str(data.get("nombre", "")).strip()[:100]
    cedula = str(data.get("cedula", "")).strip()[:30]
    telefono = str(data.get("telefono", "")).strip()[:30]
    placa = str(data.get("placa") or data.get("unidad", "")).strip()[:50]
    reglas = data.get("reglas_aceptadas") in (True, 1, "1", "true", "True")

    if not reglas:
        return jsonify({"success": False, "error": "Debe aceptar las Reglas del Encargo para registrarse"}), 400

    if len(nombre) < 3:
        return jsonify({"success": False, "error": "El nombre completo es requerido (mínimo 3 caracteres)"}), 400

    cedula_clean = re.sub(r'[\s\-]', '', cedula)
    if not (re.match(r'^[0-9]{3}-?[0-9]{6}-?[0-9]{4}[A-Za-z]$', cedula) or (len(cedula_clean) >= 10 and cedula_clean.isalnum())):
        return jsonify({"success": False, "error": "Número de cédula inválido. Formato esperado: 001-000000-0000A"}), 400

    tel_clean = re.sub(r'[\s\-\+]', '', telefono)
    if not (re.match(r'^(\+?505)?[2578]\d{7}$', telefono) or (len(tel_clean) >= 8 and tel_clean.isdigit())):
        return jsonify({"success": False, "error": "Número de teléfono/WhatsApp inválido. Ingrese 8 dígitos válidos"}), 400

    if len(placa) < 3:
        return jsonify({"success": False, "error": "Número de placa o datos del vehículo requeridos"}), 400

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM conductores WHERE telefono = ? OR (cedula IS NOT NULL AND cedula != '' AND cedula = ?)", (telefono, cedula))
        if cursor.fetchone():
            return jsonify({"success": False, "error": "Ya existe un repartidor registrado con este teléfono o cédula"}), 409

        driver_token = f"MD-DRV-{secrets.token_hex(12)}"
        is_launch_free = os.environ.get("PLAN_GRATIS_LAUNCH", "").strip() == "1"
        if is_launch_free:
            plan_nombre = "Lanzamiento (Gratis)"
            exp_date = (datetime.datetime.now() + datetime.timedelta(days=365)).strftime("%Y-%m-%d")
        else:
            plan_nombre = "Pionero (15 Días Gratis)"
            exp_date = (datetime.datetime.now() + datetime.timedelta(days=15)).strftime("%Y-%m-%d")
        unidad_desc = f"Moto · Placa {placa}"

        cursor.execute("""
            INSERT INTO conductores (nombre, cedula, telefono, unidad, placa, driver_token, suspendido, reglas_aceptadas, lat, lng, is_online, plan_activo, plan_nombre, plan_expira, is_demo)
            VALUES (?, ?, ?, ?, ?, ?, 0, 1, 12.1364, -86.2514, 1, 1, ?, ?, 0)
        """, (nombre, cedula, telefono, unidad_desc, placa, driver_token, plan_nombre, exp_date))
        conductor_id = cursor.lastrowid
        conn.commit()

    return jsonify({
        "success": True,
        "conductor_id": conductor_id,
        "nombre": nombre,
        "driver_token": driver_token,
        "mensaje": "¡Registro completado! Guarda este PIN/Token de acceso; se muestra UNA SOLA VEZ."
    }), 201

@app.route("/api/conductor/posicion", methods=["POST"])
def actualizar_posicion_conductor():
    data = request.get_json(silent=True) or {}
    raw_cid = data.get("conductor_id")
    conductor_id = None
    if raw_cid is not None:
        try:
            conductor_id = int(raw_cid)
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "ID de conductor inválido"}), 400
        
    driver, auth_err = get_authenticated_driver(conductor_id)
    if auth_err:
        return auth_err
    conductor_id = driver["id"]

    try:
        lat = float(data.get("lat"))
        lng = float(data.get("lng"))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Coordenadas numéricas requeridas"}), 400

    is_online = 1 if data.get("is_online", 1) in (1, True, "1") else 0
        
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE conductores 
            SET lat = ?, lng = ?, is_online = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        """, (lat, lng, is_online, conductor_id))
        conn.commit()

    return jsonify({"success": True, "mensaje": "Posición actualizada"})

# =========================================================
# RUTAS API: MANDADOS Y ASIGNACIÓN ATÓMICA
# =========================================================
@app.route("/api/viajes/crear", methods=["POST"])
@app.route("/api/viajes/solicitar", methods=["POST"])
def solicitar_viaje():
    client_ip = get_client_ip()
    if not viaje_rate_limiter.is_allowed(client_ip):
        return jsonify({"success": False, "error": "Demasiadas solicitudes. Límite de creación de mandados excedido por IP (HTTP 429)"}), 429

    data = request.get_json(silent=True) or {}
    pasajero = str(data.get("pasajero_nombre") or data.get("cliente") or "Cliente Express")[:100]
    cliente_telefono = str(data.get("cliente_telefono") or data.get("telefono") or data.get("whatsapp") or "")[:30]
    origen = str(data.get("origen", "Punto de Recogida"))[:150]
    destino = str(data.get("destino", "Punto de Entrega"))[:150]
    paquete = str(data.get("paquete_desc") or data.get("descripcion") or data.get("paquete") or "Mandado estándar")[:200]
    session_token = str(data.get("session_token") or os.urandom(16).hex())
    
    try:
        tarifa = float(data.get("tarifa", 35.0))
        lat_o = float(data.get("lat_origen", data.get("lat", 12.1364)))
        lng_o = float(data.get("lng_origen", data.get("lng", -86.2514)))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Parámetros inválidos"}), 400

    try:
        tarifa_min = float(os.getenv("MANDADOS_TARIFA_MIN", "20.0"))
    except ValueError:
        tarifa_min = 20.0
    try:
        tarifa_max = float(os.getenv("MANDADOS_TARIFA_MAX", "300.0"))
    except ValueError:
        tarifa_max = 300.0

    if tarifa < tarifa_min or tarifa > tarifa_max:
        return jsonify({
            "success": False, 
            "error": f"Tarifa fuera de rango. Debe estar entre C$ {tarifa_min:.0f} y C$ {tarifa_max:.0f}"
        }), 400

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO viajes (session_token, pasajero_nombre, cliente_telefono, origen, destino, paquete_desc, tarifa, lat_origen, lng_origen, estado)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'buscando')
        """, (session_token, pasajero, cliente_telefono, origen, destino, paquete, tarifa, lat_o, lng_o))
        viaje_id = cursor.lastrowid
        conn.commit()

    registrar_evento_bitacora(viaje_id, None, "buscando", actor="solicitante", detalles=f"Mandado solicitado por {pasajero}")

    return jsonify({
        "success": True, 
        "viaje_id": viaje_id,
        "session_token": session_token,
        "estado": "buscando",
        "mensaje": "Buscando repartidor cercano..."
    })

@app.route("/api/viajes/<int:viaje_id>/estado", methods=["GET"])
def get_estado_viaje(viaje_id):
    token = (
        request.headers.get("X-Session-Token")
        or request.args.get("token")
        or request.args.get("session_token")
        or ""
    ).strip()

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT v.id, v.session_token, v.estado, v.tarifa, v.origen, v.destino, v.paquete_desc, v.conductor_id,
                   c.id as cond_id, c.nombre as conductor_nombre, c.telefono as conductor_telefono, c.unidad as conductor_unidad
            FROM viajes v
            LEFT JOIN conductores c ON v.conductor_id = c.id
            WHERE v.id = ?
        """, (viaje_id,))
        row = cursor.fetchone()
        
    if not row:
        return jsonify({"success": False, "error": "Mandado no encontrado"}), 404

    reg_token = (row["session_token"] or "").strip()
    if not token or not reg_token or not hmac.compare_digest(token, reg_token):
        return jsonify({"success": False, "error": "UNAUTHORIZED: Token de sesión requerido o inválido para consultar estado del mandado"}), 403
    
    conductor_obj = None
    if row["conductor_id"]:
        conductor_obj = {
            "id": row["cond_id"],
            "nombre": row["conductor_nombre"],
            "telefono": row["conductor_telefono"],
            "unidad": row["conductor_unidad"]
        }
        
    res = {
        "id": row["id"],
        "estado": row["estado"],
        "tarifa": row["tarifa"],
        "origen": row["origen"],
        "destino": row["destino"],
        "paquete": row["paquete_desc"],
        "conductor_id": row["conductor_id"],
        "conductor_nombre": row["conductor_nombre"],
        "conductor_telefono": row["conductor_telefono"],
        "conductor_unidad": row["conductor_unidad"],
        "conductor": conductor_obj,
        "success": True
    }
    return jsonify(res)

@app.route("/api/viajes/<int:viaje_id>/cancelar", methods=["POST"])
@app.route("/api/cancelar", methods=["POST"])
def cancelar_viaje(viaje_id=None):
    data = request.get_json(silent=True) or {}
    if viaje_id is None:
        viaje_id = data.get("viaje_id") or data.get("id")

    if not viaje_id:
        return jsonify({"success": False, "error": "ID de mandado requerido"}), 400

    token = (
        request.headers.get("X-Session-Token")
        or (data.get("session_token") if isinstance(data, dict) else None)
        or (data.get("token") if isinstance(data, dict) else None)
        or request.args.get("session_token")
        or request.args.get("token")
        or ""
    ).strip()

    if not token:
        return jsonify({"success": False, "error": "Autenticación requerida: session_token ausente"}), 403

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT session_token, estado FROM viajes WHERE id = ?", (viaje_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Mandado no encontrado"}), 404

        reg_token = (row["session_token"] or "").strip()
        if not reg_token or not hmac.compare_digest(token, reg_token):
            return jsonify({"success": False, "error": "UNAUTHORIZED: Token de sesión no coincide con el emisor del mandado"}), 403

        prev_estado = row["estado"]
        cursor.execute("""
            UPDATE viajes 
            SET estado = 'cancelado', lat_origen = NULL, lng_origen = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND estado IN ('buscando', 'aceptado')
        """, (viaje_id,))
        conn.commit()

    registrar_evento_bitacora(viaje_id, prev_estado, "cancelado", actor="solicitante", detalles="Cancelado por emisor con session_token")
    return jsonify({"success": True, "mensaje": "Mandado cancelado exitosamente"})

@app.route("/api/conductor/viajes_pendientes", methods=["GET"])
@app.route("/api/conductor/viajes-pendientes", methods=["GET"])
def get_viajes_pendientes():
    conductor_id = request.args.get("conductor_id")
    driver, auth_err = get_authenticated_driver(conductor_id)
    if auth_err:
        return auth_err

    conductor_lat = float(request.args.get("lat", 12.1364))
    conductor_lng = float(request.args.get("lng", -86.2514))
    max_km = float(request.args.get("radio_km", 4.0))

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM viajes WHERE estado = 'buscando' ORDER BY id DESC LIMIT 10")
        rows = cursor.fetchall()
        
    carreras = []
    for r in rows:
        dist_km = calculate_distance(conductor_lat, conductor_lng, r["lat_origen"] or 12.1364, r["lng_origen"] or -86.2514)
        if dist_km <= max_km:
            carreras.append({
                "id": r["id"],
                "pasajero": r["pasajero_nombre"],
                "origen": r["origen"],
                "destino": r["destino"],
                "paquete": r["paquete_desc"],
                "tarifa": r["tarifa"],
                "distancia_km": dist_km,
                "created_at": r["created_at"]
            })
            
    if request.path == "/api/conductor/viajes-pendientes":
        return jsonify(carreras)
    return jsonify({"success": True, "viajes": carreras})

@app.route("/api/viajes/<int:viaje_id>/aceptar", methods=["POST"])
def aceptar_viaje(viaje_id):
    data = request.get_json(silent=True) or {}
    raw_cid = data.get("conductor_id")
    conductor_id = None
    if raw_cid is not None:
        try:
            conductor_id = int(raw_cid)
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "ID de repartidor inválido"}), 400

    driver, auth_err = get_authenticated_driver(conductor_id)
    if auth_err:
        return auth_err
    conductor_id = driver["id"]

    is_launch_free = os.environ.get("PLAN_GRATIS_LAUNCH", "").strip() == "1"
    if not is_launch_free:
        if driver.get("plan_activo") != 1:
            return jsonify({"success": False, "error": "Acceso denegado: El plan del repartidor está inactivo"}), 403

        plan_exp = driver.get("plan_expira")
        if plan_exp:
            try:
                exp_d = datetime.datetime.strptime(str(plan_exp)[:10], "%Y-%m-%d").date()
                if exp_d < datetime.date.today():
                    with get_db() as c_up:
                        c_up.cursor().execute("UPDATE conductores SET plan_activo = 0 WHERE id = ?", (conductor_id,))
                        c_up.commit()
                    return jsonify({"success": False, "error": "Acceso denegado: El plan del repartidor ha expirado"}), 403
            except Exception:
                pass
    
    with get_db() as conn:
        cursor = conn.cursor()
        # Asignación ATÓMICA en base de datos
        cursor.execute("""
            UPDATE viajes 
            SET estado = 'aceptado', conductor_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND estado = 'buscando'
        """, (conductor_id, viaje_id))
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({"success": False, "error": "El mandado ya fue tomado por otro repartidor"}), 409

        cursor.execute("SELECT id, nombre, telefono, unidad, placa FROM conductores WHERE id = ?", (conductor_id,))
        cond_row = cursor.fetchone()
        cond_data = dict(cond_row) if cond_row else {}

    registrar_evento_bitacora(viaje_id, "buscando", "aceptado", actor="repartidor", detalles=f"Aceptado por {cond_data.get('nombre', 'Repartidor')} (ID {conductor_id})")

    return jsonify({
        "success": True, 
        "mensaje": "¡Mandado asignado con éxito! Dirígete al punto de recogida.",
        "conductor": cond_data
    })

@app.route("/api/viajes/<int:viaje_id>/cambiar_estado", methods=["POST"])
def cambiar_estado_viaje(viaje_id):
    data = request.get_json(silent=True) or {}
    nuevo_estado = str(data.get("estado", "")).strip().lower()
    if nuevo_estado not in ("en_camino", "entregado", "cancelado"):
        return jsonify({"success": False, "error": "Estado inválido. Debe ser: en_camino, entregado, o cancelado"}), 400

    token_repartidor = request.headers.get("X-Driver-Token", "").strip()
    token_sesion = (request.headers.get("X-Session-Token") or str(data.get("session_token", ""))).strip()

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM viajes WHERE id = ?", (viaje_id,))
        v = cursor.fetchone()
        if not v:
            return jsonify({"success": False, "error": "Mandado no encontrado"}), 404

        actor = "desconocido"
        if token_repartidor:
            driver, auth_err = get_authenticated_driver(v["conductor_id"])
            if auth_err:
                return auth_err
            actor = f"repartidor:{driver['nombre']}"
        elif token_sesion and v["session_token"] and hmac.compare_digest(token_sesion, v["session_token"]):
            actor = "solicitante"
        else:
            return jsonify({"success": False, "error": "No autorizado para cambiar el estado de este mandado"}), 403

        estado_ant = v["estado"]
        cursor.execute("UPDATE viajes SET estado = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (nuevo_estado, viaje_id))
        conn.commit()

    registrar_evento_bitacora(viaje_id, estado_ant, nuevo_estado, actor=actor, detalles=f"Transición a {nuevo_estado}")
    return jsonify({"success": True, "estado": nuevo_estado, "mensaje": f"Estado actualizado a {nuevo_estado}"})

# =========================================================
# RUTAS API: RECARGAS BANPRO
# =========================================================
@app.route("/api/conductor/recarga", methods=["POST"])
def registrar_recarga():
    client_ip = get_client_ip()
    if not recarga_rate_limiter.is_allowed(client_ip):
        return jsonify({"success": False, "error": "Demasiadas solicitudes de recarga. Intente más tarde (HTTP 429)"}), 429

    data = request.get_json(silent=True) or {}
    raw_cid = data.get("conductor_id")
    conductor_id = None
    if raw_cid is not None:
        try:
            conductor_id = int(raw_cid)
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "Datos inválidos"}), 400

    driver, auth_err = get_authenticated_driver(conductor_id)
    if auth_err:
        return auth_err
    conductor_id = driver["id"]

    try:
        monto = float(data.get("monto", 50.0))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Datos inválidos"}), 400

    plan_nombre = str(data.get("plan_nombre", "Semanal (7 Días)"))[:50]
    referencia = str(data.get("referencia", ""))[:100]
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO recargas_banpro (conductor_id, plan_nombre, monto, referencia, estado)
            VALUES (?, ?, ?, ?, 'pendiente')
        """, (conductor_id, plan_nombre, monto, referencia))
        conn.commit()
        
    return jsonify({"success": True, "mensaje": "Comprobante registrado. En revisión."})

# =========================================================
# PANEL DE ADMINISTRACIÓN (MANDADOS_ADMIN_KEY)
# =========================================================
ADMIN_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Panel de Control · Mandados App 📦</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #090d16; color: #fff; padding: 20px; }
    .card { background: #131c2e; padding: 20px; border-radius: 12px; margin-bottom: 20px; border: 1px solid #1e2d4a; }
    h1, h2 { color: #0284c7; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #1e2d4a; font-size: 0.9rem; }
    th { color: #94a3b8; }
    .badge { padding: 4px 8px; border-radius: 6px; font-weight: 700; font-size: 0.75rem; display: inline-block; }
    .badge-success { background: rgba(16,185,129,0.2); color: #10b981; }
    .badge-warning { background: rgba(245,158,11,0.2); color: #f59e0b; }
    .badge-danger { background: rgba(244,63,94,0.2); color: #f43f5e; }
    .btn { display: inline-block; padding: 8px 16px; background: #0284c7; color: #fff; text-decoration: none; border-radius: 6px; font-weight: 600; margin-bottom: 15px; }
    .btn-sm { padding: 5px 10px; font-size: 0.75rem; border-radius: 6px; text-decoration: none; font-weight: 700; display: inline-block; }
    .btn-suspend { background: #f43f5e; color: #fff; }
    .btn-activate { background: #10b981; color: #fff; }
    .btn-dossier { background: #38bdf8; color: #090d16; }
  </style>
</head>
<body>
  <h1>📦 Mandados App · Panel de Control</h1>
  <a href="/" class="btn">📱 Abrir App en Vivo</a>
  <div class="card">
    <h2>Repartidores Registrados</h2>
    <table>
      <thead>
        <tr><th>ID</th><th>Nombre</th><th>Cédula</th><th>Teléfono</th><th>Placa/Unidad</th><th>Token (PIN)</th><th>Plan</th><th>Estado</th><th>Acción Operador</th></tr>
      </thead>
      <tbody>
        {% for c in conductores %}
        <tr>
          <td>{{ c.id }}</td>
          <td><strong>{{ c.nombre }}</strong></td>
          <td><code>{{ c.cedula or '—' }}</code></td>
          <td><a href="https://wa.me/{{ c.telefono }}" target="_blank" style="color: #38bdf8;">{{ c.telefono }}</a></td>
          <td>{{ c.placa or c.unidad }}</td>
          <td><code>{{ c.driver_token }}</code></td>
          <td><span class="badge badge-success">{{ c.plan_nombre }}</span></td>
          <td>
            {% if c.suspendido == 1 %}
              <span class="badge badge-danger">SUSPENDIDO ⛔</span>
            {% else %}
              {{ 'Online 🟢' if c.is_online else 'Offline ⚪' }}
            {% endif %}
          </td>
          <td>
            {% if c.suspendido == 1 %}
              <a href="/admin/conductor/{{ c.id }}/suspender?key={{ admin_key }}&redirect=admin" class="btn-sm btn-activate">Reactivar</a>
            {% else %}
              <a href="/admin/conductor/{{ c.id }}/suspender?key={{ admin_key }}&redirect=admin" class="btn-sm btn-suspend">SUSPENDER</a>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  <div class="card">
    <h2>Últimos Mandados Solicitados</h2>
    <table>
      <thead>
        <tr><th>ID</th><th>Cliente</th><th>WhatsApp Remitente</th><th>Recogida ➔ Entrega</th><th>Paquete</th><th>Tarifa</th><th>Estado</th><th>Expediente</th></tr>
      </thead>
      <tbody>
        {% for v in viajes %}
        <tr>
          <td>#{{ v.id }}</td>
          <td>{{ v.pasajero_nombre }}</td>
          <td>
            {% if v.cliente_telefono %}
              <a href="https://wa.me/{{ v.cliente_telefono }}" target="_blank" style="color: #38bdf8;">{{ v.cliente_telefono }}</a>
            {% else %}
              <span style="color: #64748b;">—</span>
            {% endif %}
          </td>
          <td>{{ v.origen }} ➔ {{ v.destino }}</td>
          <td>{{ v.paquete_desc or 'General' }}</td>
          <td>C$ {{ v.tarifa }}</td>
          <td><span class="badge badge-warning">{{ v.estado }}</span></td>
          <td>
            <a href="/admin/caso/{{ v.id }}?key={{ admin_key }}" class="btn-sm btn-dossier">📁 Ver Caso</a>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</body>
</html>
"""

CASE_DOSSIER_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Expediente de Caso #{{ viaje.id }} · Mandados App 📦</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #090d16; color: #f1f5f9; padding: 20px; line-height: 1.5; }
    .container { max-width: 850px; margin: 0 auto; }
    .card { background: #131c2e; padding: 20px; border-radius: 14px; margin-bottom: 18px; border: 1px solid #1e2d4a; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
    h1 { color: #38bdf8; font-size: 1.4rem; margin: 0 0 5px 0; }
    h2 { color: #0284c7; font-size: 1.05rem; border-bottom: 1px solid #1e2d4a; padding-bottom: 8px; margin-top: 0; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-weight: 700; font-size: 0.75rem; text-transform: uppercase; }
    .badge-buscando { background: rgba(56,189,248,0.2); color: #38bdf8; border: 1px solid #38bdf8; }
    .badge-aceptado { background: rgba(245,158,11,0.2); color: #f59e0b; border: 1px solid #f59e0b; }
    .badge-en_camino { background: rgba(168,85,247,0.2); color: #a855f7; border: 1px solid #a855f7; }
    .badge-entregado { background: rgba(16,185,129,0.2); color: #10b981; border: 1px solid #10b981; }
    .badge-cancelado { background: rgba(244,63,94,0.2); color: #f43f5e; border: 1px solid #f43f5e; }
    .badge-expirado { background: rgba(148,163,184,0.2); color: #94a3b8; border: 1px solid #94a3b8; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-bottom: 8px; }
    .field-label { font-size: 0.72rem; text-transform: uppercase; color: #94a3b8; font-weight: 700; display: block; margin-bottom: 2px; }
    .field-value { font-size: 0.95rem; font-weight: 600; color: #fff; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #1e2d4a; font-size: 0.85rem; }
    th { color: #94a3b8; background: #0f172a; }
    .actions { display: flex; gap: 10px; margin-bottom: 15px; }
    .btn { display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px; border-radius: 8px; font-weight: 700; font-size: 0.85rem; text-decoration: none; cursor: pointer; border: none; }
    .btn-secondary { background: #1e293b; color: #94a3b8; border: 1px solid #334155; }
    .btn-copy { background: #10b981; color: #020617; }
    .dossier-box { background: #0b1120; border: 1px dashed #334155; padding: 14px; border-radius: 10px; font-family: monospace; font-size: 0.8rem; color: #cbd5e1; white-space: pre-wrap; margin-top: 15px; }
  </style>
</head>
<body>
<div class="container">
  <div class="actions">
    <a href="/admin?key={{ admin_key }}" class="btn btn-secondary">← Volver al Panel</a>
    <button onclick="copiarExpediente()" class="btn btn-copy">📋 Copiar Expediente Completo</button>
  </div>

  <div class="card">
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <div>
        <h1>📦 Expediente Oficial de Mandado #{{ viaje.id }}</h1>
        <p style="margin: 0; color: #94a3b8; font-size: 0.85rem;">Fecha y hora de solicitud: {{ viaje.created_at }}</p>
      </div>
      <span class="badge badge-{{ viaje.estado }}">{{ viaje.estado }}</span>
    </div>
  </div>

  <div class="card">
    <h2>1. Solicitante y Condiciones del Mandado</h2>
    <div class="grid">
      <div>
        <span class="field-label">Nombre del Solicitante</span>
        <span class="field-value">{{ viaje.pasajero_nombre or 'No especificado' }}</span>
      </div>
      <div>
        <span class="field-label">WhatsApp Remitente</span>
        <span class="field-value">
          {% if viaje.cliente_telefono %}
            <a href="https://wa.me/{{ viaje.cliente_telefono }}" target="_blank" style="color: #38bdf8;">{{ viaje.cliente_telefono }}</a>
          {% else %}
            <span style="color: #64748b;">No registrado</span>
          {% endif %}
        </span>
      </div>
      <div>
        <span class="field-label">Tarifa Pactada</span>
        <span class="field-value" style="color: #10b981;">C$ {{ viaje.tarifa }}</span>
      </div>
    </div>
    <div class="grid" style="margin-top: 10px;">
      <div>
        <span class="field-label">Punto de Recogida (Origen)</span>
        <span class="field-value">{{ viaje.origen }}</span>
      </div>
      <div>
        <span class="field-label">Punto de Entrega (Destino)</span>
        <span class="field-value">{{ viaje.destino }}</span>
      </div>
      <div>
        <span class="field-label">Descripción del Paquete</span>
        <span class="field-value">{{ viaje.paquete_desc or 'Mandado general' }}</span>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>2. Repartidor Asignado (Conductor)</h2>
    {% if conductor %}
    <div class="grid">
      <div>
        <span class="field-label">Nombre Completo</span>
        <span class="field-value">{{ conductor.nombre }}</span>
      </div>
      <div>
        <span class="field-label">N° de Cédula de Identidad</span>
        <span class="field-value" style="color: #facc15;">{{ conductor.cedula or 'No registrada' }}</span>
      </div>
      <div>
        <span class="field-label">WhatsApp / Teléfono</span>
        <span class="field-value">
          <a href="https://wa.me/{{ conductor.telefono }}" target="_blank" style="color: #38bdf8;">{{ conductor.telefono }}</a>
        </span>
      </div>
      <div>
        <span class="field-label">Placa / Vehículo</span>
        <span class="field-value">{{ conductor.placa or conductor.unidad }}</span>
      </div>
      <div>
        <span class="field-label">Estado de Cuenta</span>
        <span class="field-value">
          {% if conductor.suspendido == 1 %}
            <span style="color: #f43f5e; font-weight: 800;">⛔ SUSPENDIDO</span>
          {% else %}
            <span style="color: #10b981; font-weight: 800;">ACTIVO</span>
          {% endif %}
        </span>
      </div>
    </div>
    {% else %}
    <p style="color: #94a3b8; font-style: italic; margin: 5px 0;">No se asignó ningún repartidor a este mandado.</p>
    {% endif %}
  </div>

  <div class="card">
    <h2>3. Bitácora de Auditoría ("Caja Negra")</h2>
    <p style="font-size: 0.8rem; color: #94a3b8; margin: 0 0 10px 0;">Registro inmutable cronológico de transiciones de estado para auditoría y resolución de disputas.</p>
    <table>
      <thead>
        <tr>
          <th>Fecha / Hora</th>
          <th>Estado Anterior</th>
          <th>Estado Nuevo</th>
          <th>Actor Responsable</th>
          <th>Detalles / Observaciones</th>
        </tr>
      </thead>
      <tbody>
        {% for b in bitacora %}
        <tr>
          <td>{{ b.created_at }}</td>
          <td><code>{{ b.estado_anterior or '—' }}</code></td>
          <td><strong style="color: #38bdf8;">{{ b.estado_nuevo }}</strong></td>
          <td>{{ b.actor }}</td>
          <td>{{ b.detalles }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>4. Resumen Textual para Expediente / Evidencia</h2>
    <div id="rawDossierText" class="dossier-box">=== EXPEDIENTE OFICIAL MANDADOS APP ===
ID Mandado: #{{ viaje.id }}
Fecha Solicitud: {{ viaje.created_at }}
Estado Actual: {{ viaje.estado }}
Tarifa: C$ {{ viaje.tarifa }}
Origen: {{ viaje.origen }}
Destino: {{ viaje.destino }}
Paquete: {{ viaje.paquete_desc }}
Remitente: {{ viaje.pasajero_nombre }} (Tel: {{ viaje.cliente_telefono or 'N/A' }})
--- REPARTIDOR ASIGNADO ---
Nombre: {{ conductor.nombre if conductor else 'N/A' }}
Cédula: {{ conductor.cedula if conductor else 'N/A' }}
Teléfono: {{ conductor.telefono if conductor else 'N/A' }}
Placa/Unidad: {{ (conductor.placa or conductor.unidad) if conductor else 'N/A' }}
--- BITÁCORA DE ESTADOS ---
{% for b in bitacora %}[{{ b.created_at }}] {{ b.estado_anterior or 'INICIO' }} -> {{ b.estado_nuevo }} | Actor: {{ b.actor }} | {{ b.detalles }}
{% endfor %}=======================================</div>
  </div>
</div>

<script>
function copiarExpediente() {
  const text = document.getElementById('rawDossierText').innerText;
  navigator.clipboard.writeText(text).then(() => {
    alert('¡Expediente copiado al portapapeles!');
  }).catch(() => {
    alert('Expediente disponible en el recuadro para copiar.');
  });
}
</script>
</body>
</html>
"""

@app.route("/admin")
def admin_panel():
    admin_key = os.getenv("MANDADOS_ADMIN_KEY", "").strip()
    provided_key = (
        request.args.get("key")
        or request.headers.get("X-Admin-Key")
        or request.headers.get("Authorization", "").replace("Bearer ", "")
    ).strip()

    if not admin_key or not provided_key or not hmac.compare_digest(provided_key, admin_key):
        return jsonify({"success": False, "error": "Acceso denegado: Llave de administración requerida o inválida"}), 403

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM conductores ORDER BY id DESC")
        conductores = [dict(r) for r in cursor.fetchall()]
        cursor.execute("SELECT * FROM viajes ORDER BY id DESC LIMIT 20")
        viajes = [dict(r) for r in cursor.fetchall()]
    return render_template_string(ADMIN_HTML, conductores=conductores, viajes=viajes, admin_key=provided_key)

@app.route("/admin/conductor/<int:conductor_id>/suspender", methods=["GET", "POST"])
def suspender_conductor(conductor_id):
    admin_key = os.getenv("MANDADOS_ADMIN_KEY", "").strip()
    provided_key = (
        request.args.get("key")
        or request.headers.get("X-Admin-Key")
        or request.headers.get("Authorization", "").replace("Bearer ", "")
    ).strip()

    if not admin_key or not provided_key or not hmac.compare_digest(provided_key, admin_key):
        return jsonify({"success": False, "error": "Acceso denegado: Llave de administración requerida o inválida"}), 403

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, nombre, suspendido FROM conductores WHERE id = ?", (conductor_id,))
        cond = cursor.fetchone()
        if not cond:
            return jsonify({"success": False, "error": "Repartidor no encontrado"}), 404

        nuevo_estado = 0 if cond["suspendido"] == 1 else 1
        nuevo_online = 0 if nuevo_estado == 1 else 1
        cursor.execute("UPDATE conductores SET suspendido = ?, is_online = ? WHERE id = ?", (nuevo_estado, nuevo_online, conductor_id))
        conn.commit()

    if request.args.get("redirect") == "admin":
        return redirect(f"/admin?key={provided_key}")

    return jsonify({
        "success": True,
        "conductor_id": conductor_id,
        "suspendido": nuevo_estado,
        "mensaje": f"Repartidor {cond['nombre']} {'SUSPENDIDO' if nuevo_estado == 1 else 'REACTIVADO'} con éxito"
    })

@app.route("/admin/caso/<int:viaje_id>", methods=["GET"])
def admin_caso(viaje_id):
    admin_key = os.getenv("MANDADOS_ADMIN_KEY", "").strip()
    provided_key = (
        request.args.get("key")
        or request.headers.get("X-Admin-Key")
        or request.headers.get("Authorization", "").replace("Bearer ", "")
    ).strip()

    if not admin_key or not provided_key or not hmac.compare_digest(provided_key, admin_key):
        return jsonify({"success": False, "error": "Acceso denegado: Llave de administración requerida o inválida"}), 403

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM viajes WHERE id = ?", (viaje_id,))
        viaje_row = cursor.fetchone()
        if not viaje_row:
            return jsonify({"success": False, "error": "Mandado no encontrado"}), 404

        viaje = dict(viaje_row)

        conductor = None
        if viaje.get("conductor_id"):
            cursor.execute("SELECT id, nombre, cedula, telefono, unidad, placa, suspendido FROM conductores WHERE id = ?", (viaje["conductor_id"],))
            cond_row = cursor.fetchone()
            if cond_row:
                conductor = dict(cond_row)

        cursor.execute("SELECT * FROM bitacora_estados WHERE viaje_id = ? ORDER BY id ASC", (viaje_id,))
        bitacora = [dict(r) for r in cursor.fetchall()]

    if request.is_json or request.args.get("format") == "json" or request.headers.get("Accept") == "application/json":
        return jsonify({
            "success": True,
            "viaje": viaje,
            "conductor": conductor,
            "bitacora": bitacora
        })

    return render_template_string(CASE_DOSSIER_HTML, viaje=viaje, conductor=conductor, bitacora=bitacora, admin_key=provided_key)

if __name__ == "__main__":
    host_bind = os.getenv("HOST", "0.0.0.0")
    if os.path.exists("/.dockerenv") or os.getenv("CONTAINER"):
        host_bind = "0.0.0.0"
    port_bind = int(os.getenv("PORT", "5058"))
    print("==================================================")
    print(f"[OK] MANDADOS ENGINE ACTIVO en http://{host_bind}:{port_bind}")
    print("   Tiempo Real (SSE) y API de Envíos y Mandados Listos")
    print("==================================================")
    app.run(host=host_bind, port=port_bind, debug=False, threaded=True)
