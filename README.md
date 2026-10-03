# Mandados App 📦

Plataforma comunitaria Progressive Web App (PWA) de despacho y coordinación ágil para envíos, compras locales y mandados express atendidos por mototaxistas y repartidores independientes.

Servicio desacoplado e independiente de **Caponera App** (transporte exclusivo de pasajeros), con base de datos propia (`mandados.db`), motor aislado en el puerto **`5058`**, y llave de administración dedicada (`MANDADOS_ADMIN_KEY`).

---

## 1. Arquitectura del Contenedor Docker

La aplicación está dockerizada para despliegues reproducibles, autónomos y con aislamiento perimetral estricto:

- **Imagen Base:** `python:3.11-slim`
- **Puerto Interno y Loopback:** `5058` (mapeado estrictamente como `127.0.0.1:5058:5058` en el host).
- **Asignación de Puerto:** Seleccionado el puerto `5058` dado que el puerto sugerido `5057` se encuentra asignado al servicio `defi-ai-circuit-breaker`, preservando la regla de no colisión.
- **Aislamiento de Red (Layer 1 Perimeter):** Siguiendo las directrices de Sentinel Fleet, el contenedor se amarra exclusivamente a loopback local (`127.0.0.1`), impidiendo exposición directa a internet. El tráfico público ingresa mediante el reverse proxy seguro de Nginx.

### Arranque del Contenedor

Para construir y levantar el contenedor en segundo plano:

```bash
# Construir y levantar
docker compose up -d --build

# Verificar estado
docker compose ps

# Ver registros en tiempo real
docker compose logs -f mandados-app
```

---

## 2. Variables de Entorno y Configuración (.env)

El servicio lee sus parámetros del entorno operativo bajo regla estricta de higiene:

> **REGLA DE HIGIENE:** Cero secretos, tokens o credenciales en el repositorio de Git ni en las imágenes de Docker. Las variables sensibles residen exclusivamente en `/root/mandados_app/.env` en el servidor VPS con permisos restrictivos `chmod 600`.

### Variables Soportadas

| Variable | Tipo | Valor por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `MANDADOS_ADMIN_KEY` | String | *(Requerida en prod)* | Llave secreta obligatoria para acceso al panel `/admin`. |
| `MANDADOS_SEED_DEMO` | Int (0/1) | `0` | Modo semilla demo (`1` genera repartidores de prueba; `0` producción). |
| `MANDADOS_VIAJE_TTL_SEC`| Int | `900` | Tiempo de vida de un encargo buscando antes de expirar (15 min). |
| `MANDADOS_CIUDAD` | String | `Masaya` | Ciudad operativa de referencia. |
| `MANDADOS_TARIFA_MIN` | Float | `20.0` | Tarifa mínima permitida (C$). |
| `MANDADOS_TARIFA_MAX` | Float | `300.0` | Tarifa máxima permitida (C$). |
| `HOST` | String | `127.0.0.1` | Dirección de enlace local. |
| `PORT` | Int | `5058` | Puerto TCP de escucha del servidor. |

---

## 3. Persistencia de Datos y Base de Datos

### SQLite en Modo WAL (`mandados.db`)
Los datos transaccionales residen de forma independiente en `mandados.db` (sin interactuar con `caponera.db`), con directivas de alta concurrencia activas:
- `PRAGMA journal_mode=WAL;`
- `PRAGMA foreign_keys=ON;`
- `PRAGMA busy_timeout=5000;`

### Esquema de Tablas
1. **`conductores`**: Registro de repartidores/mototaxis, coordenadas, estado online y planes activos.
2. **`viajes`**: Solicitudes de mandados con punto de recogida, punto de entrega, descripción del paquete (`paquete_desc`), tarifa acordada, estado (`buscando`, `aceptado`, `cancelado`, `expirado`), y `session_token` criptográfico.
3. **`recargas_banpro`**: Registro de comprobantes de pago de repartidores.
4. **`visitas`**: Registro analítico interno de IPs anonimizadas y user agents.

---

## 4. Hardening y Seguridad Heredada (Ronda 1 + Ronda 2)

Mandados App hereda el 100% de los controles auditados y verificados:
1. **Control Anti-IDOR con `session_token`:** Consulta de estado y cancelación de mandados exigen el token emitido exclusivamente al cliente que originó el pedido.
2. **Mitigación Anti-Spoofing en Rate Limiting (P6):** Detección de IP mediante cabecera confiable `X-Real-IP` o último hop verificado en `X-Forwarded-For`, evitando falsificación de direcciones IP. Límite estricto de 5 solicitudes/minuto (HTTP 429).
3. **Autenticación en Tiempo Constante:** Verificación de `X-Driver-Token` y `MANDADOS_ADMIN_KEY` mediante `hmac.compare_digest`.
4. **Asignación Atómica en BD:** Cláusula `UPDATE viajes SET estado='aceptado', conductor_id=? WHERE id=? AND estado='buscando'` previniendo colisiones concurrentes entre repartidores.
5. **Privacidad Estricta (Zero-PII):** Teléfonos y datos personales removidos de endpoints públicos (`/api/conductores/activos` y `/api/viajes/disponibles`).
6. **Transparencia en Términos y Privacidad:** Declaración honesta de servidores en Houston, Texas, EE.UU., terceros técnicos necesarios (Carto, Leaflet, Tailwind, Cloudflare), retención sujeta a solicitud por WhatsApp, enlace oficial a `asamblea.gob.ni`, y aviso técnico transparente sobre conexión HTTP.

---

## 5. Control de Despliegue y Pruebas

- **Suite de Pruebas Automatizadas:** `python test_mandados.py` (10/10 criterios verificados).
- **Script de Despliegue al VPS:** `DESPLEGAR_MANDADOS_VPS.bat` (sincronización vía SCP + Docker compose rebuild en puerto 5058).
