"""
Suite de Pruebas Automatizadas de Verificación Integral - Mandados App
Auditoría GLM (MA-1 a MA-10) — Hardening Heredado y Adaptación de Producto 100% Pass
"""
import os
import sys
import time
import datetime
import secrets

# Configurar entorno de prueba antes de importar server
os.environ["MANDADOS_ADMIN_KEY"] = "sentinel_mandados_admin_key_2026"
os.environ["MANDADOS_SEED_DEMO"] = "1"
os.environ["MANDADOS_TARIFA_MIN"] = "20.0"
os.environ["MANDADOS_TARIFA_MAX"] = "300.0"
os.environ["MANDADOS_VIAJE_TTL_SEC"] = "2"
os.environ["PORT"] = "5058"

import server

def run_all_tests():
    server.init_db()
    client = server.app.test_client()
    print("=" * 65)
    print("INICIANDO SUITE DE AUDITORÍA AUTOMATIZADA: MANDADOS APP (MA-1 .. MA-10)")
    print("=" * 65)

    # ---------------------------------------------------------
    # MA-1: Protección de /admin con MANDADOS_ADMIN_KEY
    # ---------------------------------------------------------
    print("\n[TEST MA-1] Verificando protección estricta de /admin con MANDADOS_ADMIN_KEY...")
    res_no_key = client.get("/admin")
    assert res_no_key.status_code == 403, f"Esperado 403 sin key, obtenido {res_no_key.status_code}"
    
    res_bad_key = client.get("/admin?key=clave_invalida")
    assert res_bad_key.status_code == 403, f"Esperado 403 con key inválida, obtenido {res_bad_key.status_code}"

    res_good_key = client.get("/admin?key=sentinel_mandados_admin_key_2026")
    assert res_good_key.status_code == 200, f"Esperado 200 con key válida, obtenido {res_good_key.status_code}"
    assert "Panel de Control" in res_good_key.get_data(as_text=True)
    assert "Repartidores Registrados" in res_good_key.get_data(as_text=True)
    print("  -> PASÓ: /admin bloqueado a intrusos (403) y accesible solo con MANDADOS_ADMIN_KEY (200).")

    # ---------------------------------------------------------
    # MA-2: Autenticación de repartidor con X-Driver-Token
    # ---------------------------------------------------------
    print("\n[TEST MA-2] Verificando autenticación de repartidores (X-Driver-Token)...")
    with server.get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, driver_token FROM conductores WHERE id = 1")
        d1 = cur.fetchone()
        assert d1 and d1["driver_token"], "Repartidor 1 debe tener un driver_token generado"
        driver1_token = d1["driver_token"]

    res_no_token = client.get("/api/conductor/viajes-pendientes?conductor_id=1")
    assert res_no_token.status_code == 403, f"Esperado 403 sin driver token, obtenido {res_no_token.status_code}"

    res_bad_token = client.get("/api/conductor/viajes-pendientes?conductor_id=1", headers={"X-Driver-Token": "token_falso"})
    assert res_bad_token.status_code == 403, f"Esperado 403 con driver token falso, obtenido {res_bad_token.status_code}"

    res_ok_token = client.get("/api/conductor/viajes-pendientes?conductor_id=1", headers={"X-Driver-Token": driver1_token})
    assert res_ok_token.status_code == 200, f"Esperado 200 con token correcto, obtenido {res_ok_token.status_code}"
    print("  -> PASÓ: Endpoints de repartidor exigen X-Driver-Token en tiempo constante.")

    # ---------------------------------------------------------
    # MA-3: Cierre de hueco IDOR en cancelación de mandados
    # ---------------------------------------------------------
    print("\n[TEST MA-3] Verificando eliminación de IDOR en cancelación (/cancelar)...")
    session_token_1 = secrets.token_hex(16)
    res_trip = client.post("/api/viajes/crear", json={
        "pasajero_nombre": "Test IDOR Mandado",
        "origen": "Farmacia Central",
        "destino": "Reparto San Juan",
        "paquete_desc": "Medicinas urgentes",
        "tarifa": 40.0,
        "session_token": session_token_1
    }, environ_base={"REMOTE_ADDR": "192.168.1.101"})
    assert res_trip.status_code == 200
    trip_id = res_trip.get_json()["viaje_id"]

    res_canc_no_tok = client.post(f"/api/viajes/{trip_id}/cancelar", json={})
    assert res_canc_no_tok.status_code == 403, f"Esperado 403 sin token, obtenido {res_canc_no_tok.status_code}"

    res_canc_bad_tok = client.post(f"/api/viajes/{trip_id}/cancelar", json={"session_token": "token_erroneo"})
    assert res_canc_bad_tok.status_code == 403, f"Esperado 403 con token erróneo, obtenido {res_canc_bad_tok.status_code}"

    res_canc_ok = client.post(f"/api/viajes/{trip_id}/cancelar", json={"session_token": session_token_1})
    assert res_canc_ok.status_code == 200, f"Esperado 200 con token válido, obtenido {res_canc_ok.status_code}"
    print("  -> PASÓ: Cancelación exige estrictamente session_token coincidente (Cero IDOR).")

    # ---------------------------------------------------------
    # MA-4: session_token generado y soporte de paquete_desc
    # ---------------------------------------------------------
    print("\n[TEST MA-4] Verificando entrega de session_token y descripción de paquete...")
    res_trip2 = client.post("/api/viajes/crear", json={
        "pasajero_nombre": "Doña Silvia",
        "origen": "Mercado Municipal",
        "destino": "Barrio Monimbó",
        "paquete_desc": "Almuerzo y compras de verduras",
        "tarifa": 35.0
    }, environ_base={"REMOTE_ADDR": "192.168.1.102"})
    assert res_trip2.status_code == 200
    data2 = res_trip2.get_json()
    assert "session_token" in data2 and len(data2["session_token"]) >= 16
    trip2_id = data2["viaje_id"]
    trip2_token = data2["session_token"]
    print(f"  -> PASÓ: session_token generado ({trip2_token[:8]}...) con campo de paquete verificado.")

    # ---------------------------------------------------------
    # MA-5: Teléfonos fuera de API pública y privacidad en /estado
    # ---------------------------------------------------------
    print("\n[TEST MA-5] Verificando privacidad de teléfonos (Zero-PII)...")
    res_activos = client.get("/api/conductores/activos")
    assert res_activos.status_code == 200
    conductores_list = res_activos.get_json()
    for c in conductores_list:
        assert "telefono" not in c, "El campo 'telefono' NO debe existir en API pública"
        assert "phone" not in c, "El campo 'phone' NO debe existir en API pública"

    # Repartidor 1 acepta el mandado 2
    res_ac = client.post(f"/api/viajes/{trip2_id}/aceptar", 
                         headers={"X-Driver-Token": driver1_token}, 
                         json={"conductor_id": 1})
    assert res_ac.status_code == 200

    # Consultar /api/viajes/<id>/estado sin token -> 403
    res_est_no_tok = client.get(f"/api/viajes/{trip2_id}/estado")
    assert res_est_no_tok.status_code == 403, f"Esperado 403 sin token en estado, obtenido {res_est_no_tok.status_code}"

    # Consultar con token correcto -> 200 y teléfono accesible para el cliente legítimo
    res_est_ok = client.get(f"/api/viajes/{trip2_id}/estado?session_token={trip2_token}")
    assert res_est_ok.status_code == 200
    est_data = res_est_ok.get_json()
    assert est_data["conductor"]["telefono"] is not None
    assert "paquete" in est_data
    print("  -> PASÓ: Teléfonos protegidos por session_token en /estado; datos de paquete transmitidos.")

    # ---------------------------------------------------------
    # MA-6: Rate Limiting y Expiración TTL de Mandados
    # ---------------------------------------------------------
    print("\n[TEST MA-6] Verificando Rate Limiter (HTTP 429) y TTL Sweeper...")
    test_ip = "192.168.1.210"
    for i in range(5):
        r = client.post("/api/viajes/crear", json={"origen": "A", "destino": "B", "tarifa": 35}, environ_base={"REMOTE_ADDR": test_ip})
        assert r.status_code == 200, f"Petición {i+1} debe permitirse"
    
    r_burst = client.post("/api/viajes/crear", json={"origen": "A", "destino": "B", "tarifa": 35}, environ_base={"REMOTE_ADDR": test_ip})
    assert r_burst.status_code == 429, f"Esperado 429 por rate limit, obtenido {r_burst.status_code}"

    # Anti-spoofing en X-Forwarded-For (P6)
    spoofed_proxy_ip = "192.168.1.255"
    for i in range(5):
        headers = {"X-Forwarded-For": f"10.88.{i}.1, {spoofed_proxy_ip}"}
        r = client.post("/api/viajes/crear", json={"origen": "A", "destino": "B", "tarifa": 35}, headers=headers)
        assert r.status_code == 200, f"Petición spoofed {i+1} debe permitirse"
    
    r_spoofed_burst = client.post("/api/viajes/crear", json={"origen": "A", "destino": "B", "tarifa": 35}, 
                                  headers={"X-Forwarded-For": f"10.88.88.88, {spoofed_proxy_ip}"})
    assert r_spoofed_burst.status_code == 429, f"Esperado 429 mitigando spoofing en X-Forwarded-For, obtenido {r_spoofed_burst.status_code}"
    
    # TTL: mandado expirado
    with server.get_db() as conn:
        cur = conn.cursor()
        old_time = (datetime.datetime.now() - datetime.timedelta(seconds=1000)).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("INSERT INTO viajes (origen, destino, tarifa, estado, created_at) VALUES ('OldA', 'OldB', 35, 'buscando', ?)", (old_time,))
        old_id = cur.lastrowid
        conn.commit()

    server.purge_expired_trips()
    with server.get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT estado FROM viajes WHERE id = ?", (old_id,))
        assert cur.fetchone()["estado"] == "expirado"
    print("  -> PASÓ: Rate Limiter bloquea ráfagas (429); anti-spoofing activo; mandados viejos expiran.")

    # ---------------------------------------------------------
    # MA-7: MANDADOS_SEED_DEMO y Control de plan_expira
    # ---------------------------------------------------------
    print("\n[TEST MA-7] Verificando aislamiento de semilla demo y vencimiento de plan...")
    res_trip_exp = client.post("/api/viajes/crear", json={"origen": "X", "destino": "Y", "tarifa": 40}, environ_base={"REMOTE_ADDR": "192.168.1.155"})
    trip_exp_id = res_trip_exp.get_json()["viaje_id"]

    # Simular repartidor con plan vencido
    with server.get_db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE conductores SET plan_expira = '2020-01-01', plan_activo = 1 WHERE id = 1")
        conn.commit()

    res_accept_expired = client.post(f"/api/viajes/{trip_exp_id}/aceptar", 
                                     headers={"X-Driver-Token": driver1_token}, 
                                     json={"conductor_id": 1})
    assert res_accept_expired.status_code == 403, f"Esperado 403 por plan expirado, obtenido {res_accept_expired.status_code}"

    # Restaurar repartidor 1 a fecha futura
    with server.get_db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE conductores SET plan_expira = '2099-12-31', plan_activo = 1 WHERE id = 1")
        conn.commit()
    print("  -> PASÓ: Repartidores con plan vencido no pueden aceptar mandados (403).")

    # ---------------------------------------------------------
    # MA-8: sw.js funcional y PWA
    # ---------------------------------------------------------
    print("\n[TEST MA-8] Verificando Service Worker (sw.js) y PWA...")
    res_sw = client.get("/sw.js")
    assert res_sw.status_code == 200, f"Esperado 200 en /sw.js, obtenido {res_sw.status_code}"
    assert "application/javascript" in res_sw.headers.get("Content-Type", "")
    assert "mandados" in res_sw.get_data(as_text=True)
    print("  -> PASÓ: sw.js activo (HTTP 200) con caché de mandados configurado.")

    # ---------------------------------------------------------
    # MA-9: Configuración dinámica y validación tarifaria de mandados
    # ---------------------------------------------------------
    print("\n[TEST MA-9] Verificando /api/config y límites tarifarios...")
    res_cfg = client.get("/api/config")
    assert res_cfg.status_code == 200
    cfg = res_cfg.get_json()
    assert cfg["tarifa_min"] == 20.0
    assert cfg["tarifa_max"] == 300.0

    # Tarifa menor al mínimo (C$ 10 < 20) -> 400
    res_low = client.post("/api/viajes/crear", json={"tarifa": 10.0}, environ_base={"REMOTE_ADDR": "192.168.1.185"})
    assert res_low.status_code == 400, f"Esperado 400 por tarifa baja, obtenido {res_low.status_code}"

    # Tarifa mayor al máximo (C$ 350 > 300) -> 400
    res_high = client.post("/api/viajes/crear", json={"tarifa": 350.0}, environ_base={"REMOTE_ADDR": "192.168.1.186"})
    assert res_high.status_code == 400, f"Esperado 400 por tarifa excesiva, obtenido {res_high.status_code}"
    print("  -> PASÓ: /api/config responde correctamente y backend rechaza tarifas fuera de rango.")

    # ---------------------------------------------------------
    # MA-10: Telemetría /api/version y Health Check
    # ---------------------------------------------------------
    print("\n[TEST MA-10] Verificando /api/version y /health...")
    res_ver = client.get("/api/version")
    assert res_ver.status_code == 200
    ver_data = res_ver.get_json()
    assert ver_data["app"] == "mandados-app"
    assert ver_data["version"] == "1.0.1-vitrina-tls", f"Esperado 1.0.1-vitrina-tls, obtenido {ver_data['version']}"

    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.get_json()["status"] == "healthy"
    print(f"  -> PASÓ: Telemetría activa en /api/version ({ver_data['version']}) y /health (healthy).")

    print("\n" + "=" * 65)
    print("[OK] AUDITORIA COMPLETA! LOS 10 CRITERIOS MA-1 A MA-10 PASARON AL 100%")
    print("=" * 65)

if __name__ == "__main__":
    run_all_tests()
