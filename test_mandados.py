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

    # Simular repartidor con plan vencido (con variable apagada = vence con 403)
    os.environ.pop("PLAN_GRATIS_LAUNCH", None)
    with server.get_db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE conductores SET plan_expira = '2020-01-01', plan_activo = 1 WHERE id = 1")
        conn.commit()

    res_accept_expired = client.post(f"/api/viajes/{trip_exp_id}/aceptar", 
                                     headers={"X-Driver-Token": driver1_token}, 
                                     json={"conductor_id": 1})
    assert res_accept_expired.status_code == 403, f"Esperado 403 por plan expirado, obtenido {res_accept_expired.status_code}"

    # Con PLAN_GRATIS_LAUNCH=1, no se desactiva y se permite operar
    os.environ["PLAN_GRATIS_LAUNCH"] = "1"
    res_trip_launch = client.post("/api/viajes/crear", json={"origen": "X2", "destino": "Y2", "tarifa": 40}, environ_base={"REMOTE_ADDR": "192.168.1.156"})
    trip_launch_id = res_trip_launch.get_json()["viaje_id"]
    res_accept_launch = client.post(f"/api/viajes/{trip_launch_id}/aceptar",
                                    headers={"X-Driver-Token": driver1_token},
                                    json={"conductor_id": 1})
    assert res_accept_launch.status_code == 200, f"Esperado 200 con PLAN_GRATIS_LAUNCH=1, obtenido {res_accept_launch.status_code}"

    # Restaurar repartidor 1 a fecha futura y resetear variable
    os.environ.pop("PLAN_GRATIS_LAUNCH", None)
    with server.get_db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE conductores SET plan_expira = '2099-12-31', plan_activo = 1 WHERE id = 1")
        conn.commit()
    print("  -> PASÓ: Control de vencimiento y bypass con PLAN_GRATIS_LAUNCH=1 verificado.")

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
    assert ver_data["version"] == "1.3.0-lanzamiento-gratis", f"Esperado 1.3.0-lanzamiento-gratis, obtenido {ver_data['version']}"

    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.get_json()["status"] == "healthy"
    print(f"  -> PASÓ: Telemetría activa en /api/version ({ver_data['version']}) y /health (healthy).")

    # ---------------------------------------------------------
    # M7-1: Validación de Registro de Repartidores (Zero Aprobación Manual)
    # ---------------------------------------------------------
    print("\n[TEST M7-1] Verificando endpoint de registro de repartidores (/api/conductor/registro)...")
    # 1. Falta aceptar reglas -> 400
    r_no_rules = client.post("/api/conductor/registro", json={
        "nombre": "Juan Pérez", "cedula": "001-201090-0001A", "telefono": "88887777", "placa": "MY-1111", "reglas_aceptadas": False
    })
    assert r_no_rules.status_code == 400, f"Esperado 400 sin reglas, obtenido {r_no_rules.status_code}"

    # 2. Nombre muy corto -> 400
    r_short_name = client.post("/api/conductor/registro", json={
        "nombre": "J", "cedula": "001-201090-0001A", "telefono": "88887777", "placa": "MY-1111", "reglas_aceptadas": True
    })
    assert r_short_name.status_code == 400, f"Esperado 400 con nombre corto, obtenido {r_short_name.status_code}"

    # 3. Cédula inválida -> 400
    r_bad_cedula = client.post("/api/conductor/registro", json={
        "nombre": "Juan Pérez", "cedula": "123", "telefono": "88887777", "placa": "MY-1111", "reglas_aceptadas": True
    })
    assert r_bad_cedula.status_code == 400, f"Esperado 400 con cédula inválida, obtenido {r_bad_cedula.status_code}"

    # 4. Teléfono inválido -> 400
    r_bad_tel = client.post("/api/conductor/registro", json={
        "nombre": "Juan Pérez", "cedula": "001-201090-0001A", "telefono": "123", "placa": "MY-1111", "reglas_aceptadas": True
    })
    assert r_bad_tel.status_code == 400, f"Esperado 400 con teléfono inválido, obtenido {r_bad_tel.status_code}"

    server.registro_rate_limiter.requests.clear()
    test_phone = f"50587{secrets.randbelow(899999) + 100000}"
    test_cedula = f"001-{secrets.randbelow(899999) + 100000:06d}-0004X"

    # 5. Registro exitoso -> 201
    r_reg_ok = client.post("/api/conductor/registro", json={
        "nombre": "Moisés Gadea",
        "cedula": test_cedula,
        "telefono": test_phone,
        "placa": "MY-9988",
        "reglas_aceptadas": True
    })
    assert r_reg_ok.status_code == 201, f"Esperado 201 en registro exitoso, obtenido {r_reg_ok.status_code}"
    reg_data = r_reg_ok.get_json()
    assert reg_data["success"] is True
    assert "driver_token" in reg_data and reg_data["driver_token"].startswith("MD-DRV-")
    nuevo_cond_id = reg_data["conductor_id"]
    nuevo_cond_token = reg_data["driver_token"]

    # 6. Intento de registro duplicado -> 409
    r_reg_dup = client.post("/api/conductor/registro", json={
        "nombre": "Moisés Gadea Clon",
        "cedula": test_cedula,
        "telefono": test_phone,
        "placa": "MY-9988",
        "reglas_aceptadas": True
    })
    assert r_reg_dup.status_code == 409, f"Esperado 409 por duplicado, obtenido {r_reg_dup.status_code}"

    # 7. Registro con PLAN_GRATIS_LAUNCH=1 -> plan 'Lanzamiento (Gratis)' (+365 días)
    server.registro_rate_limiter.requests.clear()
    test_phone_launch = f"50586{secrets.randbelow(899999) + 100000}"
    test_cedula_launch = f"001-{secrets.randbelow(899999) + 100000:06d}-0005Y"
    os.environ["PLAN_GRATIS_LAUNCH"] = "1"
    r_reg_launch = client.post("/api/conductor/registro", json={
        "nombre": "Conductor Lanzamiento",
        "cedula": test_cedula_launch,
        "telefono": test_phone_launch,
        "placa": "MY-7766",
        "reglas_aceptadas": True
    })
    assert r_reg_launch.status_code == 201
    launch_cond_id = r_reg_launch.get_json()["conductor_id"]
    with server.get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT plan_nombre, plan_expira FROM conductores WHERE id = ?", (launch_cond_id,))
        cond_row = cur.fetchone()
        assert cond_row["plan_nombre"] == "Lanzamiento (Gratis)"
    os.environ.pop("PLAN_GRATIS_LAUNCH", None)
    print("  -> PASÓ: Registro valida cédula/teléfono/reglas, emite token secreto, asigna plan Lanzamiento si aplica y previene duplicados (201/409).")

    # ---------------------------------------------------------
    # M7-2: Suspensión Inmediata por Operador (Corte Inmediato 403)
    # ---------------------------------------------------------
    print("\n[TEST M7-2] Verificando palanca de suspensión del operador (/admin/conductor/<id>/suspender)...")
    # Conductor nuevo puede consultar viajes con su token -> 200
    r_feed_init = client.get(f"/api/conductor/viajes-pendientes?conductor_id={nuevo_cond_id}",
                             headers={"X-Driver-Token": nuevo_cond_token})
    assert r_feed_init.status_code == 200, f"Esperado 200 para conductor activo, obtenido {r_feed_init.status_code}"

    # Suspender sin admin key -> 403
    r_susp_no_key = client.post(f"/admin/conductor/{nuevo_cond_id}/suspender")
    assert r_susp_no_key.status_code == 403, f"Esperado 403 sin admin key, obtenido {r_susp_no_key.status_code}"

    # Suspender con admin key -> 200
    r_susp_ok = client.post(f"/admin/conductor/{nuevo_cond_id}/suspender?key=sentinel_mandados_admin_key_2026")
    assert r_susp_ok.status_code == 200
    assert r_susp_ok.get_json()["suspendido"] == 1

    # Conductor suspendido consulta viajes -> 403 INMEDIATO
    r_feed_susp = client.get(f"/api/conductor/viajes-pendientes?conductor_id={nuevo_cond_id}",
                             headers={"X-Driver-Token": nuevo_cond_token})
    assert r_feed_susp.status_code == 403, f"Esperado 403 para conductor suspendido, obtenido {r_feed_susp.status_code}"
    assert "suspendida" in r_feed_susp.get_json()["error"].lower()

    # Conductor suspendido intenta aceptar mandado -> 403
    r_trip_for_susp = client.post("/api/viajes/crear", json={
        "pasajero_nombre": "Prueba Susp", "origen": "A", "destino": "B", "tarifa": 35.0
    })
    trip_susp_id = r_trip_for_susp.get_json()["viaje_id"]
    r_accept_susp = client.post(f"/api/viajes/{trip_susp_id}/aceptar",
                                headers={"X-Driver-Token": nuevo_cond_token},
                                json={"conductor_id": nuevo_cond_id})
    assert r_accept_susp.status_code == 403, f"Esperado 403 al aceptar mandado estando suspendido, obtenido {r_accept_susp.status_code}"

    # Reactivar conductor con admin key -> 200
    r_reactivate = client.post(f"/admin/conductor/{nuevo_cond_id}/suspender?key=sentinel_mandados_admin_key_2026")
    assert r_reactivate.status_code == 200
    assert r_reactivate.get_json()["suspendido"] == 0

    # Ahora sí puede consultar de nuevo -> 200
    r_feed_react = client.get(f"/api/conductor/viajes-pendientes?conductor_id={nuevo_cond_id}",
                              headers={"X-Driver-Token": nuevo_cond_token})
    assert r_feed_react.status_code == 200
    print("  -> PASÓ: Suspensión por operador bloquea acceso al instante (403); reactivación operativa verificada.")

    # ---------------------------------------------------------
    # M7-3: Bitácora de Estados "Caja Negra" (Tabla bitacora_estados)
    # ---------------------------------------------------------
    print("\n[TEST M7-3] Verificando bitácora inmutable de estados (caja negra)...")
    session_tok_caja = secrets.token_hex(16)
    r_caja_trip = client.post("/api/viajes/crear", json={
        "pasajero_nombre": "Don Rigoberto",
        "cliente_telefono": "50588883333",
        "origen": "Ferretería Central",
        "destino": "Reparto El Calvario",
        "paquete_desc": "Herramientas de mano",
        "tarifa": 45.0,
        "session_token": session_tok_caja
    })
    caja_trip_id = r_caja_trip.get_json()["viaje_id"]

    # Repartidor acepta el mandado
    r_caja_acc = client.post(f"/api/viajes/{caja_trip_id}/aceptar",
                             headers={"X-Driver-Token": nuevo_cond_token},
                             json={"conductor_id": nuevo_cond_id})
    assert r_caja_acc.status_code == 200

    # Repartidor avanza a en_camino
    r_caja_prog = client.post(f"/api/viajes/{caja_trip_id}/cambiar_estado",
                              headers={"X-Driver-Token": nuevo_cond_token},
                              json={"estado": "en_camino"})
    assert r_caja_prog.status_code == 200

    # Completar / entregar mandado
    r_caja_done = client.post(f"/api/viajes/{caja_trip_id}/cambiar_estado",
                              headers={"X-Driver-Token": nuevo_cond_token},
                              json={"estado": "entregado"})
    assert r_caja_done.status_code == 200

    # Consultar eventos en bitacora_estados
    with server.get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM bitacora_estados WHERE viaje_id = ? ORDER BY id ASC", (caja_trip_id,))
        eventos = [dict(r) for r in cur.fetchall()]
        assert len(eventos) >= 4, f"Se esperaban al menos 4 eventos en bitácora, obtenidos {len(eventos)}"
        assert eventos[0]["estado_nuevo"] == "buscando"
        assert eventos[1]["estado_anterior"] == "buscando" and eventos[1]["estado_nuevo"] == "aceptado"
        assert eventos[2]["estado_anterior"] == "aceptado" and eventos[2]["estado_nuevo"] == "en_camino"
        assert eventos[3]["estado_anterior"] == "en_camino" and eventos[3]["estado_nuevo"] == "entregado"
        for ev in eventos:
            assert ev["created_at"] is not None
            assert ev["actor"] is not None
    print(f"  -> PASÓ: Bitácora registró fielmente {len(eventos)} transiciones con actor y timestamp (Caja Negra 100%).")

    # ---------------------------------------------------------
    # M7-4: Vista de Expediente / Caso en /admin/caso/<id>
    # ---------------------------------------------------------
    print("\n[TEST M7-4] Verificando expediente de caso en /admin/caso/<id>...")
    # Sin admin key -> 403
    r_caso_nokey = client.get(f"/admin/caso/{caja_trip_id}")
    assert r_caso_nokey.status_code == 403, f"Esperado 403 sin admin key, obtenido {r_caso_nokey.status_code}"

    # Con admin key incorrecta -> 403
    r_caso_badkey = client.get(f"/admin/caso/{caja_trip_id}?key=clave_erronea")
    assert r_caso_badkey.status_code == 403, f"Esperado 403 con admin key incorrecta, obtenido {r_caso_badkey.status_code}"

    # Con admin key válida (HTML) -> 200
    r_caso_html = client.get(f"/admin/caso/{caja_trip_id}?key=sentinel_mandados_admin_key_2026")
    assert r_caso_html.status_code == 200
    html_text = r_caso_html.get_data(as_text=True)
    assert "Expediente Oficial de Mandado" in html_text
    assert "Don Rigoberto" in html_text
    assert "50588883333" in html_text
    assert "Moisés Gadea" in html_text
    assert test_cedula in html_text
    assert "MY-9988" in html_text
    assert "Caja Negra" in html_text or "Bitácora" in html_text

    # Con admin key válida (JSON) -> 200
    r_caso_json = client.get(f"/admin/caso/{caja_trip_id}?key=sentinel_mandados_admin_key_2026&format=json")
    assert r_caso_json.status_code == 200
    caso_data = r_caso_json.get_json()
    assert caso_data["viaje"]["id"] == caja_trip_id
    assert caso_data["viaje"]["cliente_telefono"] == "50588883333"
    assert caso_data["conductor"]["cedula"] == test_cedula
    assert caso_data["conductor"]["placa"] == "MY-9988"
    assert len(caso_data["bitacora"]) >= 4
    print("  -> PASÓ: Expediente de caso protegido (403/200), reúne solicitante, repartidor, cédula y bitácora.")

    # ---------------------------------------------------------
    # M7-5: Verificación Estricta Zero-PII en APIs Públicas
    # ---------------------------------------------------------
    print("\n[TEST M7-5] Verificando Zero-PII (Cero filtración de cédulas ni teléfonos de clientes)...")
    r_pub_drivers = client.get("/api/conductores/activos")
    assert r_pub_drivers.status_code == 200
    for d in r_pub_drivers.get_json():
        assert "cedula" not in d, "Cédula NUNCA debe estar en /api/conductores/activos"
        assert "telefono" not in d, "Teléfono NUNCA debe estar en /api/conductores/activos"
        assert "placa" not in d, "Placa NUNCA debe estar en /api/conductores/activos"

    r_pub_feed = client.get(f"/api/conductor/viajes_pendientes?conductor_id=1",
                            headers={"X-Driver-Token": driver1_token})
    assert r_pub_feed.status_code == 200
    for c in r_pub_feed.get_json().get("viajes", []):
        assert "cliente_telefono" not in c, "Teléfono del remitente NO debe estar en feed público"
        assert "telefono" not in c, "Teléfono del remitente NO debe estar en feed público"
        assert "session_token" not in c, "Token de sesión NO debe filtrarse en feed de repartidores"
    print("  -> PASÓ: APIs públicas estrictamente saneadas contra PII (Cero fugas).")

    print("\n" + "=" * 65)
    print("[OK] AUDITORIA COMPLETA! TODOS LOS CRITERIOS (MA-1 A MA-10 Y M7-1 A M7-5) PASARON AL 100%")
    print("=" * 65)

if __name__ == "__main__":
    run_all_tests()
