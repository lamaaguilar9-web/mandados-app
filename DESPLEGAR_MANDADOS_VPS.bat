@echo off
title DESPLEGAR MANDADOS APP AL VPS (2.25.121.124)
color 0b
echo ===============================================================================
echo     DESPLEGAR MANDADOS APP (PUERTO 5058) AL VPS DE HOUSTON
echo ===============================================================================
echo.
echo [1/4] Sincronizando archivos actualizados a /root/mandados_app/...
echo (Introduce la contrasenia de root del VPS si te la solicita)
ssh root@2.25.121.124 "mkdir -p /root/mandados_app"
scp "C:\Users\luis\mandados_app\index.html" "C:\Users\luis\mandados_app\server.py" "C:\Users\luis\mandados_app\app.js" "C:\Users\luis\mandados_app\sw.js" "C:\Users\luis\mandados_app\version.txt" "C:\Users\luis\mandados_app\privacidad.html" "C:\Users\luis\mandados_app\manifest.json" "C:\Users\luis\mandados_app\test_mandados.py" "C:\Users\luis\mandados_app\test_dispatch.py" "C:\Users\luis\mandados_app\Dockerfile" "C:\Users\luis\mandados_app\docker-compose.yml" "C:\Users\luis\mandados_app\requirements.txt" "C:\Users\luis\mandados_app\.env.example" root@2.25.121.124:/root/mandados_app/

echo.
echo [2/4] Configurando Nginx para mandados.sentinelfleet.tech (puerto 5058)...
scp "C:\Users\luis\mandados_app\nginx_mandados.conf" root@2.25.121.124:/etc/nginx/conf.d/mandados.conf
ssh root@2.25.121.124 "nginx -t && systemctl reload nginx"

echo.
echo [3/4] Reconstruyendo y levantando contenedor mandados_app en puerto 5058...
ssh root@2.25.121.124 "cd /root/mandados_app && if [ ! -f .env ]; then cp .env.example .env; fi && sed -i 's/HOST=127.0.0.1/HOST=0.0.0.0/g' .env && docker compose down 2>/dev/null; if [ -d mandados.db ]; then rm -rf mandados.db; fi; touch mandados.db && docker compose up -d --build --force-recreate"

echo.
echo [4/4] Verificando sondas en vivo (Mandados 5058 y Caponera 5054)...
timeout /t 5 /nobreak >nul
echo --- Sonda Mandados App (/api/version):
ssh -i C:\Users\luis\.ssh\id_auditor_sentinel -o BatchMode=yes auditor@2.25.121.124 "curl -s http://127.0.0.1:5058/api/version"
echo.
echo --- Sonda Mandados App (/health):
ssh -i C:\Users\luis\.ssh\id_auditor_sentinel -o BatchMode=yes auditor@2.25.121.124 "curl -s http://127.0.0.1:5058/health"
echo.
echo --- Sonda Caponera App (/api/version intacta):
ssh -i C:\Users\luis\.ssh\id_auditor_sentinel -o BatchMode=yes auditor@2.25.121.124 "curl -s http://127.0.0.1:5054/api/version"
echo.
echo --- Diagnostico de contenedor Docker mandados_app:
ssh root@2.25.121.124 "docker ps -f name=mandados_app && echo --- Ultimos logs: && docker logs --tail 15 mandados_app"

echo.
echo ===============================================================================
echo  DESPLIEGUE FINALIZADO! Mandados App activo en 5058 y Caponera intacta en 5054
echo ===============================================================================
pause
