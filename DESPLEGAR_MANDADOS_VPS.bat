@echo off
title DESPLEGAR MANDADOS APP AL VPS (2.25.121.124)
color 0b
echo ===============================================================================
echo     DESPLEGAR MANDADOS APP (PUERTO 5058) AL VPS DE HOUSTON
echo ===============================================================================
echo.
echo [1/3] Sincronizando archivos actualizados a /root/mandados_app/...
echo (Introduce la contrasenia de root del VPS si te la solicita)
ssh root@2.25.121.124 "mkdir -p /root/mandados_app"
scp "C:\Users\luis\mandados_app\index.html" "C:\Users\luis\mandados_app\server.py" "C:\Users\luis\mandados_app\app.js" "C:\Users\luis\mandados_app\sw.js" "C:\Users\luis\mandados_app\version.txt" "C:\Users\luis\mandados_app\privacidad.html" "C:\Users\luis\mandados_app\manifest.json" "C:\Users\luis\mandados_app\test_mandados.py" "C:\Users\luis\mandados_app\test_dispatch.py" "C:\Users\luis\mandados_app\Dockerfile" "C:\Users\luis\mandados_app\docker-compose.yml" "C:\Users\luis\mandados_app\requirements.txt" "C:\Users\luis\mandados_app\.env.example" root@2.25.121.124:/root/mandados_app/

echo.
echo [2/3] Reconstruyendo y levantando contenedor mandados_app en puerto 5058...
ssh root@2.25.121.124 "cd /root/mandados_app && if [ ! -f .env ]; then cp .env.example .env; fi && docker compose up -d --build"

echo.
echo [3/3] Verificando respuesta en vivo en /api/version y /health (puerto 5058)...
timeout /t 3 /nobreak >nul
ssh -i C:\Users\luis\.ssh\id_auditor_sentinel -o BatchMode=yes auditor@2.25.121.124 "curl -s http://127.0.0.1:5058/api/version"
echo.
ssh -i C:\Users\luis\.ssh\id_auditor_sentinel -o BatchMode=yes auditor@2.25.121.124 "curl -s http://127.0.0.1:5058/health"

echo.
echo ===============================================================================
echo  DESPLIEGUE FINALIZADO! Mandados App activo y aislado en puerto 5058
echo ===============================================================================
pause
