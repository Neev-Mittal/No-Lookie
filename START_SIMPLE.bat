@echo off
REM QRIE Platform - Simple Startup Script
REM Fast startup without Docker/PostgreSQL checks

echo.
echo ============================================================
echo   PSB Cybersecurity Hackathon - QRIE Platform
echo   Starting Services...
echo ============================================================
echo.

REM Change to project directory
cd /d "%~dp0"

echo Starting services (open 5 new windows)...
echo.

REM Start services in separate windows
echo [1/5] Starting PostgreSQL (Docker)...
start "QRIE - PostgreSQL" cmd /k "docker-compose up -d && echo. && echo PostgreSQL is starting... && pause"

timeout /t 3 /nobreak

echo [2/5] Starting Scanner API (Port 8000)...
start "QRIE - Scanner API" cmd /k "python scanner_api.py"

timeout /t 2 /nobreak

echo [3/5] Starting Database API (Port 8001)...
start "QRIE - Database API" cmd /k "python database_api.py"

timeout /t 2 /nobreak

echo [4/5] Starting Frontend (Port 5173)...
start "QRIE - Frontend" cmd /k "npm run dev"

echo [5/5] Loading data (one-time)...
timeout /t 5 /nobreak
start "QRIE - Data Loader" cmd /k "python load_data.py && echo. && echo Data loaded! You can close this window. && pause"

echo.
echo ============================================================
echo   Services are starting in separate windows!
echo ============================================================
echo.
echo Access the application at:
echo   Frontend: http://localhost:5173
echo   API Docs: http://localhost:8001/docs
echo   pgAdmin:  http://localhost:5050 (admin@qrie.local / admin)
echo.
echo Demo Credentials:
echo   Email: any@email.com
echo   Password: anypassword
echo.
pause
