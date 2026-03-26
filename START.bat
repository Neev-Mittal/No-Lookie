@echo off
REM QRIE Platform - Complete Startup Script for Windows
REM Starts both the Frontend (Vite) and Backend (Python) servers

echo.
echo ============================================================
echo   PSB Cybersecurity Hackathon - QRIE Platform
echo   Complete Development Environment Startup
echo ============================================================
echo.

REM Change to project directory
cd /d "%~dp0"

echo Checking prerequisites...
echo.

REM Check Node.js
node --version > nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js is not installed or not in PATH
    echo Please install Node.js 18+ from https://nodejs.org
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('node --version') do set NODE_VER=%%i
echo ✓ Node.js detected: %NODE_VER%

REM Check npm
npm --version > nul 2>&1
if errorlevel 1 (
    echo ERROR: npm is not installed
    pause
    exit /b 1
)
echo ✓ npm detected

REM Check Python
python --version > nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.9+ from https://www.python.org
    pause
    exit /b 1
)
echo ✓ Python detected

echo.
echo ============================================================
echo   Installing/Verifying Dependencies...
echo ============================================================
echo.

REM Install Node dependencies if node_modules doesn't exist
if not exist "node_modules" (
    echo Installing Node.js dependencies...
    call npm install
    if errorlevel 1 (
        echo ERROR: Failed to install Node.js dependencies
        pause
        exit /b 1
    )
    echo ✓ Node.js dependencies installed
) else (
    echo ✓ Node.js dependencies already installed
)

REM Verify Python packages
echo Checking Python dependencies...
pip show fastapi > nul 2>&1
if errorlevel 1 (
    echo Installing Python dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install Python dependencies
        pause
        exit /b 1
    )
    echo ✓ Python dependencies installed
) else (
    echo ✓ Python dependencies already installed
)

REM Check Docker and PostgreSQL
echo.
echo ============================================================
echo   Checking Database Setup...
echo ============================================================
echo.

REM Check if Docker is available (for PostgreSQL)
docker --version > nul 2>&1
if errorlevel 1 (
    echo ⚠ Warning: Docker not found. PostgreSQL will not start.
    echo   Install Docker from https://docker.com
    echo   Or set up PostgreSQL locally and update .env.local
    echo.
) else (
    echo ✓ Docker detected
    echo Starting PostgreSQL in Docker...
    docker-compose up -d 2>nul
    if errorlevel 1 (
        echo ⚠ Warning: Failed to start Docker containers (Docker daemon might not be running)
        echo   Start Docker Desktop manually and try again
        echo.
    ) else (
        echo ✓ PostgreSQL container started
        echo Waiting for database to be ready...
        timeout /t 5 /nobreak
        echo ✓ Database ready (data will auto-load when API starts)
    )
    echo.
)

echo.
echo ============================================================
echo   Starting Servers...
echo ============================================================
echo.
echo Frontend will be available at: http://localhost:5173
echo Database API will be available at: http://localhost:8001 (with docs at /docs)
echo Scanner API will be available at: http://localhost:8000
echo.
echo Press Ctrl+C in any terminal to stop a server
echo.

REM Start Python backend in new window
echo Starting Python Scanner API (port 8000)...
start "QRIE - Scanner API" cmd /k python scanner_api.py

REM Start Database API in new window
echo Starting Python Database API (port 8001)...
timeout /t 2 /nobreak
start "QRIE - Database API" cmd /k python database_api.py

REM Start Frontend in new window
echo Starting Frontend (Vite, port 5173)...
timeout /t 2 /nobreak
start "QRIE - Frontend" cmd /k npm run dev

echo.
echo ============================================================
echo   All servers started! Opening browser...
echo ============================================================
echo.

REM Wait a moment for servers to start
timeout /t 4 /nobreak

REM Open browser
start http://localhost:5173

echo.
echo ✓ QRIE Platform is ready!
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
echo Close this window to stop monitoring.
pause
