@echo off
title SecureShare server
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 ( set PY=py -3 ) else ( set PY=python )

echo Installing requirements (first run only)...
%PY% -m pip install -q -r requirements.txt
if errorlevel 1 (
  echo.
  echo Could not install requirements. Check that Python is installed and on PATH.
  pause
  exit /b 1
)

rem open the browser a few seconds after the server starts
start "" cmd /c "timeout /t 10 /nobreak >nul & start http://127.0.0.1:5050 & start \"\" explorer \"%~dp0data\""

echo.
echo Keep this window open while SecureShare is in use.
%PY% server.py
pause
