@echo off
rem Regenerates every table and figure of the paper. Run setup.bat once before this.
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (set "PY=.venv\Scripts\python.exe") else (where py >nul 2>nul && (set "PY=py -3") || (set "PY=python"))
%PY% run_all.py
set RC=%ERRORLEVEL%
echo.
if not "%RC%"=="0" echo Something failed. If a package is missing, run setup.bat first.
pause
exit /b %RC%
