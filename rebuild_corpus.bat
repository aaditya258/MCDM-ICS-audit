@echo off
rem Rebuilds the 33 ICS matrices from the public CISA feeds. Needs git and an internet connection.
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (set "PY=.venv\Scripts\python.exe") else (where py >nul 2>nul && (set "PY=py -3") || (set "PY=python"))
where git >nul 2>nul || (echo git was not found. Install it from https://git-scm.com/download/win & pause & exit /b 1)
if not exist feeds mkdir feeds
if not exist feeds\CSAF git clone --depth 1 https://github.com/cisagov/CSAF feeds\CSAF
if not exist feeds\vulnrichment git clone --depth 1 https://github.com/cisagov/vulnrichment feeds\vulnrichment
%PY% scripts\build_corpus.py --csaf feeds\CSAF --vulnrichment feeds\vulnrichment
pause
