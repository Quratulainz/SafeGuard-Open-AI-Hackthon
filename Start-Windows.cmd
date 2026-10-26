@echo off
setlocal
cd /d "%~dp0"
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 goto launch_py
python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 goto launch_python
echo Install Python 3.10 or newer from https://www.python.org/downloads/ and try again.
echo Enable the Python launcher or Add Python to PATH during installation.
pause
exit /b 1
:launch_py
py -3 "%~dp0start.py" %*
goto finished
:launch_python
python "%~dp0start.py" %*
:finished
set "safeguard_exit=%errorlevel%"
if not "%safeguard_exit%"=="0" pause
exit /b %safeguard_exit%
