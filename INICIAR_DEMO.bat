@echo off
cd /d "%~dp0"
echo =============================================
echo        AUDIT LOG SYSTEM - INICIO LOCAL
echo =============================================
where py >nul 2>nul
if errorlevel 1 (
  echo No se encontro el lanzador de Python (py).
  echo Instala Python 3 desde https://www.python.org/downloads/ y marca Add Python to PATH.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo Creando entorno virtual...
  py -m venv .venv
  if errorlevel 1 goto error
)
call ".venv\Scripts\activate.bat"
echo Comprobando e instalando dependencias...
python -m pip install -r requirements.txt
if errorlevel 1 goto error
echo.
echo Abriendo servidor local...
echo Cuando aparezca la direccion, abre http://127.0.0.1:8000 en Chrome o Edge.
echo Para cerrar, regresa a esta ventana y presiona Ctrl+C.
echo.
python app.py
pause
exit /b 0
:error
echo Ocurrio un error durante la preparacion. Revisa que Python este instalado.
pause
exit /b 1
