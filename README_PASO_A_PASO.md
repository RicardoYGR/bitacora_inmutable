# Audit Log Lab — guía para ejecutar la demostración

Esta es una interfaz local para acompañar el proyecto de bitácora. Usa Python para ejecutar las operaciones criptográficas y el navegador solo presenta estados resumidos. Los registros son ficticios.

## 1. Qué incluye

- `app.py`: servidor local y conexión entre la página y los módulos criptográficos.
- `chain.py`: encadenamiento HMAC-SHA-256 (adaptado del módulo del equipo).
- `merkle.py`: cálculo de la raíz del árbol Merkle (adaptado del módulo del equipo).
- `signer.py`: funciones de firma y verificación Ed25519 basadas en el módulo del equipo.
- `static/index.html`: interfaz visual.
- `data/`: aquí se generan las llaves locales y se guarda la bitácora de demostración (`bitacora_demo.jsonl`) junto con los sellos de lote. No compartir ni publicar esta carpeta.

La llave HMAC y la llave privada Ed25519 se guardan localmente con permisos restringidos. Nunca se envían al navegador. La interfaz tampoco muestra etiquetas HMAC, raíces Merkle, firmas ni valores de llaves.

## 2. Requisitos

- Windows 10/11.
- Python 3.10 o posterior.
- Visual Studio Code (recomendado) o una terminal.
- Conexión a internet solo para instalar `cryptography` si aún no está instalado. La página después funciona localmente.

## 3. Abrir la carpeta

1. Descomprime `Bitacora_Audit_Lab.zip` en una carpeta fácil de encontrar, por ejemplo `Documentos`.
2. Abre Visual Studio Code.
3. Selecciona **File > Open Folder** y abre `Bitacora_Audit_Lab`.
4. Abre **Terminal > New Terminal**.

## 4. Crear un entorno e instalar la librería

En la terminal de VS Code, ejecuta estos comandos, uno por uno:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Si PowerShell bloquea la activación, puedes usar la terminal **Command Prompt** y ejecutar:

```cmd
.venv\Scripts\activate.bat
```

Después instala con `pip install -r requirements.txt`.

## 5. Iniciar la página

**Forma más sencilla:** haz doble clic en `INICIAR_DEMO.bat`. La primera vez crea el entorno virtual e instala la librería necesaria. Cuando aparezca el mensaje del servidor, abre `http://127.0.0.1:8000` en Chrome o Edge.

**Forma manual:** en la misma terminal, desde la carpeta donde está `app.py`, ejecuta:

```powershell
python app.py
```

Debe aparecer un mensaje indicando que está disponible en `http://127.0.0.1:8000`.

Abre Chrome o Edge y escribe esa dirección. No cierres la terminal mientras uses la página. Para detener el servidor, vuelve a la terminal y presiona `Ctrl + C`.

## 6. Orden recomendado para la demostración

1. Pulsa **Agregar registro** tres o cuatro veces, cambiando el tipo de evento.
2. En **Vista interna**, observa los mensajes de proceso. No se muestran llaves ni valores criptográficos.
3. Pulsa **Sellar lote Merkle + Ed25519**. Esto calcula una raíz para los registros nuevos y la firma con Ed25519.
4. Pulsa **Verificar bitácora**. Debe mostrar integridad confirmada y firma válida.
5. Pulsa **Simular alteración**. Se cambia un registro ficticio en memoria.
6. Pulsa **Verificar bitácora** otra vez. Debe detectarse la alteración.
7. Pulsa **Ejecutar comparación** para mostrar por qué la cadena débil con SHA-256 simple puede recalcularse y por qué el HMAC sin la llave no puede falsificarse de esa manera.
8. Pulsa **Reiniciar laboratorio** para limpiar la sesión de demostración y comenzar de nuevo.

## 7. Qué significa cada vista

- **Lo que ve el usuario:** estado general, cantidad de eventos y resultado de las verificaciones. No recibe secretos ni datos internos.
- **Vista interna:** mensajes explicativos de las operaciones ejecutadas por Python. Se muestran nombres de algoritmos y etapas, no sus valores secretos.

La vista interna es una representación didáctica del procedimiento, no una captura de memoria ni una consola que revele los datos criptográficos.

## 8. Seguridad y limitaciones importantes

- La aplicación escucha solo en `127.0.0.1`, por lo que no se publica en internet ni se abre a otros equipos de la red.
- No subas `data/`, `.venv/`, archivos `.key` ni la llave privada al repositorio o a GitHub.
- No uses datos reales de estudiantes, docentes, cuentas o sistemas. Los eventos incluidos son ficticios.
- La interfaz oculta valores sensibles, pero una persona con acceso a la computadora y a los archivos Python puede inspeccionar el proyecto. No debe describirse como protección frente a un administrador local malicioso.
- Los registros y sellos de lote se guardan localmente en `data/` y se recuperan al volver a iniciar la aplicación. La simulación de alteración modifica una copia en memoria y no destruye el archivo original. Las llaves también permanecen en `data/` entre ejecuciones.
- El sellado Merkle/Ed25519 se guarda junto con la bitácora para poder volver a verificarlo al reiniciar. Para una bitácora de producción todavía harían falta almacenamiento de solo anexado, copias externas o anclajes independientes que dificulten el borrado o reemplazo de archivos.
- El demo de ataque es educativo y solo modifica datos sintéticos en memoria.

## 9. Si algo no funciona

- `py` no se reconoce: instala Python desde python.org y activa la opción **Add Python to PATH**.
- `No module named cryptography`: activa el entorno `.venv` e instala `pip install -r requirements.txt`.
- El navegador no abre: comprueba que `python app.py` siga ejecutándose y usa exactamente `http://127.0.0.1:8000`.
- Puerto ocupado: cierra otra ejecución de la aplicación antes de volver a iniciar.
- No borres ni edites manualmente los archivos de `data/` mientras la aplicación está funcionando.
