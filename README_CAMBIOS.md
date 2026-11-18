# Cambios corregidos — Bitácora Audit Lab

Fecha: 18 de noviembre de 2026. Revisado y probado el flujo completo
(agregar, verificar, sellar, alterar, detectar, atacar y reiniciar).

## Qué se corrigió

### 1. El botón "Reiniciar laboratorio" no hacía nada
Causa: usaba el diálogo nativo `confirm()` del navegador, que los
navegadores automatizados cancelan solos y en móvil a veces ni se ve.
Ahora la confirmación es en dos pasos dentro del mismo botón: el primer
clic dice "¿Seguro? Haz clic de nuevo para reiniciar" y el segundo
reinicia de verdad. Al reiniciar también se limpian los resultados de
la comparación de ataque. Aplica a `index.html` (GitHub Pages) y a
`static/index.html` (demo local).

### 2. Los botones no respondían con la bitácora vacía
Sellar, alterar y verificar con 0 registros no mostraban nada, porque
los errores se mostraban con `alert()`, que también se suprime en
navegadores automatizados y bloqueadores. Ahora los errores aparecen
dentro de la página, en la caja de resultado:
- Sellar en vacío: "Primero agrega al menos un registro."
- Alterar en vacío: "Agrega registros antes de simular una alteración."
- Verificar en vacío: ya no dice "Integridad confirmada" (era engañoso);
  dice "Sin registros" y explica que no hay nada que verificar.

### 3. Etiquetas de integridad inconsistentes
Al entrar se leía "Pendiente" y tras recargar "Íntegra" con 0 registros.
Ahora con 0 registros siempre dice "Sin verificar", y cuando se detecta
una alteración dice "Comprometida" en rojo (antes "Revisar", poco claro).

### 4. La vista interna ya muestra los SHA y todo el detalle
Nueva sección "DETALLE CRIPTOGRÁFICO / VALORES CALCULADOS" en la vista
interna, con valores completos (no solo los primeros 8 caracteres):
- Por registro: HMAC-SHA-256 completo (64 hex) y el `prev` al que se encadena.
- Por lote: raíz Merkle completa (64 hex) y firma Ed25519 completa (128 hex).
- Las llaves NUNCA se muestran: la llave HMAC y la privada Ed25519 se
  quedan en el servidor (versión local) o en memoria no exportable
  (versión de navegador).

### 5. La versión local ahora marca qué registro se alteró
Antes, al detectar una alteración, todos los registros decían "Revisar".
Ahora el registro alterado dice "Alterado", los siguientes "Afectado" y
los anteriores "Válido", igual que en la versión de navegador.
También se corrigió un fallo: si fallaba una firma de lote (sin
`bad_index`), el mensaje de verificación rompía con un error 500.

### 6. Detalles
- La consola interna ya no deja tanto espacio en blanco.
- El pie trae el enlace al código fuente en GitHub.
- `app.py` ahora expone los valores criptográficos en `/api/state`
  (etiquetas, raíces y firmas; nunca las llaves).

## Archivos de este paquete

- `index.html` — versión de navegador (GitHub Pages). Reemplaza el
  `index.html` de la raíz del repo.
- `static/index.html` — versión local (Flask). Reemplaza el archivo en
  `static/`.
- `app.py` — servidor local con los cambios del punto 4 y 5.
- `chain.py`, `merkle.py`, `signer.py`, `requirements.txt`,
  `INICIAR_DEMO.bat`, `README_PASO_A_PASO.md` — sin cambios.
- No se incluye la carpeta `data/` (llaves y bitácora locales): no se
  debe publicar ni compartir.

## Cómo lo sube Ricardo

1. En GitHub, en el repo `ricardoygr/bitacora_inmutable`, reemplazar
   `index.html` (raíz) por el de este paquete y `static/index.html` y
   `app.py` por los de este paquete.
2. GitHub Pages se actualiza solo en unos minutos.
3. Para la demo local: `python app.py` y abrir http://127.0.0.1:8000.

## Probado

- Versión local (Python + `cryptography`): estado inicial, verificar en
  vacío, sellar en vacío, agregar 2 registros, sellar lote, verificar,
  alterar y detectar (EVT-002 Alterado, EVT-001 Válido), comparación de
  ataque, reinicio y carga de la página (200). Todo correcto.
- Versión de navegador (Node + WebCrypto): mismo flujo, más la
  comprobación de que el detalle criptográfico muestra los valores
  completos y que las etiquetas quedan en "Sin verificar" /
  "Comprometida" según corresponde. Todo correcto.
