"""Servidor local para la interfaz de demostración. Solo escucha en 127.0.0.1."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
import json, os, hashlib, hmac, struct, copy, base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

import chain, merkle, signer

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
DATA.mkdir(exist_ok=True)
HMAC_PATH = DATA / "audit_hmac.key"
SIGN_PATH = DATA / "audit_ed25519_private.pem"
LEDGER_PATH = DATA / "bitacora_demo.jsonl"
BATCH_PATH = DATA / "lotes_demo.json"

# Las llaves se crean localmente y nunca se envían al navegador.
if not HMAC_PATH.exists():
    fd = os.open(HMAC_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(os.urandom(32))
HMAC_KEY = HMAC_PATH.read_bytes()
if len(HMAC_KEY) != 32:
    raise RuntimeError("La llave local de HMAC no tiene el tamaño esperado. Detén el servidor y revisa data/.")

if SIGN_PATH.exists():
    SIGN_PRIVATE = serialization.load_pem_private_key(SIGN_PATH.read_bytes(), password=None)
else:
    SIGN_PRIVATE = Ed25519PrivateKey.generate()
    pem = SIGN_PRIVATE.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(SIGN_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
SIGN_PUBLIC = SIGN_PRIVATE.public_key()

EVENTS = {
    "login": ("Acceso autorizado", {"actor": "usuario-demo", "event": "login"}),
    "consulta": ("Consulta de recurso", {"actor": "usuario-demo", "event": "consulta_recurso"}),
    "cambio": ("Cambio de configuración", {"actor": "usuario-demo", "event": "cambio_configuracion"}),
    "logout": ("Cierre de sesión", {"actor": "usuario-demo", "event": "logout"}),
}
records = []
batches = []
logs = []
last_result = {"status": "Pendiente", "message": "Agrega registros para comenzar."}

# Recuperar la bitácora y los sellos de la última ejecución, si existen.
def load_saved_demo():
    if LEDGER_PATH.exists():
        with LEDGER_PATH.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                item = json.loads(line)
                event_name = item.get("registro", {}).get("event", "")
                label = next((v[0] for v in EVENTS.values() if v[1].get("event") == event_name), "Evento de auditoría")
                records.append({"i": item["i"], "registro": item["registro"], "tag": item["tag"], "label": label})
    if BATCH_PATH.exists():
        for item in json.loads(BATCH_PATH.read_text(encoding="utf-8")):
            batches.append({"id": item["id"], "start": item["start"], "end": item["end"],
                            "count": item["count"], "signature": base64.b64decode(item["signature"])})

def save_batches():
    data = [{"id": b["id"], "start": b["start"], "end": b["end"], "count": b["count"],
             "signature": base64.b64encode(b["signature"]).decode("ascii")} for b in batches]
    BATCH_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")

load_saved_demo()

def log(message, status="ok"):
    logs.insert(0, {"message": message, "status": status})
    del logs[12:]

def add_record(kind):
    if kind not in EVENTS:
        raise ValueError("Evento no permitido")
    label, payload = EVENTS[kind]
    i = len(records)
    prev = bytes.fromhex(records[-1]["tag"]) if records else chain.TAG_INICIAL
    tag = chain.calcular_tag(HMAC_KEY, i, payload, prev)
    entry = {"i": i, "registro": copy.deepcopy(payload), "tag": tag.hex(), "label": label}
    records.append(entry)
    # La bitácora se agrega en formato JSONL: un evento por línea.
    with LEDGER_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"i": i, "registro": payload, "tag": tag.hex()}, ensure_ascii=False) + "\n")
    log(f"Registro {i+1:03d}: evento incorporado y protegido con HMAC-SHA-256.")
    return i

def verify_chain():
    # Se entrega al verificador una copia; la UI solo recibe índice/estado.
    safe_entries = [{"i": x["i"], "registro": x["registro"], "tag": x["tag"]} for x in records]
    bad = chain.primer_registro_alterado(HMAC_KEY, safe_entries)
    return bad

def seal_batch():
    if not records:
        raise ValueError("Primero agrega al menos un registro.")
    bad = verify_chain()
    if bad is not None:
        raise ValueError("No se puede sellar: la cadena no pasó la verificación.")
    start = batches[-1]["end"] if batches else 0
    # El lote contiene los registros nuevos desde el último sello.
    subset = records[start:]
    if not subset:
        raise ValueError("No hay registros nuevos para sellar.")
    tags = [bytes.fromhex(x["tag"]) for x in subset]
    root = merkle.calcular_raiz_merkle(tags)
    batch_id = len(batches) + 1
    message = signer.empaquetar_mensaje_lote(batch_id, len(subset), root)
    signature = signer.firmar_lote(SIGN_PRIVATE, message)
    # Se conserva internamente la evidencia necesaria para verificar una firma histórica.
    batches.append({"id": batch_id, "start": start, "end": len(records), "count": len(subset),
                    "root": root, "signature": signature, "message": message})
    save_batches()
    log(f"Lote {batch_id:03d}: raíz Merkle calculada y firma Ed25519 generada.")
    return batch_id

def verify_all():
    bad = verify_chain()
    if bad is not None:
        return {"ok": False, "stage": "HMAC", "bad_index": bad, "signed": False if batches else None}
    if not batches:
        return {"ok": True, "stage": "HMAC", "bad_index": None, "signed": None}
    batch_results = []
    for b in batches:
        subset = records[b["start"]:b["end"]]
        # Recalcular raíz con los tags actuales del segmento firmado.
        try:
            current_root = merkle.calcular_raiz_merkle([bytes.fromhex(x["tag"]) for x in subset])
            message = signer.empaquetar_mensaje_lote(b["id"], b["count"], current_root)
            batch_results.append(signer.verificar_firma_lote(SIGN_PUBLIC, b["signature"], message))
        except Exception:
            batch_results.append(False)
    return {"ok": all(batch_results), "stage": "HMAC+Merkle+Ed25519", "bad_index": None,
            "signed": all(batch_results)}

def public_state():
    check = verify_all()
    bad = check["bad_index"]
    def st(i):
        if bad is not None:
            return "Alterado" if i == bad else ("Afectado" if i > bad else "Válido")
        return "Válido" if check["ok"] else "Revisar"
    visible_records = [{"id": f"EVT-{r['i']+1:03d}", "event": r["label"], "status": st(r["i"]), "hash": r["tag"][:8]} for r in records]
    return {"count": len(records), "records": visible_records,
            "batches": [{"id": f"LOTE-{b['id']:03d}", "count": b["count"], "status": "Firmado", "from": b["start"]+1, "to": b["end"]} for b in batches],
            "integrity": check["ok"], "signed": check["signed"], "logs": logs,
            "last_result": last_result,
            "keys_ready": HMAC_PATH.exists() and SIGN_PATH.exists()}

def attack_demo():
    # Caso débil: SHA-256 sin secreto. Tras cambiar un evento, el atacante recalcula la cadena.
    weak_records = [{"event": "login"}, {"event": "consulta"}, {"event": "logout"}]
    def weak_tag(i, item, previous):
        raw = json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(struct.pack(">Q", i) + raw + previous).digest()
    weak_tags, previous = [], b""
    for i, item in enumerate(weak_records):
        previous = weak_tag(i, item, previous)
        weak_tags.append(previous)
    weak_records[1]["event"] = "cambio_no_autorizado"
    previous = weak_tags[0]
    for i in range(1, len(weak_records)):
        previous = weak_tag(i, weak_records[i], previous)
        weak_tags[i] = previous
    # Verificador débil: recalcula la cadena y compara con las huellas guardadas.
    def weak_check():
        prev = b""
        for i, (item, t) in enumerate(zip(weak_records, weak_tags)):
            prev = weak_tag(i, item, prev)
            if prev != t:
                return False
        return True
    weak_passes = weak_check()  # True = el verificador débil aceptó la falsificación

    # Caso protegido: cambia un registro, pero no conoce la llave HMAC.
    protected = [{"i": r["i"], "registro": copy.deepcopy(r["registro"]), "tag": r["tag"]} for r in records]
    if not protected:
        # Un pequeño conjunto sintético si el usuario aún no generó registros.
        demo_payloads = [{"actor": "usuario-demo", "event": x} for x in ("login", "consulta", "logout")]
        prev = chain.TAG_INICIAL
        for i, payload in enumerate(demo_payloads):
            tag = chain.calcular_tag(HMAC_KEY, i, payload, prev)
            protected.append({"i": i, "registro": payload, "tag": tag.hex()})
            prev = tag
    k = min(1, len(protected)-1)
    protected[k]["registro"]["event"] = "cambio_no_autorizado"
    prev_tag = bytes.fromhex(protected[k-1]["tag"]) if k else chain.TAG_INICIAL
    forged = hashlib.sha256(struct.pack(">Q", k) + chain.serializar_registro(protected[k]["registro"]) + prev_tag)
    protected[k]["tag"] = forged.hexdigest()  # intento de falsificar sin conocer la llave HMAC
    protected_bad = chain.primer_registro_alterado(HMAC_KEY, protected)
    log("Laboratorio de ataque: SHA-256 simple pudo ser recalculado; HMAC rechazó la falsificación.", "warn")
    return {"weak": {"detected": not weak_passes, "result": "Falsificación aceptada" if weak_passes else "Detectada"},
            "protected": {"detected": protected_bad is not None, "result": f"Alteración detectada en el evento {protected_bad+1}" if protected_bad is not None else "No detectada"}}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass
    def send_json(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-store")
        self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/state":
            return self.send_json(200, public_state())
        if path == "/":
            target = BASE / "static" / "index.html"
        elif path.startswith("/static/"):
            target = BASE / path.lstrip("/")
        else:
            return self.send_json(404, {"error": "No encontrado"})
        if not target.resolve().is_relative_to(BASE.resolve()) or not target.is_file():
            return self.send_json(404, {"error": "No encontrado"})
        content = target.read_bytes(); self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8" if target.suffix == ".html" else "text/plain")
        self.send_header("Content-Length", str(len(content))); self.end_headers(); self.wfile.write(content)
    def do_POST(self):
        global last_result
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length) or b"{}")
            path = urlparse(self.path).path
            if path == "/api/add":
                idx = add_record(body.get("kind")); last_result = {"status": "Correcto", "message": f"Registro {idx+1:03d} agregado y protegido."}
            elif path == "/api/verify":
                result = verify_all()
                if result["ok"]:
                    last_result = {"status": "Integridad confirmada", "message": "La cadena y los sellos disponibles pasaron la verificación."}
                    log("Verificación completada: cadena íntegra y firmas válidas.")
                else:
                    last_result = {"status": "Alteración detectada", "message": f"Se detectó un cambio desde el evento {result['bad_index']+1:03d}."}
                    log("Verificación rechazada: se detectó una alteración.", "warn")
            elif path == "/api/seal":
                bid = seal_batch(); last_result = {"status": "Lote sellado", "message": f"Lote {bid:03d} firmado correctamente."}
            elif path == "/api/attack":
                result = attack_demo(); last_result = {"status": "Prueba de ataque terminada", "message": "La versión débil aceptó la falsificación; la versión HMAC la rechazó."}
                return self.send_json(200, {"state": public_state(), "attack": result})
            elif path == "/api/tamper":
                if not records:
                    raise ValueError("Agrega registros antes de simular una alteración.")
                target = min(1, len(records)-1)
                records[target]["registro"]["event"] = "evento_modificado_sin_permiso"
                last_result = {"status": "Alteración simulada", "message": "Se modificó un evento de prueba en memoria. Ejecuta Verificar para detectarlo."}
                log("Simulación: un evento fue modificado sin recalcular su HMAC.", "warn")
            elif path == "/api/reset":
                records.clear(); batches.clear(); logs.clear()
                for path in (LEDGER_PATH, BATCH_PATH):
                    if path.exists(): path.unlink()
                last_result = {"status": "Entorno reiniciado", "message": "La bitácora de demostración está vacía. Las llaves locales se conservaron."}
                log("Entorno de demostración reiniciado. Llaves locales conservadas.")
            else:
                return self.send_json(404, {"error": "No encontrado"})
            return self.send_json(200, {"state": public_state()})
        except ValueError as exc:
            return self.send_json(400, {"error": str(exc), "state": public_state()})
        except Exception:
            return self.send_json(500, {"error": "No fue posible completar la operación.", "state": public_state()})

if __name__ == "__main__":
    print("Bitácora Audit Lab disponible en http://127.0.0.1:8000")
    print("Solo es accesible desde esta computadora. Cierra con Ctrl+C.")
    ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
