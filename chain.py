"""Cadena de auditoría HMAC-SHA-256. Adaptada del módulo del equipo."""
import hashlib, hmac, json, struct
TAG_INICIAL = bytes(32)

def serializar_registro(registro: dict) -> bytes:
    return json.dumps(registro, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def calcular_tag(llave: bytes, i: int, registro: dict, tag_prev: bytes) -> bytes:
    datos = struct.pack(">Q", i) + serializar_registro(registro) + tag_prev
    return hmac.new(llave, datos, hashlib.sha256).digest()

def primer_registro_alterado(llave: bytes, entradas: list[dict]):
    tag_prev = TAG_INICIAL
    for posicion, e in enumerate(entradas):
        try:
            if e["i"] != posicion:
                return posicion
            esperado = calcular_tag(llave, posicion, e["registro"], tag_prev)
            if not hmac.compare_digest(esperado, bytes.fromhex(e["tag"])):
                return posicion
            tag_prev = esperado
        except (KeyError, ValueError, TypeError):
            return posicion
    return None
