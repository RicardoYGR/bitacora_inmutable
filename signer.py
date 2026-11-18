"""Funciones Ed25519 basadas en el módulo signer.py del equipo."""
import struct
from cryptography.hazmat.primitives.asymmetric import ed25519

def generar_par_llaves_ed25519():
    llave_privada = ed25519.Ed25519PrivateKey.generate()
    return llave_privada, llave_privada.public_key()

def empaquetar_mensaje_lote(id_lote: int, num_registros: int, raiz_merkle: bytes) -> bytes:
    return struct.pack(">QI", id_lote, num_registros) + raiz_merkle

def firmar_lote(llave_privada, mensaje_bytes: bytes) -> bytes:
    return llave_privada.sign(mensaje_bytes)

def verificar_firma_lote(llave_publica, firma: bytes, mensaje_bytes: bytes) -> bool:
    try:
        llave_publica.verify(firma, mensaje_bytes)
        return True
    except Exception:
        return False
