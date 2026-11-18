"""Construcción de raíz Merkle con separación de dominios."""
import hashlib

def calcular_raiz_merkle(hojas: list[bytes]) -> bytes:
    if not hojas:
        raise ValueError("La lista de hojas no puede estar vacía.")
    nivel = [hashlib.sha256(b"\x00" + h).digest() for h in hojas]
    while len(nivel) > 1:
        siguiente = []
        for j in range(0, len(nivel) - 1, 2):
            siguiente.append(hashlib.sha256(b"\x01" + nivel[j] + nivel[j + 1]).digest())
        if len(nivel) % 2:
            siguiente.append(nivel[-1])
        nivel = siguiente
    return nivel[0]
