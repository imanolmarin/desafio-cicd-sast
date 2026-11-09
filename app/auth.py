import base64
import hashlib
import hmac
import secrets

# CORREGIDO (A02 Cryptographic Failures / CWE-327 y CWE-916): MD5 -> scrypt.
# scrypt es una KDF para contrasenas: lleva sal aleatoria por usuario (el mismo
# password da hashes distintos, no sirven tablas precalculadas) y un costo de
# CPU/memoria configurable que hace caro el ataque por fuerza bruta.
# Parametros recomendados por OWASP para scrypt: N=2^17, r=8, p=1.
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
_MAXMEM = 256 * 1024 * 1024


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def hash_password(password: str) -> str:
    sal = secrets.token_bytes(16)
    dk = hashlib.scrypt(
        password.encode(), salt=sal, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        dklen=SCRYPT_DKLEN, maxmem=_MAXMEM,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(sal)}${_b64(dk)}"


def verify_password(password: str, almacenado: str) -> bool:
    try:
        algoritmo, n, r, p, sal_b64, dk_b64 = almacenado.split("$")
        if algoritmo != "scrypt":
            return False
        esperado = base64.b64decode(dk_b64)
        calculado = hashlib.scrypt(
            password.encode(), salt=base64.b64decode(sal_b64), n=int(n), r=int(r),
            p=int(p), dklen=len(esperado), maxmem=_MAXMEM,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(calculado, esperado)
