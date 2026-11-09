import hashlib


# VULNERABLE (A02 Cryptographic Failures / CWE-327): MD5 para contraseñas
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
