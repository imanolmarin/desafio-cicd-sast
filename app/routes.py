import ipaddress
import os
import re
import shutil
# subprocess se usa solo con lista de argv y host validado (ver /ping).
import subprocess  # nosec B404

from flask import Blueprint, jsonify, request
from markupsafe import escape

from .auth import hash_password
from .calc import ExpresionInvalida, evaluar
from .db import buscar_usuarios_por_nombre

bp = Blueprint("main", __name__)
BASE_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "files"))
_NOMBRE_ARCHIVO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


@bp.get("/health")
def health():
    return jsonify(status="ok")


# CORREGIDO (CWE-89): consulta parametrizada (en db.py). El valor viaja
# separado de la sentencia SQL: una comilla en "name" es un caracter mas.
@bp.get("/users")
def users():
    name = request.args.get("name", "")
    rows = buscar_usuarios_por_nombre(name)
    return jsonify([{"id": r[0], "name": r[1], "email": r[2]} for r in rows])


# CORREGIDO (CWE-79): se codifica la salida para el contexto HTML. "<" y ">"
# llegan al navegador como &lt; y &gt;: se muestran, no se interpretan.
@bp.get("/search")
def search():
    q = request.args.get("q", "")
    html = "<h1>Resultados para: " + str(escape(q)) + "</h1>"
    return html, 200, {
        "Content-Type": "text/html; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'",
    }


# Ruta absoluta del binario (evita depender del PATH al ejecutar).
PING = shutil.which("ping") or "/usr/bin/ping"

# Hostname RFC 1123: etiquetas de letras, digitos y "-", separadas por ".",
# sin empezar ni terminar con "-". Nada de espacios ni metacaracteres de shell.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def _host_valido(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.fullmatch(host))


# CORREGIDO (CWE-78): sin shell. El host se valida con una allowlist (IP o
# hostname RFC 1123) y se pasa como un elemento de argv: aunque tuviera ";" o
# "$( )", ping lo recibiria como un unico argumento y nadie lo interpretaria.
@bp.get("/ping")
def ping():
    host = request.args.get("host", "localhost")
    if not _host_valido(host):
        return jsonify(error="host invalido"), 400
    # argv fijo + host validado, sin shell
    out = subprocess.run(  # nosec B603
        [PING, "-c", "1", "-W", "2", host],
        capture_output=True, text=True, timeout=5, check=False,
    )
    return out.stdout, 200, {"Content-Type": "text/plain"}


# CORREGIDO (CWE-22): dos controles independientes.
#  1. Allowlist del nombre: solo un nombre de archivo simple, sin barras
#     y sin empezar con "." (descarta "..", rutas absolutas y archivos ocultos).
#  2. Se resuelve la ruta real (symlinks incluidos) y se exige que siga dentro
#     de BASE_DIR. Si el control 1 tuviera un hueco, este lo frena igual.
@bp.get("/files")
def files():
    name = request.args.get("name", "hola.txt")
    if not _NOMBRE_ARCHIVO_RE.fullmatch(name):
        return jsonify(error="nombre de archivo invalido"), 400
    ruta = os.path.realpath(os.path.join(BASE_DIR, name))
    if os.path.commonpath([ruta, BASE_DIR]) != BASE_DIR or not os.path.isfile(ruta):
        return jsonify(error="archivo no encontrado"), 404
    with open(ruta, encoding="utf-8") as f:
        return f.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}


# CORREGIDO (CWE-95): no se evalua codigo. app/calc.py parsea la expresion y
# solo acepta numeros y operadores aritmeticos (allowlist de nodos del AST).
@bp.get("/calc")
def calc():
    try:
        return jsonify(result=evaluar(request.args.get("expr", "0")))
    except ExpresionInvalida:
        return jsonify(error="expresion invalida"), 400


@bp.post("/register")
def register():
    password = (request.get_json(silent=True) or {}).get("password")
    if not password:
        return jsonify(error="password requerido"), 400
    return jsonify(hash=hash_password(password))
