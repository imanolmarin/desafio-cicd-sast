import os
import subprocess

from flask import Blueprint, jsonify, request
from markupsafe import escape

from .auth import hash_password
from .db import get_conn

bp = Blueprint("main", __name__)
BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "files")


@bp.get("/health")
def health():
    return jsonify(status="ok")


# CORREGIDO (CWE-89): consulta parametrizada. El valor viaja separado de la
# sentencia SQL, asi que una comilla en "name" es un caracter mas, no codigo.
@bp.get("/users")
def users():
    name = request.args.get("name", "")
    rows = get_conn().execute(
        "SELECT id, name, email FROM users WHERE name = ?", (name,)
    ).fetchall()
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


# VULNERABLE (A03 Injection / CWE-78): command injection
@bp.get("/ping")
def ping():
    host = request.args.get("host", "localhost")
    out = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True, text=True)
    return out.stdout, 200, {"Content-Type": "text/plain"}


# VULNERABLE (A01 Broken Access Control / CWE-22): path traversal
@bp.get("/files")
def files():
    name = request.args.get("name", "hola.txt")
    with open(os.path.join(BASE_DIR, name)) as f:
        return f.read(), 200, {"Content-Type": "text/plain"}


# VULNERABLE (A03 Injection / CWE-95): eval sobre input del usuario
@bp.get("/calc")
def calc():
    return jsonify(result=eval(request.args.get("expr", "0")))


@bp.post("/register")
def register():
    password = (request.get_json(silent=True) or {}).get("password")
    if not password:
        return jsonify(error="password requerido"), 400
    return jsonify(hash=hash_password(password))
