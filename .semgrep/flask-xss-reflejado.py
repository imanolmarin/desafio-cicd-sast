# Casos de prueba de la regla (semgrep --test .semgrep/)
from flask import Blueprint, request
from markupsafe import escape

bp = Blueprint("t", __name__)


@bp.get("/a")
def vulnerable():
    q = request.args.get("q", "")
    # ruleid: flask-xss-reflejado-por-concatenacion
    return "<h1>Resultados para: " + q + "</h1>"


@bp.get("/c")
def escapado():
    q = request.args.get("q", "")
    # ok: flask-xss-reflejado-por-concatenacion
    return "<h1>Resultados para: " + str(escape(q)) + "</h1>"


@bp.get("/d")
def texto_plano_sin_html():
    q = request.args.get("q", "")
    # ok: flask-xss-reflejado-por-concatenacion
    return "resultado: " + q
