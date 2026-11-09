"""Tests de regresion de seguridad: cada ataque del desafio tiene que quedar
bloqueado o neutralizado despues de su correccion."""
import pytest

from app import create_app


@pytest.fixture()
def client():
    return create_app().test_client()


# ── CWE-89: SQL injection en /users ─────────────────────────────────────────
def test_users_sql_injection_no_devuelve_todos(client):
    res = client.get("/users", query_string={"name": "x' OR '1'='1"})
    assert res.status_code == 200
    assert res.get_json() == []


def test_users_busqueda_normal_sigue_funcionando(client):
    assert [u["name"] for u in client.get("/users?name=beto").get_json()] == ["beto"]


# ── CWE-79: XSS reflejado en /search ────────────────────────────────────────
def test_search_escapa_html(client):
    res = client.get("/search", query_string={"q": "<script>alert(1)</script>"})
    cuerpo = res.get_data(as_text=True)
    assert "<script>" not in cuerpo
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in cuerpo
    assert res.headers["Content-Type"].startswith("text/html")
    assert res.headers["X-Content-Type-Options"] == "nosniff"


def test_search_texto_normal(client):
    assert "Resultados para: hola" in client.get("/search?q=hola").get_data(as_text=True)
