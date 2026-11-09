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
