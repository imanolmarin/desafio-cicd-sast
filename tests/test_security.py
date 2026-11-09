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


# ── CWE-78: command injection en /ping ──────────────────────────────────────
@pytest.mark.parametrize(
    "host",
    ["127.0.0.1;id", "localhost && whoami", "$(id)", "`id`", "a|b", "-f", "x y", "", "a" * 300],
)
def test_ping_rechaza_hosts_invalidos(client, host, monkeypatch):
    llamadas = []
    monkeypatch.setattr("app.routes.subprocess.run", lambda *a, **k: llamadas.append(a))
    res = client.get("/ping", query_string={"host": host})
    assert res.status_code == 400
    assert llamadas == []  # nunca se llega a ejecutar nada


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1", "example.com", "mi-host.local"])
def test_ping_usa_argv_sin_shell(client, host, monkeypatch):
    capturado = {}

    class Resultado:
        stdout = "ok"

    def falso_run(args, **kwargs):
        capturado["args"], capturado["kwargs"] = args, kwargs
        return Resultado()

    monkeypatch.setattr("app.routes.subprocess.run", falso_run)
    res = client.get("/ping", query_string={"host": host})
    assert res.status_code == 200
    assert capturado["args"] == ["ping", "-c", "1", "-W", "2", host]
    assert capturado["kwargs"].get("shell", False) is False
