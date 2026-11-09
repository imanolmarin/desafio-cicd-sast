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


# ── CWE-22: path traversal en /files ────────────────────────────────────────
@pytest.mark.parametrize(
    "name",
    ["../app/db.py", "../../../../etc/passwd", "/etc/passwd", "..%2Fapp%2Fdb.py", "sub/../../app/db.py", "", "hola.txt\x00.png"],
)
def test_files_no_sale_del_directorio_base(client, name):
    res = client.get("/files", query_string={"name": name})
    assert res.status_code in (400, 404)
    assert "sqlite3" not in res.get_data(as_text=True)
    assert "root:" not in res.get_data(as_text=True)


def test_files_inexistente_da_404(client):
    assert client.get("/files?name=noexiste.txt").status_code == 404


def test_files_legitimo(client):
    assert "Hola" in client.get("/files?name=hola.txt").get_data(as_text=True)


# ── CWE-95: eval en /calc ───────────────────────────────────────────────────
@pytest.mark.parametrize(
    "expr",
    [
        "__import__('os').popen('id').read()",
        "open('/etc/passwd').read()",
        "().__class__.__bases__[0].__subclasses__()",
        "(lambda: 1)()",
        "a + 1",
        "'a' * 10",
        "9**9**9**9",
        "10**100",
        "1/0",
        "1" * 200,
        "",
    ],
)
def test_calc_rechaza_codigo_y_abusos(client, expr):
    res = client.get("/calc", query_string={"expr": expr})
    assert res.status_code == 400


@pytest.mark.parametrize(
    "expr,esperado",
    [("1+1", 2), ("2*(3+4)", 14), ("-5+2", -3), ("7/2", 3.5), ("7//2", 3), ("2**10", 1024), ("10%3", 1)],
)
def test_calc_aritmetica_valida(client, expr, esperado):
    assert client.get("/calc", query_string={"expr": expr}).get_json()["result"] == esperado
