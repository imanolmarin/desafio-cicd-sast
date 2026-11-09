from app import create_app


def test_endpoints_basicos():
    client = create_app().test_client()
    assert client.get("/health").status_code == 200
    assert len(client.get("/users?name=ana").get_json()) == 1
    assert client.get("/calc?expr=1%2B1").get_json()["result"] == 2
    assert "Hola" in client.get("/files?name=hola.txt").get_data(as_text=True)
