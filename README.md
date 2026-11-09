# Microservicio Python (Flask)

> Repositorio del desafío **SAST en CI/CD**, variante **Python**. La consigna completa está en [`CONSIGNA.md`](CONSIGNA.md) (la app Java del enunciado no se incluye: este repo es solo el de Python, por eso el pipeline queda en la raíz).

> ⚠️ Vulnerable a propósito. Solo para practicar SAST; no lo expongas a internet.

API Flask con SQLite en memoria. Escucha en el puerto **5000**.

## Requisitos
- Python 3.12+ (o Docker)

## Levantarlo con Python

```bash
cd desafio-cicd-sast
python3 -m venv .venv
source .venv/bin/activate          # en Windows: .venv\Scripts\activate
pip install -r requirements.txt
python wsgi.py
```

## Levantarlo con Docker

```bash
cd desafio-cicd-sast
docker build -t desafio-sast-python .
docker run --rm -p 5000:5000 desafio-sast-python
```

## Probarlo

```bash
curl http://localhost:5000/health
curl "http://localhost:5000/users?name=ana"
curl "http://localhost:5000/search?q=hola"
curl "http://localhost:5000/files?name=hola.txt"
curl "http://localhost:5000/calc?expr=1%2B1"
curl "http://localhost:5000/ping?host=localhost"
curl -X POST http://localhost:5000/register -H "Content-Type: application/json" -d '{"password":"secreto"}'
```

## Tests

```bash
pytest -q
```

## Endpoints

| Endpoint | Descripción |
|---|---|
| `GET /health` | Estado |
| `GET /users?name=` | Busca usuarios (SQLite) |
| `GET /search?q=` | Devuelve HTML con el término |
| `GET /ping?host=` | Ejecuta `ping` |
| `GET /files?name=` | Lee un archivo de `files/` |
| `GET /calc?expr=` | Evalúa una expresión |
| `POST /register` | Devuelve el hash de la contraseña |

## Problemas comunes
- **Puerto 5000 ocupado** (en macOS lo usa AirPlay): cambia el puerto en `wsgi.py`, o con Docker usa `-p 5001:5000`.
- **`ping` no existe** dentro del contenedor `slim`: el endpoint devolverá vacío; no afecta al ejercicio de SAST.
