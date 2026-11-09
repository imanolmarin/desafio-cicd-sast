# Desafío — SAST en GitLab CI/CD (Python y Java)

> ⚠️ **Este código es vulnerable a propósito.** Sirve únicamente para practicar. No lo despliegues ni lo expongas a internet.

Práctico de refuerzo de la clase 2. Es el mismo ejercicio, pero sobre aplicaciones distintas para que practiques por tu cuenta.

## Objetivo

Incorporar **SAST** (*Static Application Security Testing*) a un pipeline de GitLab CI/CD, interpretar el reporte y corregir vulnerabilidades en el código.

## Modalidad

Se puede hacer **de forma individual o en grupo de 2 o 3 personas**.

- Repartan el trabajo, pero que **todos** participen del análisis del Nivel 2 y del Merge Request.
- Cada integrante debe tener **commits propios** en el repositorio (no vale que uno solo haga todo).
- En el grupo de 3, el MR tiene que incluir las correcciones de al menos una vulnerabilidad por persona.
- Indiquen los integrantes en la descripción del MR.

## Elegí tu lenguaje

| Carpeta | Stack | Puerto |
|---|---|---|
| [`python/`](python/) | Flask + SQLite | 5000 |
| [`java/`](java/) | Spring Boot 3 + H2 + Maven | 8080 |

Hacé **uno** (o los dos para ver cómo cambia lo que detecta cada analizador). Cada carpeta es un proyecto independiente con su propio `.gitlab-ci.yml`, que hoy solo tiene **build y tests**, sin ningún análisis de seguridad.

## Preparación

1. Hacé un **fork** (o copiá) del proyecto a tu grupo de GitLab. Si es un repositorio por lenguaje, el `.gitlab-ci.yml` tiene que quedar en la raíz.
2. Creá una rama `sast`. **No trabajes sobre `main`.**
3. Confirmá que el pipeline actual pasa en verde.

Para correrlo localmente (opcional):

```bash
# Python (3.12+)
cd python && python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/pytest -q && .venv/bin/python wsgi.py     # http://localhost:5000/health

# Java (JDK 21 + Maven)
cd java && mvn test && mvn spring-boot:run          # http://localhost:8080/health
```

---

## Nivel 1 — Agregar SAST al pipeline

**Meta:** que aparezca un job de SAST en el pipeline.

Agregá al `.gitlab-ci.yml` el template oficial de GitLab:

```yaml
include:
  - template: Security/SAST.gitlab-ci.yml
```

GitLab detecta los lenguajes del repositorio y activa solo el analizador que corresponde (Semgrep para Python; Semgrep y SpotBugs para Java, según la versión de GitLab).

**Criterio de aceptación**
- [ ] El pipeline incluye al menos un job de SAST en el stage `test`.
- [ ] El job termina y publica el artifact `gl-sast-report.json`.

> 💡 Si el job falla al descargar la imagen del analizador, avisá al docente: puede ser un tema de red del runner.

---

## Nivel 2 — Leer el reporte y clasificar hallazgos

**Meta:** entender qué encontró la herramienta y qué no.

1. Descargá `gl-sast-report.json` desde los artifacts del job.
2. Listá los hallazgos (local, con `jq`):

   ```bash
   jq '.vulnerabilities[] | {name, severity, file: .location.file, line: .location.start_line, cwe: .identifiers[0].value}' gl-sast-report.json
   ```

3. Completá una tabla por cada hallazgo:

   | # | Archivo:línea | Tipo (CWE) | Severidad | ¿Verdadero positivo? | Justificación |
   |---|---|---|---|---|---|

   Criterio: ¿puede un atacante **controlar el dato** que llega a la función riesgosa?

4. Recorré el código a mano y anotá si hay vulnerabilidades que el reporte **no** marcó (falsos negativos).

**Criterio de aceptación**
- [ ] Tabla completa con todos los hallazgos.
- [ ] Al menos un análisis razonado de verdadero vs. falso positivo.
- [ ] Al menos una vulnerabilidad no detectada, identificada por revisión manual.

---

## Nivel 3 — Corregir vulnerabilidades

**Meta:** corregir **al menos 3** vulnerabilidades y comprobar que el pipeline lo refleja.

Las aplicaciones tienen las mismas 6 categorías de vulnerabilidad, cada una en su endpoint:

| Endpoint | Categoría | CWE | OWASP Top 10 (2021) |
|---|---|---|---|
| `GET /users?name=` | Inyección SQL | CWE-89 | A03 |
| `GET /search?q=` | XSS reflejado | CWE-79 | A03 |
| `GET /ping?host=` | Inyección de comandos | CWE-78 | A03 |
| `GET /files?name=` | Path traversal | CWE-22 | A01 |
| `GET /calc?expr=` | Evaluación de código (`eval` en Python, SpEL en Java) | CWE-95 / CWE-917 | A03 |
| `POST /register` | Hash débil (MD5) | CWE-327 | A02 |

Pasos:

1. Elegí una vulnerabilidad de tu tabla del Nivel 2.
2. Corregila. **Un commit por corrección** con mensaje claro (`fix: evita SQL injection en /users`).
3. Verificá que los tests sigan pasando.
4. Hacé push y compará el nuevo `gl-sast-report.json` con el anterior: ese hallazgo tiene que haber desaparecido.
5. Repetí hasta completar 3.
6. Abrí un **Merge Request** de `sast` hacia `main` explicando cada corrección.

### Pistas de remediación

| Categoría | Idea general |
|---|---|
| SQL injection | Consultas **parametrizadas** (`?` en `sqlite3`; `PreparedStatement` en Java). El dato viaja separado de la sentencia. |
| XSS | Escapar la salida (`markupsafe.escape` / `html.escape`; `HtmlUtils.htmlEscape` en Spring) o devolver texto plano/JSON. |
| Command injection | Evitar la shell. Pasar argumentos como **lista** (`subprocess.run([...])`, `ProcessBuilder` sin `sh -c`) y validar el valor con una lista blanca/regex estricta. |
| Path traversal | Resolver la ruta y comprobar que sigue dentro del directorio base (`os.path.realpath` / `Path.normalize().startsWith(base)`). |
| Evaluación de código | No evaluar input. Parsear número/operador permitidos, o usar un evaluador acotado (en Spring, `SimpleEvaluationContext`). |
| Hash débil | Usar un algoritmo de contraseñas con sal y costo: `hashlib.scrypt` / `bcrypt` / Argon2; en Java, BCrypt o Argon2 (Spring Security `Argon2PasswordEncoder`). |

**Criterio de aceptación**
- [ ] Al menos 3 vulnerabilidades corregidas, cada una en su propio commit.
- [ ] Pipeline del MR en verde (tests + SAST).
- [ ] El reporte final tiene al menos 3 hallazgos menos que el inicial.
- [ ] El MR explica cada corrección y qué hallazgo resolvía.

---

## Checklist de entrega

- [ ] `.gitlab-ci.yml` con el `include` de SAST
- [ ] Tabla de clasificación de hallazgos (Nivel 2) en el MR o en `mi-analisis.md`
- [ ] 3+ correcciones con commits separados
- [ ] Pipeline en verde en el MR
- [ ] Integrantes del grupo (2 o 3) indicados en el MR, con commits de cada uno
- [ ] Captura del reporte antes/después
- [ ] **Secret detection** agregado al pipeline (ver abajo)

### Secret detection

Además de SAST, agregá el análisis de secretos de GitLab, que busca credenciales, tokens y claves que se hayan subido al repositorio:

```yaml
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
```

Para entregar:
- [ ] El pipeline incluye el job `secret_detection` y termina correctamente.
- [ ] El job publica el artifact `gl-secret-detection-report.json`.
- [ ] Probá que funciona: en una rama aparte, agregá una credencial **falsa** (por ejemplo `AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"` en un archivo) y comprobá que el job la reporta. Después borrala y anotá en el MR qué pasó.

> ⚠️ Nunca uses credenciales reales para esta prueba. Y tené presente que un secreto subido queda en el historial de git aunque lo borres en un commit posterior: la solución real es **revocarlo/rotarlo**.

## Desafíos extra (opcionales)

- Hacer que el job de SAST **falle el pipeline** en merge requests (`allow_failure: false` sobre el job, o una regla propia).
- Excluir rutas de tests con `SAST_EXCLUDED_PATHS`.
- Escribir una **regla propia de Semgrep** para un patrón de tu proyecto.
- Resolver el mismo ejercicio en el otro lenguaje y comparar los reportes.

## Referencias

- [GitLab SAST](https://docs.gitlab.com/ee/user/application_security/sast/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Semgrep](https://semgrep.dev/docs/)
