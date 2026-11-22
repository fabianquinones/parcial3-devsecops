# Parcial 3 OCY1102: Pipeline DevSecOps (Jenkins + Docker + SonarQube + Dependency-Check + ZAP + Grafana)

Usa el **código vulnerable de la guía 3.2.2** (`/hello?name=...`) y su versión corregida.
Guía paso a paso para **Windows** con Jenkins (MSI) y Docker Desktop. El informe para entregar está en [INFORME.md](INFORME.md).

## 0. Requisitos (ya instalados en tu PC)

- Docker Desktop abierto y con *Engine running*.
- Jenkins LTS en `http://localhost:8080` con los *plugins sugeridos* más **Docker** y **Docker Pipeline**.
- Puertos libres: **5000** (app), **9090** (Prometheus), **3000** (Grafana) y **9000** (SonarQube).

## 1. Copiar el proyecto a una ruta corta

Copia la carpeta a `C:\parcial3-devsecops`. Las rutas largas de Windows rompen algunas herramientas.

## 2. Levantar SonarQube (una sola vez)

```powershell
cd C:\parcial3-devsecops; docker compose -p sonar -f docker-compose.sonar.yml up -d
```

1. Espera 1 o 2 minutos y abre `http://localhost:9000`. Entra con `admin` / `admin`; SonarQube te obliga a cambiar la contraseña.
2. Crea un token: avatar (arriba a la derecha) → **My Account → Security → Generate Tokens**, con nombre `jenkins` y tipo *User Token*. Cópialo, porque se muestra una sola vez.

## 3. Crear las credenciales en Jenkins (los secretos no van en el código)

*Manage Jenkins → Credentials → System → Global credentials → Add Credentials*:

| Kind | ID (exacto) | Secret |
|---|---|---|
| Secret text | `grafana-admin-password` | Contraseña que quieras para el usuario `admin` de Grafana |
| Secret text | `sonar-token` | El token de SonarQube del paso 2 |

## 4. Crear el job de Pipeline

**Opción A, con GitHub (necesaria para Dependabot, que exige la pauta)**
1. Sube la carpeta a un repositorio de GitHub. Para el job multibranch, conviene que sea público o usar una credencial de GitHub en Jenkins.
2. En GitHub → *Settings → Code security*, activa **Dependabot alerts** y **Dependabot security updates**. El archivo `.github/dependabot.yml` ya activa las *version updates* para `app_vulnerable/`, `app/` y las imágenes Docker. En unos minutos aparecen los PR en la pestaña *Pull requests* (también los puedes forzar en *Insights → Dependency graph → Dependabot → Check for updates*).
3. En Jenkins: *New Item → **Multibranch Pipeline*** → *Branch Sources: Git*, con la URL del repo y Script Path `Jenkinsfile`, y en *Scan Multibranch Pipeline Triggers* marca un intervalo (por ejemplo, 5 minutos). Jenkins construye `main` y **cada rama que abra Dependabot**. Si la rama actualiza `app_vulnerable/`, el pipeline analiza esa versión automáticamente.
4. Si prefieres un job simple: *New Item → Pipeline → Pipeline script from SCM → Git*, con rama `main`.

**Opción B, sin Git**
1. *New Item → Pipeline → Pipeline script* y pega el contenido de `Jenkinsfile`.
2. En el `Jenkinsfile` pegado, cambia `defaultValue: ''` del parámetro `SOURCE_DIR` por `'C:\\parcial3-devsecops'`.

## 5. Ejecutar

La primera vez usa **Build Now**. Esa ejecución carga los parámetros; desde la siguiente aparece **Build with Parameters**.

| Build | APP_VERSION | ZAP_SCAN | SIMULAR_ATAQUE | Resultado esperado |
|---|---|---|---|---|
| 1 | `vulnerable` | `full` | no | **UNSTABLE** (amarillo): pruebas fallidas, Bandit, SonarQube, CVE en dependencias y XSS en ZAP |
| 2 | `corregida` | `full` | **sí** | **SUCCESS** (verde): todo en 0 y alertas de incidente en Grafana |

`RUN_SONARQUBE` y `RUN_DEPENDENCY_CHECK` vienen activados. Si SonarQube está apagado, la etapa se marca "NO EJECUTADO" pero no bloquea el pipeline.

**Validar los PR de Dependabot (evidencia de la tarea "Gestión de Dependencias"):** Dependabot abre dos PR sobre el código vulnerable: uno de **pip** (`dependabot/pip/app_vulnerable/...`) y otro de la **imagen Docker** (`dependabot/docker/app_vulnerable/...`). Jenkins construye cada rama. Resultado esperado, comparado con `main` (pip-audit 17 y Dependency-Check 28):

| Rama | pip-audit | Dependency-Check | Pruebas |
|---|---|---|---|
| PR de pip (#3) | **0** | 12 (solo de la imagen base `python:3.10-slim`: certifi, pip, wheel…) | Las funcionales pasan |
| PR de Docker (#2, `python:3.15-slim`) | 17 | 16 (Flask, Werkzeug y Jinja2) | La app no arranca: Werkzeug 2.2.2 no es compatible con Python 3.14+ |

Las pruebas de seguridad siguen fallando por el XSS y el debug, que son del código y no de las dependencias (eso se corrige en `app/`). El PR de pip se integró porque no agrega CVE nuevas; el de Docker queda en espera porque el pipeline lo bloqueó.

## 6. Dónde ver los resultados

- **Build Artifacts**: `TRAZABILIDAD.md`, `zap-report.html`, `dependency-check-report.html`, `bandit.html`, `sonarqube.json`, `pip-audit.md`, `sbom-cyclonedx.json`, `app-logs.txt` y `SHA256SUMS.txt`.
- **Test Result**: detalle de las 13 pruebas.
- **SonarQube**: `http://localhost:9000` → proyecto *SecureDev - Parcial 3*.
- **Grafana**: `http://localhost:3000` (usuario `admin`) → *Dashboards → SecureDev → SecureDev - Monitorización de seguridad*.
- **Prometheus**: `http://localhost:9090/alerts`.
- **App**: `http://localhost:5000/hello?name=TEST`. Para la evidencia del XSS (solo con la versión vulnerable desplegada): `http://localhost:5000/hello?name=<script>alert(1)</script>`.

Para simular un ataque desde tu PC (solo contra esta app de laboratorio):

```powershell
python C:\parcial3-devsecops\scripts\simular_ataque.py http://localhost:5000 50
```

## 7. Problemas comunes

| Problema | Solución |
|---|---|
| `'sh' no se reconoce...` | El Jenkinsfile ya usa `bat` en Windows. Revisa que estés usando este archivo y no el ejemplo de la guía |
| `docker: no se reconoce` o error con `docker_engine` dentro de Jenkins | Abre Docker Desktop. Si sigue fallando, en `services.msc` → *Jenkins* → *Iniciar sesión* → *Esta cuenta*, pon tu usuario de Windows y reinicia el servicio |
| `Could not find credentials entry with ID 'grafana-admin-password'` | Falta el paso 3, o el ID está mal escrito |
| SonarQube "NO EJECUTADO" | Revisa que esté arriba (`docker ps` debe mostrar `securedev-sonarqube`) y que exista la credencial `sonar-token` |
| Dependency-Check falla al actualizar | Usa el caché público de la base NVD (`NVD_DATAFEED` en el Jenkinsfile). Revisa tu conexión a Internet |
| La etapa de dependencias marca CVE en la versión **corregida** | Salieron CVE nuevas. Sube el paquete a la versión corregida que indica el reporte en `app/requirements.txt` y documéntalo (sección 6 del informe) |
| Puerto ocupado | Cambia el puerto de la izquierda en `docker-compose.yml` (por ejemplo `"5001:5000"`) |

Para apagar el entorno:

```powershell
$env:GRAFANA_PASSWORD='x'; docker compose -p parcial3 -f C:\parcial3-devsecops\docker-compose.yml down; docker compose -p sonar -f C:\parcial3-devsecops\docker-compose.sonar.yml down
```

## 8. Probar sin Jenkins (opcional)

```powershell
cd C:\parcial3-devsecops; python -m venv .venv; .\.venv\Scripts\pip install -r app\requirements.txt pytest; $env:APP_DIR='app'; .\.venv\Scripts\python -m pytest tests -v
```
