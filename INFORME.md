# Informe técnico: Pipeline DevSecOps para SecureDev

**Evaluación Parcial N°3 – Explotación y Mitigación de Vulnerabilidades Web**
**Asignatura:** OCY1102 Ciberseguridad en Desarrollo
**Estudiante:** [COMPLETAR] | **Sección:** [COMPLETAR] | **Fecha:** [COMPLETAR]

> Los resultados de este informe se obtuvieron ejecutando, con Docker, exactamente los mismos comandos del `Jenkinsfile` sobre ambas versiones del código (20-11-2026). Las marcas **[COMPLETAR]** y **[CAPTURA]** indican datos y capturas que salen de tu ejecución en Jenkins (número de build, pantallazos).

---

## 1. Contexto y objetivo

Una auditoría interna de SecureDev encontró cuatro debilidades:

1. Las pruebas de seguridad no están automatizadas en el pipeline.
2. La gestión de dependencias es deficiente.
3. La documentación y la trazabilidad no alcanzan para una auditoría.
4. La monitorización de producción es inadecuada.

**Objetivo:** implementar un pipeline CI/CD en **Jenkins** con **Docker** que integre seguridad en todas las etapas del SDLC. Se usó el código vulnerable entregado en la guía 3.2.2 para identificar, explotar y mitigar sus vulnerabilidades, dejando evidencia auditable de cada actividad.

| Indicador de logro | Dónde se aborda |
|---|---|
| IL 3.2: Pruebas de seguridad automatizadas, implementación continua y monitorización | Secciones 4, 5, 7 y 9 |
| IL 3.3: Gestión de dependencias y parcheo | Sección 8 |
| IL 3.4: Documentación y trazabilidad para auditorías | Secciones 5, 10 y anexos |

## 2. Código vulnerable analizado (guía 3.2.2)

```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/hello')
def hello():
    name = request.args.get('name')
    return f"Hello, {name}!"

if __name__ == '__main__':
    app.run(debug=True)
```

Se conserva **sin cambios** en `app_vulnerable/app.py`. Como la guía no entrega `requirements.txt`, el entorno original se reconstruyó con versiones antiguas de Flask y sus dependencias (`app_vulnerable/requirements.txt`). La versión corregida está en `app/`.

---

## 3. Herramientas utilizadas

| Herramienta | Versión | Uso en el pipeline |
|---|---|---|
| Jenkins LTS | 2.580.2 | Orquestador CI/CD (pipeline declarativo en `Jenkinsfile`) |
| Docker / Docker Compose | 29.9.3 | Imágenes, ejecución aislada de cada herramienta y despliegue |
| pytest + pytest-cov | 8.3.3 / 6.0.0 | Pruebas unitarias y de seguridad, con medición de cobertura |
| Bandit | 1.8.0 | SAST específico para Python |
| SonarQube Community | 26.10 (scanner 12.3.1) | Análisis estático de calidad y seguridad, con Quality Gate |
| pip-audit | 2.7.3 | SCA: CVE de las dependencias declaradas y SBOM CycloneDX |
| OWASP Dependency-Check | 13.0.0 | SCA: CVE de **todos** los paquetes instalados en la imagen |
| Dependabot | — | Pull requests semanales con actualizaciones (pip e imagen base) |
| OWASP ZAP | stable (2.17) | DAST: escaneo activo de la app desplegada |
| Prometheus / Grafana | 2.55.1 / 11.3.0 | Métricas, reglas de detección de incidentes y dashboard |
| Git / GitHub | 2.56.1 | Control de versiones y trazabilidad de cambios |

---

## 4. Diseño del pipeline CI/CD

Las etapas siguen la estructura de la guía 3.2.2 (Build, Test, Analyze, Security Test, Deploy) y agregan las que pide el parcial: Security Gate, Monitor y Documentación.

| Etapa | Qué hace | Evidencia generada |
|---|---|---|
| Checkout | Obtiene el código desde Git y registra el commit | Commit en `TRAZABILIDAD.md` |
| Build | `docker build` multi-stage; etiqueta la imagen con build, versión y commit | ID de imagen y etiquetas |
| Test | 13 pruebas (2 funcionales y 11 de seguridad) con cobertura | `junit.xml`, `coverage.xml` |
| Analyze: SAST (Bandit) | Análisis estático Python | `bandit.json/.html` |
| Analyze: SonarQube | Calidad, seguridad, cobertura y Quality Gate | `sonarqube.json` y web de SonarQube |
| Security Test: Dependencias (pip-audit) | CVE de `requirements.txt` y SBOM | `pip-audit.json/.md`, `sbom-cyclonedx.json` |
| Security Test: OWASP Dependency-Check | CVE de los paquetes **instalados** en la imagen (incluye los de la imagen base) | `dependency-check-report.html/.json` |
| Security Gate | Si la versión corregida tiene hallazgos, **bloquea el despliegue** | Estado en `pipeline-estado.txt` |
| Deploy | `docker compose up` (app, Prometheus y Grafana) con secretos desde Jenkins Credentials | Contenedores corriendo |
| Security Test: DAST (OWASP ZAP) | Spider y escaneo activo sobre `/hello?name=TEST` | `zap-report.html/.json/.md` |
| Simulación de incidente (opcional) | Tráfico malicioso controlado | Alertas en Prometheus y Grafana |
| Monitor | Consulta targets y alertas a Prometheus y guarda los logs | `monitor-*.json`, `app-logs.txt` |
| Documentación y trazabilidad | Consolida los resultados con hashes de integridad | `TRAZABILIDAD.md`, `SHA256SUMS.txt` |

**Decisiones de diseño:**

- Cada herramienta corre en su propio contenedor, así el pipeline es reproducible.
- Los controles marcan el build como **UNSTABLE** sin detenerlo, para que se generen todos los reportes. El **Security Gate** convierte esos hallazgos en un bloqueo (FAILURE) cuando se intenta desplegar la versión corregida.
- La versión vulnerable sí se despliega, solo en el laboratorio y registrado como excepción, porque ZAP necesita la aplicación corriendo.
- El trigger `cron('H 6 * * 1')` repite el pipeline cada lunes para detectar CVE publicadas después del último cambio.

[CAPTURA] Stage View de Jenkins con un build vulnerable (amarillo) y uno corregido (verde).

---

## 5. Revisiones de seguridad y vulnerabilidades

### 5.1 Metodología

1. Revisión manual del código guiada por OWASP Top 10 2021.
2. SAST con Bandit y SonarQube.
3. Pruebas de seguridad automatizadas: cada vulnerabilidad tiene una prueba que falla en el código vulnerable y pasa en el corregido.
4. SCA con pip-audit y Dependency-Check.
5. DAST con OWASP ZAP.
6. Monitorización en operación.

### 5.2 Vulnerabilidades identificadas

| ID | Vulnerabilidad | OWASP 2021 | CWE | Severidad | Detectada por |
|---|---|---|---|---|---|
| VULN-01 | XSS reflejado en `/hello?name=` | A03 Injection | CWE-79 | **Alta** | Revisión, pytest, **ZAP** (XSS Reflected y DOM, riesgo Alto) |
| VULN-02 | Modo debug activo (debugger de Werkzeug permite ejecutar código) | A05 Security Misconfiguration | CWE-489 / CWE-94 | **Crítica** | **Bandit B201 (High)**, **SonarQube S4507**, pytest |
| VULN-03 | Entrada sin validar y sin manejo de nulos (`Hello, None!`) | A03 Injection | CWE-20 | Media | Revisión, pytest |
| VULN-04 | Faltan cabeceras de seguridad HTTP | A05 Security Misconfiguration | CWE-693 / CWE-1021 | Media | **ZAP** (CSP, anti-clickjacking, nosniff, Permissions-Policy, COOP/COEP/CORP), pytest |
| VULN-05 | Dependencias con CVE conocidas | A06 Vulnerable & Outdated Components | CWE-1104 | **Alta** | **pip-audit** (17), **Dependency-Check** (28 hallazgos) |
| VULN-06 | Despliegue inseguro: servidor de desarrollo, contenedor root, imagen antigua, versión expuesta en la cabecera `Server` | A05 Security Misconfiguration | CWE-250 / CWE-497 | Media | **SonarQube S6471**, ZAP (Server Leaks Version), Dependency-Check |
| VULN-07 | Sin registro de eventos ni métricas de seguridad | A09 Logging & Monitoring Failures | CWE-778 | Media | Revisión, Prometheus (alerta `AplicacionCaida`: no hay `/metrics`) |

### 5.3 Explotación y mitigación

#### VULN-01: XSS reflejado (CWE-79)
- **Explotación:** `http://localhost:5000/hello?name=<script>alert(1)</script>` ejecuta JavaScript en el navegador de la víctima. Con un enlace malicioso, un atacante puede robar cookies o sesiones, o modificar la página.
- **Causa:** `return f"Hello, {name}!"` inserta la entrada en el HTML sin codificarla.
- **Mitigación [FIX-01]:** codificación de salida con `markupsafe.escape(name)` (convierte `< > & " '` en entidades HTML), validación por lista blanca (VULN-03) y una CSP restrictiva (`default-src 'none'`).
- **Verificación:** las 3 pruebas `test_vuln01_*` (payloads `<script>`, `<img onerror>` y `<svg onload>`) fallan en la vulnerable y pasan en la corregida. ZAP deja de reportar XSS.

[CAPTURA] `/hello?name=TEST` funcionando y la alerta de `/hello?name=<script>alert(1)</script>` en la versión vulnerable (evidencias 14 y 15 de la guía).

#### VULN-02: Modo debug activo (CWE-489 / CWE-94)
- **Riesgo:** con `debug=True`, cualquier error muestra el debugger interactivo de Werkzeug, que permite ejecutar código Python en el servidor. Werkzeug 2.2.2 además tiene la CVE-2024-34069 (RCE vía debugger). También expone trazas con rutas y código fuente.
- **Mitigación [FIX-02]:** `app.config["DEBUG"] = False`, sin `debug=True` en el código, y servidor de producción **gunicorn** en el contenedor.
- **Verificación:** Bandit (B201) y SonarQube (S4507) dejan de reportarlo; `test_vuln02_debug_desactivado` pasa.

#### VULN-03: Validación de entrada (CWE-20)
- **Riesgo:** se acepta cualquier valor y largo, lo que abre la puerta a inyecciones y abuso. Sin `name`, la respuesta es `Hello, None!`.
- **Mitigación [FIX-03]:** lista blanca `^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ' -]+$`, máximo 50 caracteres y valor por defecto `invitado`. Una entrada inválida responde **HTTP 400**, se registra en el log `security` y suma 1 a la métrica `input_rejected_total`.

#### VULN-04: Cabeceras de seguridad (CWE-693)
- **Mitigación [FIX-04]:** `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Resource/Opener/Embedder-Policy` y `Cache-Control: no-store`.

#### VULN-05: Dependencias vulnerables
Ver la sección 8.

#### VULN-06: Despliegue inseguro (CWE-250 / CWE-497)
- **Mitigación [FIX-06]:** imagen `python:3.12-slim` multi-stage, usuario sin privilegios (`appuser`, UID 10001), gunicorn (no expone la versión de Python/Werkzeug) y `HEALTHCHECK`. En Compose: `read_only`, `cap_drop: ALL` y `no-new-privileges`.

#### VULN-07: Sin registro ni monitoreo (CWE-778)
- **Mitigación [FIX-07]:** el logger `security` registra las entradas rechazadas con IP y valor truncado (con `repr` para evitar inyección en logs). La app expone `/metrics` para Prometheus, con métricas HTTP y la métrica propia `input_rejected_total`.

#### Hallazgo revisado: SonarQube python:S4502 (CSRF)
SonarQube marca que la app Flask no tiene protección CSRF. Se clasifica como **no aplicable / riesgo aceptado**: la app solo expone un endpoint GET idempotente y no usa formularios, cookies ni sesiones, así que un CSRF no tiene ninguna acción que forzar. Se marca con `# NOSONAR` en el código y la justificación queda en este informe. Si en el futuro se agregan formularios, se debe incorporar `Flask-WTF CSRFProtect`.

### 5.4 Resultados antes y después (ejecución real)

| Control | Versión vulnerable | Versión corregida |
|---|---|---|
| Pruebas pytest (13) | **10 fallidas**, 3 aprobadas | **13/13 aprobadas** (cobertura 97,6 %) |
| Bandit (severidad media o superior) | **1**: B201 `debug=True` (High) | **0** |
| SonarQube | **3 vulnerabilidades** (S4502, S4507, S6471), seguridad **D**, Quality Gate **ERROR** | **0 vulnerabilidades**, seguridad **A**, Quality Gate **OK** |
| pip-audit | **17 vulnerabilidades** en 3 paquetes | **0** |
| OWASP Dependency-Check | **28 hallazgos** (26 CVE distintas) en 10 componentes; 1 crítica y 7 altas | **0** |
| OWASP ZAP (Alto/Medio sin triage) | **2 altas** (XSS Reflected, XSS DOM) y **2 medias** | **0** |
| Resultado del pipeline | **UNSTABLE** | **SUCCESS** |

[CAPTURA] Pestaña *Test Result* de Jenkins (build vulnerable) y proyecto en SonarQube (antes y después).

---

## 6. Análisis estático con SonarQube

- **Despliegue:** `docker-compose.sonar.yml` (SonarQube Community 26.10, puerto 9000). El token se guarda en Jenkins Credentials (`sonar-token`) y nunca en el código.
- **Integración:** la etapa *Analyze: SonarQube* ejecuta `sonar-scanner-cli` en un contenedor, envía el código y el reporte de cobertura, y `scripts/sonar_resumen.py` consulta el resultado vía API (Quality Gate, vulnerabilidades y hotspots). La etapa queda UNSTABLE si hay hallazgos.
- **Limitación observada:** SonarQube Community **no detectó el XSS**, porque el análisis de flujo de datos (*taint analysis*) es de las ediciones pagadas. Lo detectaron ZAP y las pruebas. Esto justifica combinar herramientas SAST, DAST y pruebas, en vez de depender de una sola.

---

## 7. Pruebas automatizadas de seguridad con OWASP ZAP

### 7.1 Integración

ZAP corre como contenedor en la misma red Docker que la app (`devsecops-net`):

```
docker run --rm --network devsecops-net -v <workspace>/reports:/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t "http://app:5000/hello?name=TEST" -r zap-report.html -J zap-report.json -w zap-report.md -I -m 2
```

- `full`: spider y escaneo **activo**, que ataca el parámetro `name`. `baseline`: solo pasivo.
- `scripts/evaluar_zap.py` deja la etapa en UNSTABLE si hay alertas Medias o Altas **sin triage**.

### 7.2 Resultados

**Versión vulnerable:** 12 tipos de alerta (3 altas, 2 medias, 6 bajas y 1 informativa).

| Riesgo | Alerta ZAP | CWE | Vulnerabilidad | Mitigación |
|---|---|---|---|---|
| Alto | Cross Site Scripting (Reflected) | 79 | VULN-01 | `escape()`, validación y CSP |
| Alto | Cross Site Scripting (DOM Based) | 79 | VULN-01 | Ídem |
| Alto | Source Code Disclosure - File Inclusion | 541 | — | **Falso positivo** (ver 7.3) |
| Medio | Content Security Policy (CSP) Header Not Set | 693 | VULN-04 | Cabecera CSP |
| Medio | Missing Anti-clickjacking Header | 1021 | VULN-04 | `X-Frame-Options: DENY` y `frame-ancestors` |
| Bajo | Server Leaks Version Information ("Server" header) | 497 | VULN-06 | gunicorn |
| Bajo | X-Content-Type-Options Header Missing | 693 | VULN-04 | `nosniff` |
| Bajo | Permissions Policy Header Not Set | 693 | VULN-04 | `Permissions-Policy` |
| Bajo | Cross-Origin-Embedder/Opener/Resource-Policy Missing | 693 | VULN-04 | Cabeceras COEP, COOP y CORP |
| Info | Storable and Cacheable Content | 524 | VULN-04 | `Cache-Control: no-store` |

**Versión corregida:** solo quedan 3 alertas, todas con triage:

| Riesgo | Alerta | Triage | Justificación |
|---|---|---|---|
| Alto | Source Code Disclosure - File Inclusion | FALSO_POSITIVO | ZAP envía `name=hello`; como la app devuelve "Hello, hello!", interpreta la diferencia como lectura de archivo. El código nunca abre archivos |
| Medio | HTTP Only Site | RIESGO_ACEPTADO | El laboratorio corre sin TLS. En producción: proxy inverso con HTTPS y HSTS |
| Info | Non-Storable Content | — | Esperado: `Cache-Control: no-store` |

### 7.3 Triage de falsos positivos

Las alertas descartadas se registran con su justificación en `zap-riesgos-aceptados.tsv`, versionado en Git. Siguen apareciendo en los reportes y en `TRAZABILIDAD.md` (columna *Triage*), pero no bloquean el pipeline. Así se evita tanto ignorar alertas sin dejar rastro como bloquear despliegues por falsos positivos.

[CAPTURA] Reporte HTML de ZAP de la versión vulnerable (XSS) y de la corregida.

---

## 8. Gestión de dependencias y parcheo

### 8.1 Herramientas y configuración

| Práctica (material 3.3.1) | Implementación |
|---|---|
| Bloqueo de versiones | `requirements.txt` con todas las dependencias, directas y transitivas, fijadas con `==` (lo verifica `test_vuln05_*`) |
| Entornos aislados | Cada build instala en un contenedor limpio |
| Auditoría automatizada en CI | **pip-audit** (dependencias declaradas) y **OWASP Dependency-Check** (paquetes instalados en la imagen) en cada build. Si hay hallazgos, el Security Gate bloquea el despliegue |
| Auditorías regulares | Trigger semanal `cron('H 6 * * 1')` |
| Actualización automática | `.github/dependabot.yml`: PR semanal para pip y para la imagen base Docker |
| Reportes | `pip-audit.md`, `dependency-check-report.html`, **SBOM** `sbom-cyclonedx.json`, `dependencias-desactualizadas.txt` |

**Configuración de Dependency-Check:**

- Escanear solo `requirements.txt` no encontró nada, porque ese archivo trae únicamente el nombre del paquete y eso no alcanza para calzar el identificador CPE del NVD. Por eso el pipeline escanea los **paquetes instalados en la imagen**: se llena un volumen temporal con su `site-packages`, cuyos metadatos (autor, URL del proyecto) sí permiten asociar las CVE. Este enfoque además detecta vulnerabilidades de la **imagen base** (pip, certifi, wheel).
- Dependency-Check 13 exige una API key para consultar el NVD directamente. Se usa el caché público de la base NVD que publica el propio proyecto (`--nvdDatafeed`), almacenado en el volumen `dependency-check-data`.

### 8.2 Política de actualización (SemVer) y plazos de parcheo

| Tipo de cambio | Acción |
|---|---|
| PATCH (x.y.**Z**) | Se acepta el PR de Dependabot si el pipeline queda en verde |
| MINOR (x.**Y**.z) | Revisión del changelog y pipeline completo |
| MAJOR (**X**.y.z) | Se planifica como tarea, con pruebas de regresión |

| Severidad (CVSS) | Plazo máximo para parchear |
|---|---|
| Crítica (9,0–10) | 48 horas |
| Alta (7,0–8,9) | 7 días |
| Media (4,0–6,9) | 30 días |
| Baja (menor a 4,0) | 90 días o en la siguiente versión |

### 8.3 Resultados

**Versión vulnerable: OWASP Dependency-Check (28 hallazgos, 26 CVE distintas):**

| Componente | CVE (CVSS) | Origen |
|---|---|---|
| Flask 2.2.2 | CVE-2023-30861 (7,5), CVE-2026-27205 (4,3) | Dependencia de la app |
| Werkzeug 2.2.2 | CVE-2023-25577 (7,5), CVE-2023-46136 (7,5), **CVE-2024-34069 (7,5, RCE vía debugger)**, CVE-2024-49767 (7,5), CVE-2024-49766, CVE-2025-66221, CVE-2026-21860, CVE-2026-27199, CVE-2023-23934 | Dependencia de la app |
| Jinja2 3.1.2 | CVE-2024-56201 (8,8), CVE-2025-27516 (8,8), CVE-2024-56326 (7,8), CVE-2024-22195, CVE-2024-34064 | Dependencia de la app |
| certifi 2022.12.07 | **CVE-2023-37920 (9,8, crítica)**, CVE-2024-39689 (7,5) | Imagen base `python:3.10-slim` |
| pip 23.0.1 | CVE-2018-20225 (7,8), CVE-2026-13346, CVE-2026-8643, CVE-2023-5752 | Imagen base |
| jaraco.context 5.3.0 | CVE-2026-23949 (8,6) | Imagen base |
| wheel 0.45.1, pygments 2.13.0, cli-32/64.exe | CVE-2026-24049, CVE-2022-40896, CVE-2016-10538 | Imagen base |

**Versión vulnerable: pip-audit:** 17 vulnerabilidades (Flask 2, Werkzeug 10, Jinja2 5), con las mismas CVE de la app.

**Versión corregida:** pip-audit **0** y Dependency-Check **0** (80 componentes analizados). Se logró actualizando Flask, Werkzeug y Jinja2, y cambiando la imagen base a `python:3.12-slim`, que ya no trae setuptools, wheel ni certifi antiguos.

**Evidencia real del proceso de parcheo:** la primera versión corregida usaba Flask 3.1.1 y Werkzeug 3.1.3. Al auditarla, pip-audit detectó **5 CVE publicadas después** (CVE-2026-27205 en Flask; CVE-2025-66221, CVE-2026-21860, CVE-2026-27199 y CVE-2026-102598 en Werkzeug). Aplicando la política se subió a **Flask 3.1.3** y **Werkzeug 3.1.9** (PATCH), y las pruebas siguieron aprobadas. Esto demuestra por qué la auditoría debe ser **continua**.

[CAPTURA] Reporte HTML de Dependency-Check (vulnerable) y salida de las etapas de dependencias.

---

## 9. Monitorización del entorno de producción

### 9.1 Arquitectura

```
 App corregida (/metrics) ──scrape cada 5 s──► Prometheus ──reglas de alerta──► ALERTS
         │                                         │
         └── log "security" (docker logs)          └──► Grafana: dashboard "SecureDev - Monitorización de seguridad"
```

- Grafana se configura **como código** (provisioning): el datasource, la carpeta y el dashboard de 11 paneles se cargan solos. Requiere contraseña desde Jenkins Credentials y no permite registro ni acceso anónimo.
- Prometheus monta la carpeta de reglas y se recarga (`SIGHUP`) en cada despliegue.

### 9.2 Reglas de detección (`monitoring/prometheus/alert-rules.yml`)

| Alerta | Condición | Severidad | Qué detecta |
|---|---|---|---|
| AplicacionCaida | `up == 0` por 30 s | Crítica | Caída, DoS o app sin métricas |
| IntentosDeInyeccionXSS | más de 3 entradas rechazadas en 2 min | Alta | Campaña de XSS o inyección |
| TasaErrores4xxAlta | más de 1 respuesta 4xx/s por 30 s | Media | Escaneo o enumeración |
| ErroresServidor5xx | más de 0,1 respuestas 5xx/s por 30 s | Alta | Explotación o falla |
| TraficoAnomalo | más de 5 peticiones/s por 30 s | Media | Escáner automatizado o DoS |

### 9.3 Actividades realizadas y resultados

1. Despliegue de Prometheus y Grafana desde el pipeline. Verificado: datasource conectado ("Successfully queried the Prometheus API"), dashboard cargado y reglas visibles en Grafana.
2. **Versión vulnerable desplegada:** Prometheus marcó el target como **CAÍDO** y disparó `AplicacionCaida`, porque el código original no expone métricas. Esto es evidencia directa de VULN-07.
3. **Versión corregida:** target **EN LÍNEA**; observación del dashboard durante el escaneo de ZAP.
4. **Simulación controlada de un incidente** (`scripts/simular_ataque.py`) contra la versión corregida:

| Fase | Respuestas | Interpretación |
|---|---|---|
| Enumeración de 20 rutas sensibles (`/.env`, `/.git/config`, `/admin`…) | 20 × 404 | No existen |
| 5 payloads XSS en `/hello` | 5 × 400; **0/5 reflejados** | Bloqueados por la validación |
| 5 inyecciones (`{{7*7}}`, `' OR '1'='1`, `../../etc/passwd`…) | 5 × 400 | Bloqueadas |
| Ráfaga de 50 s (~19 req/s, mitad legítima y mitad XSS) | 464 × 200, 464 × 400 | Se atiende el tráfico legítimo y se rechaza el malicioso |

**Alertas disparadas:** `IntentosDeInyeccionXSS`, `TasaErrores4xxAlta` y `TraficoAnomalo`.

[CAPTURA] Dashboard de Grafana durante la simulación y Prometheus → Alerts (o Grafana → Alerting) con las alertas en *Firing*.

### 9.4 Incidentes detectados y respuesta (ciclo NIST SP 800-61)

**Incidente 1: campaña de XSS con ráfaga de tráfico (simulación)**
- *Detección:* `IntentosDeInyeccionXSS` (alta), `TasaErrores4xxAlta` y `TraficoAnomalo` en Firing.
- *Análisis:* `app-logs.txt` muestra los eventos `entrada_rechazada endpoint=/hello` con la IP de origen y los payloads.
- *Contención:* automática. La validación respondió 400 y ningún payload se reflejó.
- *Erradicación y recuperación:* en un caso real, bloquear la IP en un firewall o WAF, aplicar rate limiting en el proxy y verificar en los logs que no haya respuestas 200 con payloads.
- *Lecciones aprendidas:* agregar rate limiting y notificaciones con Alertmanager.

**Incidente 2: tráfico anómalo durante la etapa DAST**
- *Detección:* aumento de 4xx y de peticiones por segundo durante el escaneo de ZAP.
- *Clasificación:* **evento autorizado** (prueba planificada). Se propone silenciar las alertas durante las ventanas de escaneo.

**Incidente 3: aplicación sin observabilidad (versión vulnerable)**
- *Detección:* `AplicacionCaida` en estado crítico.
- *Análisis:* la app responde, pero no expone `/metrics`, así que el entorno opera "a ciegas" (VULN-07).
- *Acción:* se instrumentó la versión corregida con métricas y logs de seguridad; el target pasó a EN LÍNEA.

---

## 10. Documentación y trazabilidad

| Mecanismo | Qué permite rastrear |
|---|---|
| Git (commits y PR de Dependabot) | Quién cambió qué y cuándo; cada build registra su commit |
| Número de build y parámetros de Jenkins | Qué versión se construyó y con qué configuración |
| Etiquetas de la imagen (`securedev.build`, `securedev.version`, `securedev.commit`) | Relación contenedor ↔ build ↔ commit |
| `archiveArtifacts` con **fingerprint** | En qué builds aparece cada artefacto |
| `reports/TRAZABILIDAD.md` | Registro auditable por build con todas las herramientas |
| `reports/SHA256SUMS.txt` | Integridad de los reportes |
| `zap-riesgos-aceptados.tsv` y marca `NOSONAR` | Justificación versionada de cada falso positivo o riesgo aceptado |
| `app-logs.txt` y métricas en Prometheus | Registro de la operación y de los incidentes |
| IDs VULN-XX/FIX-XX del informe y pruebas `test_vulnXX_*` | Relación vulnerabilidad → corrección → prueba |

### Matriz de trazabilidad

| Requisito del parcial | Implementación | Evidencia |
|---|---|---|
| Pipeline con construcción, pruebas y despliegue | `Jenkinsfile` | Stage View, consola |
| Revisiones de seguridad continuas | Bandit, SonarQube, pytest, pip-audit, Dependency-Check y ZAP en cada build, más el cron | Reportes en *Build Artifacts* |
| Corregir las vulnerabilidades | `app/` | 13/13 pruebas y 0 hallazgos en todas las herramientas |
| Integrar OWASP ZAP | Etapa DAST | `zap-report.*` |
| Configurar Grafana | Compose y provisioning | Dashboard y alertas |
| Monitorear y documentar incidentes | Reglas, simulación y logs | Sección 9.4, `monitor-*.json` |
| Gestión de dependencias | Versiones fijadas, pip-audit, Dependency-Check, SBOM, Dependabot y cron | Sección 8 |
| Documentación y trazabilidad | Etapa final del pipeline | `TRAZABILIDAD.md`, `SHA256SUMS.txt` |

| Build | Versión | Resultado | Pruebas | Bandit | SonarQube | pip-audit | Dep.-Check | ZAP (A/M sin triage) |
|---|---|---|---|---|---|---|---|---|
| #[COMPLETAR] | vulnerable | UNSTABLE | 3/13 | 1 | 3 vulns (D) | 17 | 28 | 4 |
| #[COMPLETAR] | corregida | SUCCESS | 13/13 | 0 | 0 (A) | 0 | 0 | 0 |

---

## 11. Conclusiones y mejoras

El pipeline integra la seguridad de forma **continua y automática** en cada etapa del SDLC: código (Bandit y SonarQube), pruebas (tests de seguridad con cobertura), dependencias (pip-audit y Dependency-Check), ejecución (ZAP) y operación (Prometheus y Grafana). El Security Gate impide desplegar código con hallazgos, y cada build deja un registro auditable con integridad verificable.

Ninguna herramienta por sí sola detectó todo: SonarQube no vio el XSS (lo detectaron ZAP y las pruebas), y Dependency-Check encontró CVE de la imagen base que pip-audit no ve. Eso confirma el valor de combinarlas.

**Mejoras propuestas:** HTTPS con proxy inverso y HSTS, rate limiting, Alertmanager con notificaciones, escaneo de la imagen con Trivy, detección de secretos con gitleaks y API key del NVD para que Dependency-Check consulte la fuente oficial.

---

## Anexo A: Evidencias (guía 3.2.2 y parcial)

- [ ] 1–3: `docker --version`, Docker Desktop activo, Jenkins en `localhost:8080`
- [ ] 4–5: plugins instalados y credenciales (`sonar-token`, `grafana-admin-password`, sin mostrar valores)
- [ ] 6–8: repositorio en GitHub con `app_vulnerable/app.py`, `Jenkinsfile`, y job "Pipeline script from SCM"
- [ ] 9–10: pipeline ejecutándose y completado (vulnerable amarillo, corregida verde)
- [ ] 11: SonarQube (vulnerable: 3 vulnerabilidades / D; corregida: A, Quality Gate OK)
- [ ] 12: reporte de Dependency-Check
- [ ] 13: reporte de ZAP con XSS
- [ ] 14–15: `/hello?name=TEST` y XSS con `<script>alert(1)</script>`
- [ ] 16 y 18: secciones 5 y 11 de este informe
- [ ] 17: `Jenkinsfile` en el repositorio
- [ ] Parcial: Grafana con alertas en Firing y `TRAZABILIDAD.md` de un build

## Anexo B: Estructura del repositorio

```
parcial3-devsecops/
├── Jenkinsfile                   Pipeline CI/CD
├── docker-compose.yml            Producción (app + Prometheus + Grafana)
├── docker-compose.sonar.yml      Servidor SonarQube
├── sonar-project.properties      Configuración del análisis
├── zap-riesgos-aceptados.tsv     Triage de alertas de ZAP
├── app_vulnerable/               Código original de la guía 3.2.2
├── app/                          Código corregido
├── tests/                        Pruebas funcionales y de seguridad
├── monitoring/                   Prometheus y Grafana como código
├── scripts/                      Evaluación ZAP/SonarQube, simulación y trazabilidad
└── .github/dependabot.yml        Actualización automática de dependencias
```
