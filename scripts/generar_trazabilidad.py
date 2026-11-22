import hashlib
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

REP = "reports"
RIESGO_ZAP = {"3": "Alto", "2": "Medio", "1": "Bajo", "0": "Informativo"}


def leer_json(nombre):
    try:
        with open(os.path.join(REP, nombre), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def env(nombre, defecto="N/A"):
    return os.environ.get(nombre) or defecto


def seccion_estado():
    lineas = ["## 2. Estado de las etapas del pipeline", "", "| Etapa | Resultado |", "|---|---|"]
    try:
        with open(os.path.join(REP, "pipeline-estado.txt"), encoding="utf-8-sig") as fh:
            for linea in fh:
                if "=" in linea:
                    etapa, res = linea.strip().split("=", 1)
                    lineas.append(f"| {etapa} | {res} |")
    except OSError:
        lineas.append("| (sin datos) | - |")
    return lineas


def seccion_pytest():
    lineas = ["### 3.1 Pruebas unitarias y de seguridad (pytest)", ""]
    try:
        raiz = ET.parse(os.path.join(REP, "junit.xml")).getroot()
    except (OSError, ET.ParseError):
        return lineas + ["Sin reporte junit.xml.", ""]
    suites = [raiz] if raiz.tag == "testsuite" else list(raiz.iter("testsuite"))
    total = sum(int(s.get("tests", 0)) for s in suites)
    fallos = sum(int(s.get("failures", 0)) + int(s.get("errors", 0)) for s in suites)
    lineas.append(f"- Pruebas ejecutadas: **{total}** | Aprobadas: **{total - fallos}** | Fallidas: **{fallos}**")
    fallidas = [tc.get("name") for tc in raiz.iter("testcase")
                if tc.find("failure") is not None or tc.find("error") is not None]
    if fallidas:
        lineas.append("- Pruebas fallidas (cada una evidencia una vulnerabilidad):")
        lineas += [f"  - `{n}`" for n in fallidas]
    return lineas + [""]


def seccion_bandit():
    lineas = ["### 3.2 Análisis estático - SAST (Bandit)", ""]
    data = leer_json("bandit.json")
    if data is None:
        return lineas + ["Sin reporte bandit.json.", ""]
    res = data.get("results", [])
    conteo = {}
    for r in res:
        conteo[r["issue_severity"]] = conteo.get(r["issue_severity"], 0) + 1
    lineas.append("- Hallazgos por severidad: " +
                  (", ".join(f"{k}={v}" for k, v in sorted(conteo.items())) if conteo else "ninguno"))
    if res:
        lineas += ["", "| ID | Severidad | Archivo:línea | Descripción |", "|---|---|---|---|"]
        for r in res:
            archivo = r["filename"].replace("/src/", "")
            lineas.append(f"| {r['test_id']} | {r['issue_severity']} | {archivo}:{r['line_number']} | {r['issue_text']} |")
    return lineas + [""]


def seccion_sonar():
    lineas = ["### 3.3 Análisis estático - SonarQube", ""]
    data = leer_json("sonarqube.json")
    if data is None:
        return lineas + ["No ejecutado en este build (parámetro RUN_SONARQUBE o servidor no disponible).", ""]
    m = data.get("medidas", {})
    nota = {"1.0": "A", "2.0": "B", "3.0": "C", "4.0": "D", "5.0": "E"}
    lineas.append(f"- Quality Gate: **{data.get('quality_gate')}** | Vulnerabilidades: **{m.get('vulnerabilities', '?')}** "
                  f"| Hotspots: {m.get('security_hotspots', '?')} | Bugs: {m.get('bugs', '?')} "
                  f"| Code smells: {m.get('code_smells', '?')} | Líneas: {m.get('ncloc', '?')}")
    lineas.append(f"- Calificación de seguridad: **{nota.get(str(m.get('security_rating')), '?')}** "
                  f"| Confiabilidad: {nota.get(str(m.get('reliability_rating')), '?')} "
                  f"| Mantenibilidad: {nota.get(str(m.get('sqale_rating')), '?')}")
    hallazgos = data.get("issues", []) + data.get("hotspots", [])
    if hallazgos:
        lineas += ["", "| Regla | Tipo/Severidad | Archivo:línea | Descripción |", "|---|---|---|---|"]
        for h in hallazgos:
            tipo = f"{h.get('tipo', 'HOTSPOT')} {h.get('severidad') or h.get('probabilidad') or ''}".strip()
            lineas.append(f"| {h['regla']} | {tipo} | {h['archivo']}:{h.get('linea')} | {h['mensaje']} |")
    return lineas + [""]


def seccion_dependency_check():
    lineas = ["### 3.5 Gestión de dependencias - OWASP Dependency-Check", ""]
    data = leer_json("dependency-check-report.json")
    if data is None:
        return lineas + ["No ejecutado en este build (parámetro RUN_DEPENDENCY_CHECK).", ""]
    deps = data.get("dependencies", [])
    filas = []
    for d in deps:
        for v in d.get("vulnerabilities") or []:
            cvss = (v.get("cvssv3") or {}).get("baseScore") or (v.get("cvssv4") or {}).get("baseScore") or ""
            filas.append((d.get("fileName"), v.get("name"), v.get("severity"), cvss))
    paquetes = {f[0] for f in filas}
    lineas.append(f"- Componentes analizados (paquetes instalados en la imagen): **{len(deps)}** "
                  f"| Con CVE: **{len(paquetes)}** | CVE encontradas: **{len(filas)}**")
    if filas:
        lineas += ["", "| Componente | CVE | Severidad | CVSS |", "|---|---|---|---|"]
        lineas += [f"| {a} | {b} | {c} | {d} |" for a, b, c, d in filas]
    lineas.append("- Reporte completo: `dependency-check-report.html`")
    return lineas + [""]


def seccion_pip_audit():
    lineas = ["### 3.4 Gestión de dependencias - SCA (pip-audit)", ""]
    data = leer_json("pip-audit.json")
    if data is None:
        return lineas + ["Sin reporte pip-audit.json.", ""]
    deps = data.get("dependencies", data if isinstance(data, list) else [])
    vulnerables = [d for d in deps if d.get("vulns")]
    total_vulns = sum(len(d["vulns"]) for d in vulnerables)
    lineas.append(f"- Dependencias analizadas: **{len(deps)}** | Con vulnerabilidades: **{len(vulnerables)}** "
                  f"| Vulnerabilidades: **{total_vulns}**")
    if vulnerables:
        lineas += ["", "| Paquete | Versión | Vulnerabilidad | Alias | Versión corregida |", "|---|---|---|---|---|"]
        for d in vulnerables:
            for v in d["vulns"]:
                lineas.append(f"| {d['name']} | {d['version']} | {v['id']} | {', '.join(v.get('aliases', []))} "
                              f"| {', '.join(v.get('fix_versions', [])) or 'sin parche'} |")
    lineas.append("- SBOM (inventario de componentes): `sbom-cyclonedx.json`")
    return lineas + [""]


def seccion_zap():
    lineas = ["### 3.6 Pruebas dinámicas - DAST (OWASP ZAP)", "", f"- Tipo de escaneo: **{env('ZAP_SCAN')}**"]
    data = leer_json("zap-report.json")
    if data is None:
        return lineas + ["Sin reporte zap-report.json.", ""]
    alertas = [a for s in data.get("site", []) for a in s.get("alerts", [])]
    alertas.sort(key=lambda a: -int(a.get("riskcode", 0)))
    conteo = {k: 0 for k in RIESGO_ZAP}
    for a in alertas:
        conteo[str(a.get("riskcode", "0"))] += 1
    lineas.append("- Alertas por riesgo: " + ", ".join(f"{RIESGO_ZAP[k]}={conteo[k]}" for k in ("3", "2", "1", "0")))
    triage = {}
    if os.path.exists("zap-riesgos-aceptados.tsv"):
        with open("zap-riesgos-aceptados.tsv", encoding="utf-8") as fh:
            for linea in fh:
                partes = linea.rstrip("\n").split("\t")
                if not linea.startswith("#") and len(partes) >= 3:
                    triage[partes[0].strip()] = partes[1].strip()
    if alertas:
        lineas += ["", "| Riesgo | Alerta | CWE | Instancias | Triage |", "|---|---|---|---|---|"]
        for a in alertas:
            lineas.append(f"| {RIESGO_ZAP.get(str(a.get('riskcode')), '?')} | {a.get('alert') or a.get('name')} "
                          f"| {a.get('cweid', '')} | {a.get('count') or len(a.get('instances', []))} "
                          f"| {triage.get(str(a.get('pluginid')), '-')} |")
        if any(str(a.get("pluginid")) in triage for a in alertas):
            lineas.append("- Justificación del triage: ver `zap-riesgos-aceptados.tsv` en el repositorio.")
    return lineas + [""]


def seccion_monitor():
    lineas = ["### 3.7 Monitorización del entorno (Prometheus / Grafana)", ""]
    up = leer_json("monitor-targets.json")
    if up:
        for r in up.get("data", {}).get("result", []):
            estado = "EN LÍNEA" if r["value"][1] == "1" else "CAÍDO"
            lineas.append(f"- Target `{r['metric'].get('job')}` ({r['metric'].get('instance')}): **{estado}**")
    alertas = leer_json("monitor-alertas.json")
    activas = [r["metric"] for r in (alertas or {}).get("data", {}).get("result", [])
               if r["metric"].get("alertstate") == "firing"]
    if activas:
        lineas.append("- Alertas activas al cierre del build:")
        lineas += [f"  - **{a.get('alertname')}** (severidad {a.get('severity', '?')})" for a in activas]
    else:
        lineas.append("- Sin alertas activas al cierre del build.")
    lineas.append("- Registro de eventos de la aplicación: `app-logs.txt`")
    return lineas + [""]


def seccion_artefactos():
    lineas = ["## 4. Artefactos generados (integridad SHA-256)", "", "| Archivo | SHA-256 |", "|---|---|"]
    sums = []
    for nombre in sorted(os.listdir(REP)):
        ruta = os.path.join(REP, nombre)
        if os.path.isfile(ruta) and nombre not in ("TRAZABILIDAD.md", "SHA256SUMS.txt"):
            with open(ruta, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            sums.append(f"{digest}  {nombre}")
            lineas.append(f"| {nombre} | `{digest[:16]}…` |")
    with open(os.path.join(REP, "SHA256SUMS.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(sums) + "\n")
    return lineas + ["", "Hashes completos en `SHA256SUMS.txt`."]


def main():
    os.makedirs(REP, exist_ok=True)
    ahora = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    doc = [
        f"# Registro de trazabilidad - {env('JOB_NAME')} #{env('BUILD_NUMBER')}",
        "",
        "## 1. Identificación del build",
        "",
        "| Campo | Valor |",
        "|---|---|",
        f"| Fecha de generación | {ahora} |",
        f"| Job / Build | {env('JOB_NAME')} #{env('BUILD_NUMBER')} |",
        f"| URL del build | {env('BUILD_URL')} |",
        f"| Resultado al documentar | {env('BUILD_RESULT')} |",
        f"| Versión de la aplicación | {env('APP_VERSION')} |",
        f"| Commit | {env('GIT_COMMIT')} |",
        f"| Rama | {env('GIT_BRANCH')} |",
        f"| Imagen Docker | {env('APP_IMAGE')} |",
        f"| ID de la imagen | {env('APP_IMAGE_ID')} |",
        "| Herramientas | pytest 8.3.3, Bandit 1.8.0, SonarQube 26.10 (scanner 12.3.1), pip-audit 2.7.3, OWASP Dependency-Check 13.0.0, OWASP ZAP (stable), Prometheus 2.55.1, Grafana 11.3.0 |",
        "",
    ]
    doc += seccion_estado() + [""]
    doc += ["## 3. Resultados de seguridad", ""]
    doc += (seccion_pytest() + seccion_bandit() + seccion_sonar() + seccion_pip_audit()
            + seccion_dependency_check() + seccion_zap() + seccion_monitor())
    doc += seccion_artefactos()

    with open(os.path.join(REP, "TRAZABILIDAD.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(doc) + "\n")
    print("\n".join(doc))


if __name__ == "__main__":
    main()
