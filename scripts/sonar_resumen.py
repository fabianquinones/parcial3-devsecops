import base64
import json
import os
import sys
import time
import urllib.parse
import urllib.request

URL = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://sonarqube:9000"
PROYECTO = sys.argv[2] if len(sys.argv) > 2 else "securedev"
TOKEN = os.environ.get("SONAR_TOKEN", "")
AUTH = "Basic " + base64.b64encode(f"{TOKEN}:".encode()).decode()


def api(ruta, **params):
    req = urllib.request.Request(f"{URL}{ruta}?{urllib.parse.urlencode(params)}", headers={"Authorization": AUTH})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def main():
    if not TOKEN:
        print("Falta SONAR_TOKEN")
        return 3
    try:
        for _ in range(30):
            if not api("/api/ce/component", component=PROYECTO).get("queue"):
                break
            time.sleep(2)
        gate = api("/api/qualitygates/project_status", projectKey=PROYECTO)["projectStatus"]
        issues = api("/api/issues/search", componentKeys=PROYECTO, resolved="false", ps=500)
        hotspots = api("/api/hotspots/search", project=PROYECTO, status="TO_REVIEW", ps=500)
        medidas = api("/api/measures/component", component=PROYECTO,
                      metricKeys="bugs,vulnerabilities,security_hotspots,code_smells,ncloc,"
                                 "security_rating,reliability_rating,sqale_rating")
    except Exception as exc:
        print(f"No se pudo consultar SonarQube: {exc}")
        return 3

    resumen = {
        "quality_gate": gate.get("status"),
        "medidas": {m["metric"]: m.get("value") for m in medidas["component"]["measures"]},
        "issues": [{"regla": i["rule"], "tipo": i["type"], "severidad": i.get("severity"),
                    "archivo": i["component"].split(":", 1)[-1], "linea": i.get("line"), "mensaje": i["message"]}
                   for i in issues.get("issues", [])],
        "hotspots": [{"regla": h["ruleKey"], "categoria": h.get("securityCategory"),
                      "probabilidad": h.get("vulnerabilityProbability"),
                      "archivo": h["component"].split(":", 1)[-1], "linea": h.get("line"), "mensaje": h["message"]}
                     for h in hotspots.get("hotspots", [])],
    }
    os.makedirs("reports", exist_ok=True)
    with open("reports/sonarqube.json", "w", encoding="utf-8") as fh:
        json.dump(resumen, fh, ensure_ascii=False, indent=2)

    print(f"Quality Gate: {resumen['quality_gate']}")
    print("Medidas: " + ", ".join(f"{k}={v}" for k, v in sorted(resumen["medidas"].items())))
    for h in resumen["hotspots"]:
        print(f"  HOTSPOT [{h['probabilidad']}] {h['regla']} {h['archivo']}:{h['linea']} - {h['mensaje']}")
    for i in resumen["issues"]:
        print(f"  {i['tipo']} [{i['severidad']}] {i['regla']} {i['archivo']}:{i['linea']} - {i['mensaje']}")

    vulns = sum(1 for i in resumen["issues"] if i["tipo"] == "VULNERABILITY")
    if resumen["quality_gate"] == "ERROR" or vulns or resumen["hotspots"]:
        print(f"RESULTADO: {vulns} vulnerabilidades, {len(resumen['hotspots'])} hotspots por revisar, "
              f"Quality Gate {resumen['quality_gate']}.")
        return 1
    print("RESULTADO: sin hallazgos de seguridad en SonarQube.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
