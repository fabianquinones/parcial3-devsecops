import json
import os
import sys

RIESGOS = {"3": "Alto", "2": "Medio", "1": "Bajo", "0": "Informativo"}
ARCHIVO_TRIAGE = "zap-riesgos-aceptados.tsv"


def cargar_triage(ruta=ARCHIVO_TRIAGE):
    triage = {}
    if os.path.exists(ruta):
        with open(ruta, encoding="utf-8") as fh:
            for linea in fh:
                if linea.strip() and not linea.startswith("#"):
                    partes = linea.rstrip("\n").split("\t")
                    if len(partes) >= 3:
                        triage[partes[0].strip()] = (partes[1].strip(), partes[2].strip())
    return triage


def main():
    ruta = sys.argv[1] if len(sys.argv) > 1 else "reports/zap-report.json"
    umbral = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    try:
        with open(ruta, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"No se pudo leer el reporte de ZAP ({ruta}): {exc}")
        return 3

    triage = cargar_triage()
    alertas = [a for site in data.get("site", []) for a in site.get("alerts", [])]
    alertas.sort(key=lambda a: -int(a.get("riskcode", 0)))
    conteo = {k: 0 for k in RIESGOS}
    graves = 0

    print(f"{'RIESGO':<12}{'INSTANCIAS':>11}  ALERTA")
    print("-" * 78)
    for a in alertas:
        rc = str(a.get("riskcode", "0"))
        conteo[rc] = conteo.get(rc, 0) + 1
        instancias = a.get("count") or len(a.get("instances", []))
        marca = ""
        if str(a.get("pluginid")) in triage:
            marca = f"  [{triage[str(a.get('pluginid'))][0]}]"
        elif int(rc) >= umbral:
            graves += 1
        print(f"{RIESGOS.get(rc, rc):<12}{instancias:>11}  {a.get('alert') or a.get('name')} "
              f"(CWE-{a.get('cweid', '?')}){marca}")
    print("-" * 78)
    print("Resumen: " + ", ".join(f"{RIESGOS[k]}={conteo[k]}" for k in ("3", "2", "1", "0")))
    aplicados = [p for p in triage if any(str(a.get("pluginid")) == p for a in alertas)]
    for p in aplicados:
        print(f"Triage plugin {p}: {triage[p][0]} - {triage[p][1]}")

    if graves:
        print(f"RESULTADO: {graves} tipo(s) de alerta con riesgo {RIESGOS[str(umbral)]} o superior sin triage.")
        return 1
    print(f"RESULTADO: sin alertas de riesgo {RIESGOS[str(umbral)]} o superior pendientes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
