import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000").rstrip("/")
RAFAGA = int(sys.argv[2]) if len(sys.argv) > 2 else 50

XSS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><svg onload=alert(1)>",
       "<iframe src=javascript:alert(1)>", "<body onload=alert(document.cookie)>"]
NOMBRES = ["Ana", "Pedro", "Camila", "José", "Valentina", "Matías", "Sofía", "Benjamín"]
INYECCIONES = ["{{7*7}}", "' OR '1'='1", "../../etc/passwd", "; cat /etc/passwd", "A" * 300]


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        return 0, str(exc)


def hello(valor):
    return get("/hello?" + urllib.parse.urlencode({"name": valor}))


def fase(nombre, codigos, extra=""):
    print(f"{nombre:<34} -> " + ", ".join(f"HTTP {k}: {v}" for k, v in sorted(codigos.items())) + extra)


def main():
    print(f"Simulación de incidente contra {BASE}\n")

    rutas = ["/admin", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/backup.zip",
             "/config.php", "/server-status", "/console", "/api/v1/users"]
    fase("1. Enumeración de rutas", Counter(get(r)[0] for r in rutas * 2))

    resultados = [hello(p) + (p,) for p in XSS]
    reflejados = sum(1 for _, cuerpo, p in resultados if p in cuerpo)
    fase("2. XSS reflejado en /hello", Counter(c for c, _, _ in resultados),
         f"  | payloads reflejados SIN escapar: {reflejados}/{len(XSS)}")

    fase("3. Inyecciones en /hello", Counter(hello(p)[0] for p in INYECCIONES))

    print(f"4. Ráfaga de tráfico mixto durante {RAFAGA} s ...")
    codigos, fin, i = Counter(), time.time() + RAFAGA, 0
    while time.time() < fin:
        valor = XSS[i % len(XSS)] if i % 2 else NOMBRES[i % len(NOMBRES)]
        codigos[hello(valor)[0]] += 1
        i += 1
        time.sleep(0.05)
    fase("   Ráfaga", codigos, f"  | {i} peticiones (~{i / RAFAGA:.0f} req/s)")

    print("\nRevisa Grafana (http://localhost:3000) y Prometheus (http://localhost:9090/alerts).")


if __name__ == "__main__":
    main()
