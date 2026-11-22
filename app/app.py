import logging
import os
import re

from flask import Flask, request
from markupsafe import escape
from prometheus_client import Counter
from prometheus_flask_exporter import PrometheusMetrics

# Configuración
app = Flask(__name__)  # NOSONAR
app.config["DEBUG"] = False

# Registro y métricas
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
security_log = logging.getLogger("security")

metrics = PrometheusMetrics(app)
metrics.info("app_info", "Información de la aplicación", version="corregida")
INPUT_REJECTED = Counter("input_rejected_total", "Entradas rechazadas por validación", ["endpoint"])
INPUT_REJECTED.labels(endpoint="hello")

# Validación de entrada
NAME_MAX = int(os.environ.get("NAME_MAX_LENGTH", "50"))
NAME_PATTERN = re.compile(r"^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ' -]+$")


# Cabeceras de seguridad
@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Cache-Control"] = "no-store"
    return response


# Endpoint /hello
@app.route("/hello")
def hello():
    name = request.args.get("name", "").strip()

    if not name:
        name = "invitado"
    elif len(name) > NAME_MAX or not NAME_PATTERN.fullmatch(name):
        INPUT_REJECTED.labels(endpoint="hello").inc()
        security_log.warning("entrada_rechazada endpoint=/hello valor=%r ip=%s",
                             name[:80], request.remote_addr)
        return "Nombre inválido", 400, {"Content-Type": "text/plain; charset=utf-8"}

    return f"Hello, {escape(name)}!"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
