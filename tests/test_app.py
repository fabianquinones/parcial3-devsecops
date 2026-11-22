import os
import re

import pytest


# Pruebas funcionales

def test_hello_funciona(client):
    resp = client.get("/hello", query_string={"name": "TEST"})
    assert resp.status_code == 200
    assert resp.get_data(as_text=True) == "Hello, TEST!"


def test_hello_acepta_nombres_con_tildes(client):
    resp = client.get("/hello", query_string={"name": "José Ñuñez"})
    assert resp.status_code == 200
    assert "José Ñuñez" in resp.get_data(as_text=True)


# Pruebas de seguridad

@pytest.mark.parametrize("payload", [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg onload=alert(1)>",
])
def test_vuln01_xss_reflejado_no_se_refleja_sin_escapar(client, payload):
    resp = client.get("/hello", query_string={"name": payload})
    cuerpo = resp.get_data(as_text=True)
    assert payload not in cuerpo
    assert "<script" not in cuerpo.lower() and "onerror=" not in cuerpo.lower()


def test_vuln02_debug_desactivado(module, flask_app):
    assert flask_app.debug is False
    with open(module.__file__, encoding="utf-8") as fh:
        fuente = fh.read()
    assert not re.search(r"debug\s*=\s*True", fuente), "El código no debe activar debug=True"


def test_vuln03_entrada_ausente_no_muestra_none(client):
    resp = client.get("/hello")
    assert resp.status_code == 200
    assert "None" not in resp.get_data(as_text=True)


@pytest.mark.parametrize("valor", ["A" * 500, "admin; DROP TABLE users", "{{7*7}}", "../../etc/passwd"])
def test_vuln03_entrada_invalida_se_rechaza(client, valor):
    resp = client.get("/hello", query_string={"name": valor})
    assert resp.status_code == 400


def test_vuln04_cabeceras_de_seguridad(client):
    resp = client.get("/hello", query_string={"name": "TEST"})
    assert "Content-Security-Policy" in resp.headers
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"


def test_vuln05_dependencias_con_version_fijada(module):
    req = os.path.join(os.path.dirname(os.path.abspath(module.__file__)), "requirements.txt")
    with open(req, encoding="utf-8") as fh:
        lineas = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    assert lineas, "requirements.txt vacío"
    assert all("==" in l for l in lineas), "Todas las dependencias deben tener versión exacta"
