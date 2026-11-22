# Base
FROM python:3.15-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY app/requirements.txt .
RUN pip install -r requirements.txt
COPY app/ .

# Pruebas
FROM base AS test
RUN pip install pytest==8.3.3 pytest-cov==6.0.0
WORKDIR /work
COPY app/ ./app/
COPY tests/ ./tests/
ENV APP_DIR=/work/app
RUN echo "[run]" > .coveragerc && echo "relative_files = True" >> .coveragerc
CMD ["python", "-m", "pytest", "tests", "-v", "--junitxml=/reports/junit.xml", "--cov=app", "--cov-report=xml:/reports/coverage.xml"]

# Producción
FROM base AS prod
RUN useradd --create-home --uid 10001 appuser
USER appuser
EXPOSE 5000
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/hello?name=health', timeout=2)" || exit 1
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--access-logfile", "-", "app:app"]
