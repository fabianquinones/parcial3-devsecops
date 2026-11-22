# Base
FROM python:3.10-slim AS base
WORKDIR /app
COPY app_vulnerable/requirements.txt .
RUN pip install -r requirements.txt
COPY app_vulnerable/ .

# Pruebas
FROM base AS test
RUN pip install pytest==8.3.3 pytest-cov==6.0.0
WORKDIR /work
COPY app_vulnerable/ ./app_vulnerable/
COPY tests/ ./tests/
ENV APP_DIR=/work/app_vulnerable
RUN echo "[run]" > .coveragerc && echo "relative_files = True" >> .coveragerc
CMD ["python", "-m", "pytest", "tests", "-v", "--junitxml=/reports/junit.xml", "--cov=app_vulnerable", "--cov-report=xml:/reports/coverage.xml"]

# Producción
FROM base AS prod
EXPOSE 5000
CMD ["flask", "--app", "app", "--debug", "run", "--host", "0.0.0.0", "--port", "5000"]
