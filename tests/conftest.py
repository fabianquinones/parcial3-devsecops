import importlib
import os
import sys

import pytest

APP_DIR = os.environ.get("APP_DIR") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.abspath(APP_DIR))

app_module = importlib.import_module("app")


@pytest.fixture
def module():
    return app_module


@pytest.fixture
def flask_app():
    app_module.app.config["TESTING"] = True
    return app_module.app


@pytest.fixture
def client(flask_app):
    return flask_app.test_client()
