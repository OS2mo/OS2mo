# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import os

import pytest
from fastapi.testclient import TestClient

from oio_rest.app import create_app
from oio_rest.db.testing import ensure_testing_database_exists
from oio_rest.db.testing import teardown_testing_database


# Parts of the LoRa test suite assume that Keycloak authentication is turned on.
# We turn it on here before running the actual test suite.
os.environ["LORA_AUTH"] = "true"


@pytest.fixture(scope="session")
def tests_setup_and_teardown():
    # Will be executed before the first test
    ensure_testing_database_exists()

    yield

    # Will be executed after the last test
    teardown_testing_database()


@pytest.fixture(scope="session")
def lora_client() -> TestClient:
    app = create_app()
    client = TestClient(app)
    return client
