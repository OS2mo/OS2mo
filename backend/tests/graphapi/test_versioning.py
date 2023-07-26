# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import itertools

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from mora.auth.keycloak.oidc import auth
from mora.graphapi.main import graphql_versions
from mora.graphapi.main import setup_graphql
from mora.graphapi.versions.base import BaseGraphQLVersion
from mora.graphapi.versions.latest.version import LatestGraphQLVersion
from tests.conftest import fake_auth


def get_test_client(
    versions: list[type[BaseGraphQLVersion]] | None = None,
) -> TestClient:
    app = FastAPI()
    app.dependency_overrides[auth] = fake_auth
    setup_graphql(app, versions=versions)
    return TestClient(app)


@pytest.fixture(scope="session")
def test_client() -> TestClient:
    return get_test_client()


def test_latest_not_exposed_directly():
    """The latest version should never be exposed directly, as we want clients to pin to
    a specific one."""
    assert LatestGraphQLVersion not in graphql_versions


def test_all_versions_have_version_number():
    for version in graphql_versions:
        assert isinstance(version.version, int)


def test_increasing_version_numbers():
    for a, b in itertools.pairwise(graphql_versions):
        assert b.version == a.version + 1


def test_unversioned_get_redirects_to_newest(test_client: TestClient):
    newest = graphql_versions[-1]
    response = test_client.get("/graphql", follow_redirects=False)
    assert response.is_redirect
    assert response.headers["location"] == f"/graphql/v{newest.version}"


def test_non_existent():
    class ActiveGraphQLVersion(LatestGraphQLVersion):
        version = 2

    test_client = get_test_client(
        versions=[
            ActiveGraphQLVersion,
        ]
    )
    # Previous (now non-existent) versions are GONE
    assert test_client.get("/graphql/v1").status_code == 410
    # Active versions resolve
    assert test_client.get("/graphql/v2").status_code == 200
    # Future versions are NOT FOUND
    assert test_client.get("/graphql/v3").status_code == 404
