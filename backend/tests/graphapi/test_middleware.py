#!/usr/bin/env python3
# --------------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2021 - 2022 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
import re
from datetime import datetime

import freezegun
import pytest
import strawberry
from dateutil.tz import tzutc
from fastapi.encoders import jsonable_encoder
from hypothesis import given
from hypothesis import strategies as st
from ramodels.mo import OpenValidity
from starlette_context import context

import mora.graphapi.dataloaders as dataloaders

# --------------------------------------------------------------------------------------
# Code
# --------------------------------------------------------------------------------------
pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def get_context_from_ext(monkeypatch):
    """Patch strawberry extensions to return the Starlette context in responses."""
    monkeypatch.setattr(
        strawberry.extensions.Extension,
        "get_results",
        lambda *args: {
            "is_graphql": jsonable_encoder(context.data["is_graphql"]),
            "graphql_args": jsonable_encoder(context.data["graphql_args"]),
            "lora_args": jsonable_encoder(context.data["lora_connector"]().defaults),
        },
    )
    yield


@pytest.fixture(autouse=True)
def patch_dataloader(patch_loader, monkeypatch):
    """Automatically patch dataloader to return an empty list."""
    monkeypatch.setattr(dataloaders, "search_role_type", patch_loader([]))
    yield


@freezegun.freeze_time("1337-04-20")
class TestMiddleware:
    """Class collecting tests of our GraphQL specific Starlette middleware."""

    def test_is_graphql(self, graphapi_test):
        """Test that is_graphql is set on graphql requests."""
        response = graphapi_test.post("/graphql", json={"query": "{ __typename }"})
        assert response.json()["extensions"]["is_graphql"]

    def test_graphql_args_default(self, graphapi_test):
        """Test default GraphQL date arguments."""
        response = graphapi_test.post(
            "/graphql", json={"query": "{ employees { uuid } }"}
        )
        data, errors = response.json().get("data"), response.json().get("errors")
        graphql_args = response.json()["extensions"]["graphql_args"]
        assert data is not None
        assert errors is None
        assert "from_date", "to_date" in graphql_args
        assert graphql_args["from_date"] == datetime.now(tz=tzutc()).isoformat()
        assert graphql_args["to_date"] is None

    @given(dates=st.builds(OpenValidity))
    def test_graphql_args_explicit(self, graphapi_test, dates):
        """Test explicit GraphQL date arguments."""
        query = """
                query TestQuery($from_date: DateTime, $to_date: DateTime) {
                    employees(from_date: $from_date, to_date: $to_date) {
                        uuid
                    }
                }
                """
        response = graphapi_test.post(
            "/graphql",
            json={
                "query": query,
                "variables": {"from_date": dates.from_date, "to_date": dates.to_date},
            },
        )
        data, errors = response.json().get("data"), response.json().get("errors")
        graphql_args = response.json()["extensions"]["graphql_args"]
        assert data is not None
        assert errors is None
        assert graphql_args == dates.dict()

    @given(
        dates=st.tuples(st.datetimes(), st.datetimes()).filter(
            lambda dts: dts[0] > dts[1]
        ),
    )
    def test_graphql_args_failure(self, graphapi_test_no_exc, dates):
        """Test failing GraphQL date arguments.

        We use a test client that silences server side errors in order to
        check GraphQL's error response.
        """
        query = """
                query TestQuery($from_date: DateTime, $to_date: DateTime) {
                    employees(from_date: $from_date, to_date: $to_date) {
                        uuid
                    }
                }
                """
        dates = jsonable_encoder(dates)
        response = graphapi_test_no_exc.post(
            "/graphql",
            json={
                "query": query,
                "variables": {
                    "from_date": dates[0],
                    "to_date": dates[1],
                },
            },
        )
        data, errors = response.json().get("data"), response.json().get("errors")
        graphql_args = response.json()["extensions"]["graphql_args"]
        assert data is None
        assert errors is not None
        assert graphql_args == dict()
        for error in errors:
            assert re.match(
                r"from_date .* must be less than or equal to to_date .*",
                error["message"],
            )

    def test_graphql_args_to_lora(self, graphapi_test):
        """Test that GraphQL arguments propagate to the LoRa connector."""
        response = graphapi_test.post(
            "/graphql", json={"query": "{ employees { uuid } }"}
        )
        lora_args = response.json()["extensions"]["lora_args"]
        assert lora_args["virkningfra"] == datetime.now(tz=tzutc()).isoformat()
        assert lora_args["virkningtil"] == "infinity"
