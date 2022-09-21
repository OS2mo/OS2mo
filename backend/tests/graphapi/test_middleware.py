# SPDX-FileCopyrightText: 2021 - 2022 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import re
from datetime import datetime
from datetime import timedelta

import freezegun
import pytest
import strawberry
from dateutil.tz import tzutc
from fastapi.encoders import jsonable_encoder
from hypothesis import given
from hypothesis import strategies as st
from starlette_context import context

from mora.graphapi.versions.latest import dataloaders
from ramodels.mo import OpenValidity


@pytest.fixture(autouse=True)
def get_context_from_ext(monkeypatch):
    """Patch strawberry extensions to return the Starlette context in responses."""

    # We must capture is_grapqhl during execution, as it is cleared after processing
    extension_context = {}

    def seed_extension_context(self):
        extension_context.update(
            {
                "is_graphql": jsonable_encoder(context.data["is_graphql"]),
                "lora_args": jsonable_encoder(
                    context.data["lora_connector"]().defaults
                ),
            }
        )

    monkeypatch.setattr(
        strawberry.extensions.Extension,
        "on_executing_start",
        seed_extension_context,
    )

    monkeypatch.setattr(
        strawberry.extensions.Extension,
        "get_results",
        lambda *args: {
            **extension_context,
            "graphql_dates": jsonable_encoder(
                context.data["graphql_dates"], by_alias=False
            ),
        },
    )
    yield


@pytest.fixture(autouse=True)
def patch_dataloader(patch_loader, monkeypatch):
    """Automatically patch dataloader to return an empty list."""
    monkeypatch.setattr(dataloaders, "search_role_type", patch_loader([]))
    yield


@freezegun.freeze_time("1337-04-20")
def test_is_graphql(graphapi_test):
    """Test that is_graphql is set on graphql requests."""
    response = graphapi_test.post("/graphql", json={"query": "{ __typename }"})
    assert response.json()["extensions"]["is_graphql"]


@freezegun.freeze_time("1337-04-20")
def test_graphql_dates_default(graphapi_test):
    """Test default GraphQL date arguments."""
    response = graphapi_test.post("/graphql", json={"query": "{ employees { uuid } }"})
    data, errors = response.json().get("data"), response.json().get("errors")
    graphql_dates = response.json()["extensions"]["graphql_dates"]
    assert data is not None
    assert errors is None
    assert "from_date", "to_date" in graphql_dates
    now = datetime.now(tz=tzutc())
    assert graphql_dates["from_date"] == now.isoformat()
    assert graphql_dates["to_date"] == (now + timedelta(milliseconds=1)).isoformat()


@freezegun.freeze_time("1337-04-20")
@given(dates=st.builds(OpenValidity))
def test_graphql_dates_explicit(graphapi_test, dates):
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
    graphql_dates = response.json()["extensions"]["graphql_dates"]
    assert data is not None
    assert errors is None
    assert graphql_dates == dates.dict()


@given(
    dates=st.tuples(st.datetimes(), st.datetimes()).filter(lambda dts: dts[0] > dts[1]),
)
@freezegun.freeze_time("1337-04-20")
def test_graphql_dates_failure(graphapi_test_no_exc, dates):
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
    graphql_dates = response.json()["extensions"]["graphql_dates"]
    assert data is None
    assert errors is not None
    assert graphql_dates is None
    for error in errors:
        assert re.match(
            r"from_date .* must be less than or equal to to_date .*",
            error["message"],
        )

    # Test the specific case where from is None and to is UNSET
    response = graphapi_test_no_exc.post(
        "/graphql",
        json={"query": query, "variables": {"from_date": None}},
    )
    data, errors = response.json().get("data"), response.json().get("errors")
    graphql_dates = response.json()["extensions"]["graphql_dates"]
    assert data is None
    assert errors is not None
    for error in errors:
        assert re.match(
            r"Cannot infer UNSET to_date from interval starting at -infinity",
            error["message"],
        )


@freezegun.freeze_time("1337-04-20")
def test_graphql_dates_to_lora(graphapi_test):
    """Test that GraphQL arguments propagate to the LoRa connector."""
    response = graphapi_test.post(
        "/graphql", json={"query": "{ employees (to_date: null) { uuid } }"}
    )
    lora_args = response.json()["extensions"]["lora_args"]
    now = datetime.now(tz=tzutc())
    assert lora_args["virkningfra"] == now.isoformat()
    assert lora_args["virkningtil"] == (now + timedelta(milliseconds=1)).isoformat()
