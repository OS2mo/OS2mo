# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from unittest.mock import AsyncMock
from unittest.mock import patch
from uuid import UUID
from uuid import uuid4

import pytest
from fastapi.encoders import jsonable_encoder
from hypothesis import given
from hypothesis import strategies as st

from mora import mapping
from mora.graphapi.shim import execute_graphql
from mora.graphapi.versions.latest.graphql_utils import get_uuids
from mora.graphapi.versions.latest.graphql_utils import PrintableStr
from mora.graphapi.versions.v5.version import FacetCreate
from mora.graphapi.versions.v5.version import GraphQLVersion as GraphQLVersion5
from tests.conftest import GQLResponse


OPTIONAL = {
    "uuid": st.uuids(),
    "published": st.none() | st.from_regex(PrintableStr.regex),
    "parent_uuid": st.none() | st.uuids(),
}


@st.composite
def write_strat(draw):
    required = {
        "type": st.just("facet"),
        "user_key": st.from_regex(PrintableStr.regex),
        "org_uuid": st.uuids(),
    }

    st_dict = draw(st.fixed_dictionaries(required, optional=OPTIONAL))
    return st_dict


def prepare_mutator_data(test_data):
    if "type_" in test_data:
        test_data["type"] = test_data.pop("type_")

    """Change UUID types to string."""
    for k, v in test_data.items():
        if type(v) == UUID:
            test_data[k] = str(v)

    return test_data


def prepare_query_data(test_data, query_response):
    entries_to_remove = OPTIONAL.keys()
    for k in entries_to_remove:
        test_data.pop(k, None)

    td = {k: v for k, v in test_data.items() if v is not None}

    query_dict = (
        query_response.data.get("facets").get("objects")[0]
        if isinstance(query_response.data, dict)
        else {}
    )
    query = {k: v for k, v in query_dict.items() if k in td.keys()}

    return test_data, query


"""
Facets mutator tests.

Tests are generated by Hypothesis based on FacetCreate.
"""


@given(test_data=write_strat())
@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
async def test_create_facet(test_data, graphapi_post):
    """Integrationtest for create facet mutator."""

    test_data["org_uuid"] = await get_uuids(mapping.ORG, graphapi_post)

    mutate_query = """
        mutation CreateFacet($input: FacetCreateInput!) {
            facet_create(input: $input) {
                uuid
            }
        }
    """

    test_data = prepare_mutator_data(test_data)

    mut_response: GQLResponse = graphapi_post(
        query=mutate_query, variables={"input": test_data}, url="/graphql/v5"
    )

    assert mut_response.data
    response_uuid = (
        mut_response.data.get("facet_create", {}).get("uuid", {})
        if isinstance(mut_response.data, dict)
        else {}
    )

    """Query data to check that it actually gets written to database"""
    query_query = """
        query ($uuid: [UUID!]!) {
            facets(uuids: $uuid) {
                objects {
                    uuid
                    type
                    org_uuid
                    user_key
                    published
                    parent_uuid
                }
            }
        }
    """
    query_response = await execute_graphql(
        query=query_query,
        variable_values={"uuid": str(response_uuid)},
        graphql_version=GraphQLVersion5,
    )

    test_data, query = prepare_query_data(test_data, query_response)

    """Assert response returned by mutation."""
    assert mut_response.errors is None
    assert mut_response.data
    if test_data.get("uuid"):
        assert response_uuid == test_data["uuid"]

    """Assert response returned by quering data written."""
    assert query_response.errors is None
    assert query == test_data


@given(test_data=write_strat())
@patch("mora.graphapi.versions.v5.version.create_facet", new_callable=AsyncMock)
async def test_unit_create_class(create_facet: AsyncMock, test_data: FacetCreate):
    """Unit test for create facet mutator."""

    query = """
        mutation CreateFacet($input: FacetCreateInput!){
            facet_create(input: $input){
                uuid
            }
        }
    """

    if test_data.get("uuid"):
        created_uuid = test_data["uuid"]
    else:
        created_uuid = uuid4()
    create_facet.return_value = created_uuid

    payload = jsonable_encoder(test_data)

    response = await execute_graphql(
        query=query,
        variable_values={"input": payload},
        graphql_version=GraphQLVersion5,
    )

    assert response.errors is None
    assert response.data == {"facet_create": {"uuid": str(created_uuid)}}
