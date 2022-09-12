# SPDX-FileCopyrightText: 2021- Magenta ApS
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
from uuid import UUID

import pytest
from hypothesis import given
from hypothesis import settings
from hypothesis import strategies as st
from pydantic import parse_obj_as
from pytest import MonkeyPatch
from strawberry.schema import Schema
from strawberry.types.execution import ExecutionResult

import mora.lora as lora
from .strategies import graph_data_strat
from .strategies import graph_data_uuids_strat
from mora.graphapi.versions.latest import dataloaders
from mora.graphapi.versions.latest.graphql_utils import PrintableStr
from mora.graphapi.versions.latest.models import FacetCreate
from mora.graphapi.versions.latest.version import LatestGraphQLSchema
from mora.graphapi.versions.latest.version import LatestGraphQLVersion
from ramodels.mo import FacetRead
from tests.conftest import GQLResponse

# --------------------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------------------


@given(test_data=graph_data_strat(FacetRead))
def test_query_all(test_data, graphapi_post, patch_loader):
    """Test that we can query all attributes of the facets data model."""
    # Patch dataloader
    with MonkeyPatch.context() as patch:
        # Our facet dataloaders are ~* special *~
        # We need to intercept the connector too
        patch.setattr(lora.Scope, "get_all", patch_loader({}))
        patch.setattr(
            dataloaders,
            "lora_facets_to_mo_facets",
            lambda *args, **kwargs: parse_obj_as(list[FacetRead], test_data),
        )
        query = """
            query {
                facets {
                    uuid
                    user_key
                    description
                    parent_uuid
                    org_uuid
                    published
                    type
                }
            }
        """
        response: GQLResponse = graphapi_post(query)

    assert response.errors is None
    assert response.data
    assert response.data["facets"] == test_data



@given(test_input=graph_data_uuids_strat(FacetRead))
def test_query_by_uuid(test_input, graphapi_post, patch_loader):
    """Test that we can query facets by UUID."""
    test_data, test_uuids = test_input

    # Patch dataloader
    with MonkeyPatch.context() as patch:
        # Our facet dataloaders are ~* special *~
        # We need to intercept the connector too
        patch.setattr(lora.Scope, "get_all_by_uuid", patch_loader({}))
        patch.setattr(
            dataloaders,
            "lora_facets_to_mo_facets",
            lambda *args, **kwargs: parse_obj_as(list[FacetRead], test_data),
        )
        query = """
                query TestQuery($uuids: [UUID!]) {
                    facets(uuids: $uuids) {
                        uuid
                    }
                }
            """
        response: GQLResponse = graphapi_post(query, {"uuids": test_uuids})

    assert response.errors is None
    assert response.data

    # Check UUID equivalence
    result_uuids = [facet.get("uuid") for facet in response.data["facets"]]
    assert set(result_uuids) == set(test_uuids)
    assert len(result_uuids) == len(set(test_uuids))

    @given(test_input=graph_data_uuids_strat(FacetRead))
    def test_query_by_uuid(self, test_input, graphapi_post, patch_loader):
        """Test that we can query facets by UUID."""
        test_data, test_uuids = test_input

        # Patch dataloader
        with MonkeyPatch.context() as patch:
            # Our facet dataloaders are ~* special *~
            # We need to intercept the connector too
            patch.setattr(lora.Scope, "get_all_by_uuid", patch_loader({}))
            patch.setattr(
                dataloaders,
                "lora_facets_to_mo_facets",
                lambda *args, **kwargs: parse_obj_as(list[FacetRead], test_data),
            )
            query = """
                    query TestQuery($uuids: [UUID!]) {
                        facets(uuids: $uuids) {
                            uuid
                        }
                    }
                """
            response: GQLResponse = graphapi_post(query, {"uuids": test_uuids})

        assert response.errors is None
        assert response.data

        # Check UUID equivalence
        result_uuids = [facet.get("uuid") for facet in response.data["facets"]]
        assert set(result_uuids) == set(test_uuids)
        assert len(result_uuids) == len(set(test_uuids))


OPTIONAL = {
    "published": st.none() | st.from_regex(PrintableStr.regex),
    "parent_uuid": st.none() | st.uuids(),
}


@st.composite
def write_strat(draw):
    required = {
        "uuid": st.uuids(),
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

    td_keys = td.keys()
    query_dict = (
        query_response.data["facets"][0]
        if isinstance(query_response.data, dict)
        else {}
    )
    query = {k: v for k, v in query_dict.items() if k in td_keys}

    if not test_data["user_key"]:
        test_data["user_key"] = test_data["uuid"]

    return test_data, query


"""Facets mutator tests.

Tests are generated by Hypothesis based on FacetCreate.
"""


@pytest.mark.usefixtures("load_fixture_data_with_reset")
@settings(max_examples=20)
@given(test_data=write_strat())
async def test_create_facet(self, test_data):
    """Test that we can write all attributes of the facets data model."""

    mutate_query = """
                    mutation CreateFacet($input: FacetCreateInput!){
                        facet_create(input: $input){
                                                    uuid
                                                    }
                    }
                    """

    test_data = prepare_mutator_data(test_data)

    mut_response = await LatestGraphQLSchema.get().execute(
        mutate_query, variable_values={"input": test_data}
    )

    response_uuid = mut_response.data.get("facet_create", {}).get(
        "uuid", "Error in response_uuid"
    )

    """Query data to check that it actually gets written to database"""
    query_query = """query ($uuid: [UUID!]!)
                    {
                        __typename
                        facets(uuids: $uuid)
                        {
                        uuid
                        type
                        org_uuid
                        user_key
                        published
                        parent_uuid
                        }
                    }

                """
    graphql_version = LatestGraphQLVersion
    context_value = await graphql_version.get_context()

    query_response = await LatestGraphQLSchema.get().execute(
        query=query_query,
        variable_values={"uuid": str(response_uuid)},
        context_value=context_value,
    )

    test_data, query = prepare_query_data(test_data, query_response)

    """Assert response returned by mutation."""
    assert mut_response.errors is None
    assert mut_response.data
    assert response_uuid == test_data["uuid"]

    """Assert response returned by quering data written."""
    assert query_response.errors is None
    assert query == test_data

    """Test exception gets raised if illegal values are entered"""


@pytest.mark.parametrize(
    "input",
    [
        (
            {
                "uuid": "23d891b5-85aa-4eee-bec7-e84fe21883c5",
                "type_": "class",
                "user_key": "\x01",
                "org_uuid": "8d6c00dd-4be9-4bdb-a558-1f85183cd920",
            }
        ),
        (
            {
                "uuid": "23d891b5-85aa-4eee-bec7-e84fe21883c5",
                "type_": "class",
                "user_key": "",
                "org_uuid": "8d6c00dd-4be9-4bdb-a558-1f85183cd920",
            }
        ),
    ],
)
def test_write_fails(self, uuid, type_, user_key, name, org_uuid):

    with pytest.raises(Exception):
        FacetCreate(uuid, user_key, type_, name, org_uuid)


@pytest.fixture(scope="class")
def patch_query():
    def patcher(arg, query, variable_values):
        uuid = variable_values["input"].get("uuid")
        data = {"uuid": uuid}
        return ExecutionResult(data=data, errors=None, extensions=None)

    return patcher


@given(test_data=write_strat())
async def test_unit_create_class(test_data, patch_query):
    """Unit test for create facet mutator."""

    with MonkeyPatch.context() as patch:
        patch.setattr(Schema, "execute", patch_query)
        query = """
                mutation CreateFacet($input: FacetCreateInput!){
                    facet_create(input: $input){
                                                uuid
                                                }
                }
                """

        variable_values = {"input": test_data}
        response = LatestGraphQLSchema.get().execute(
            query=query, variable_values=variable_values
        )

        response_uuid = response.data.get("uuid", None)

    assert response.data
    assert response_uuid == test_data["uuid"]
