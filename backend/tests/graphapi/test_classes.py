# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import datetime
from functools import partial
from typing import Any
from unittest.mock import AsyncMock
from unittest.mock import patch
from uuid import UUID
from uuid import uuid4

import pytest
from fastapi.encoders import jsonable_encoder
from hypothesis import given
from hypothesis import strategies as st
from more_itertools import one
from pydantic import parse_obj_as
from pytest import MonkeyPatch

import mora.lora as lora
from .strategies import graph_data_strat
from .strategies import graph_data_uuids_strat
from mora import mapping
from mora import util
from mora.auth.keycloak.oidc import noauth
from mora.graphapi.shim import execute_graphql
from mora.graphapi.versions.latest import dataloaders
from mora.graphapi.versions.latest.classes import ClassCreate
from mora.graphapi.versions.latest.graphql_utils import get_uuids
from mora.graphapi.versions.latest.graphql_utils import PrintableStr
from ramodels.mo import ClassRead
from tests.conftest import GQLResponse


# Helpers
# -------------------
OPTIONAL = {
    "published": st.sampled_from(["Publiceret", "IkkePubliceret"]),
    "scope": st.none() | st.from_regex(PrintableStr.regex),
    "parent_uuid": st.none() | st.uuids(),
    "example": st.none() | st.from_regex(PrintableStr.regex),
    "owner": st.none() | st.uuids(),
}


@st.composite
def write_strat(draw):
    required = {
        "user_key": st.from_regex(PrintableStr.regex),
        "name": st.from_regex(PrintableStr.regex),
        "facet_uuid": st.uuids(),
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
        one(query_response.data.get("classes")["objects"])["current"]
        if isinstance(query_response.data, dict)
        else {}
    )
    query = {k: v for k, v in query_dict.items() if k in td.keys()}

    if not test_data["user_key"]:
        test_data["user_key"] = test_data["uuid"]

    return test_data, query


def read_classes_helper(graphapi_post, query: str, extract: str) -> dict[UUID, Any]:
    response: GQLResponse = graphapi_post(query)
    assert response.errors is None
    assert response.data
    return {UUID(x["uuid"]): x[extract] for x in response.data["classes"]["objects"]}


read_classes = partial(
    read_classes_helper,
    query="""
        query ReadClasses {
            classes {
                objects {
                    uuid
                    current {
                        uuid
                        user_key
                        validity {
                            from
                            to
                        }
                    }
                }
            }
        }
    """,
    extract="current",
)

read_history = partial(
    read_classes_helper,
    query="""
        query ReadClasses {
            classes(filter: {from_date: null, to_date: null}) {
                objects {
                    uuid
                    objects {
                        uuid
                        user_key
                        validity {
                            from
                            to
                        }
                    }
                }
            }
        }
    """,
    extract="objects",
)


# UNIT tests
# -------------------
@given(test_data=graph_data_strat(ClassRead))
def test_query_all(test_data, graphapi_post, graphapi_test, patch_loader):
    """Test that we can query all attributes of the classes data model."""
    # patch get_classes to return list(ClassRead)
    with MonkeyPatch.context() as patch:
        # Our class dataloaders are ~* special *~
        # We need to intercept the connector too
        patch.setattr(lora.Scope, "get_all", patch_loader({}))
        patch.setattr(
            dataloaders,
            "lora_classes_to_mo_classes",
            lambda *args, **kwargs: parse_obj_as(list[ClassRead], test_data),
        )
        query = """
            query {
                classes {
                    objects {
                        current {
                            uuid
                            user_key
                            facet_uuid
                            example
                            owner
                            org_uuid
                            name
                            parent_uuid
                            published
                            scope
                            type
                        }
                    }
                }
            }
        """
        response: GQLResponse = graphapi_post(query=query)

    assert response.errors is None
    assert response.data
    assert [x["current"] for x in response.data["classes"]["objects"]] == test_data


@given(test_input=graph_data_uuids_strat(ClassRead))
def test_query_by_uuid(test_input, graphapi_post, patch_loader):
    """Test that we can query classes by UUID."""
    test_data, test_uuids = test_input
    # Patch dataloader
    with MonkeyPatch.context() as patch:
        # Our class dataloaders are ~* special *~
        # We need to intercept the connector too
        patch.setattr(lora.Scope, "get_all_by_uuid", patch_loader({}))
        patch.setattr(
            dataloaders,
            "lora_classes_to_mo_classes",
            lambda *args, **kwargs: parse_obj_as(list[ClassRead], test_data),
        )
        query = """
                query TestQuery($uuids: [UUID!]) {
                    classes(filter: {uuids: $uuids}) {
                        objects {
                            current {
                                uuid
                            }
                        }
                    }
                }
            """
        response: GQLResponse = graphapi_post(query, {"uuids": test_uuids})

    assert response.errors is None
    assert response.data

    # Check UUID equivalence
    result_uuids = [
        cla["current"].get("uuid") for cla in response.data["classes"]["objects"]
    ]
    assert set(result_uuids) == set(test_uuids)
    assert len(result_uuids) == len(set(test_uuids))


# INTEGRATION tests
# -------------------
@given(test_data=write_strat())
@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
async def test_integration_create_class(test_data, graphapi_post) -> None:
    """Integrationtest for create class mutator."""

    test_data["facet_uuid"] = await get_uuids(mapping.FACETS, graphapi_post)

    mutate_query = """
        mutation CreateClass($input: ClassCreateInput!) {
          class_create(input: $input) {
            uuid
          }
        }
    """

    test_data = prepare_mutator_data(test_data)

    mut_response: GQLResponse = graphapi_post(
        query=mutate_query, variables={"input": test_data}
    )

    assert mut_response.data
    response_uuid = (
        mut_response.data.get("class_create", {}).get("uuid", {})
        if isinstance(mut_response.data, dict)
        else {}
    )

    """Query data to check that it actually gets written to database"""
    query_query = """
        query ($uuid: [UUID!]!) {
          classes(filter: {uuids: $uuid}) {
            objects {
              current {
                uuid
                type
                org_uuid
                user_key
                name
                facet_uuid
              }
            }
          }
        }
    """
    query_response = await execute_graphql(
        query=query_query,
        variable_values={"uuid": str(response_uuid)},
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
@patch("mora.graphapi.versions.latest.mutators.create_class", new_callable=AsyncMock)
async def test_unit_create_class(
    create_class: AsyncMock, test_data: ClassCreate
) -> None:
    """Unit test for create class mutator."""

    mutate_query = """
        mutation CreateClass($input: ClassCreateInput!){
            class_create(input: $input){
                uuid
            }
        }
    """
    if test_data.get("uuid"):
        created_uuid = test_data["uuid"]
    else:
        created_uuid = uuid4()
    create_class.return_value = created_uuid

    payload = jsonable_encoder(test_data)

    response = await execute_graphql(
        query=mutate_query,
        variable_values={"input": payload},
        context_value={"org_loader": AsyncMock(), "get_token": noauth},
    )

    assert response.errors is None
    assert response.data == {"class_create": {"uuid": str(created_uuid)}}


@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
@pytest.mark.parametrize(
    "filter,expected",
    [
        ({}, 39),
        ({"facet_user_keys": "employee_address_type"}, 3),
        ({"facets": "baddc4eb-406e-4c6b-8229-17e4a21d3550"}, 3),
        ({"facet_user_keys": "org_unit_address_type"}, 6),
        ({"facets": "3c44e5d2-7fef-4448-9bf6-449bf414ec49"}, 6),
        ({"facet_user_keys": ["employee_address_type", "org_unit_address_type"]}, 9),
        (
            {
                "facets": [
                    "baddc4eb-406e-4c6b-8229-17e4a21d3550",
                    "3c44e5d2-7fef-4448-9bf6-449bf414ec49",
                ]
            },
            9,
        ),
        (
            {
                "facet_user_keys": "employee_address_type",
                "facets": "3c44e5d2-7fef-4448-9bf6-449bf414ec49",
            },
            9,
        ),
    ],
)
async def test_class_facet_filter(graphapi_post, filter, expected) -> None:
    """Test facet filters on classes."""
    class_query = """
        query Classes($filter: ClassFilter!) {
            classes(filter: $filter) {
                objects {
                    current {
                        uuid
                    }
                }
            }
        }
    """
    response: GQLResponse = graphapi_post(class_query, variables=dict(filter=filter))
    assert response.errors is None
    assert len(response.data["classes"]["objects"]) == expected


@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
async def test_integration_delete_class() -> None:
    read_query = """
        query ($uuid: [UUID!]!) {
          classes(filter: {uuids: $uuid}) {
            objects {
              current {
                uuid
                name
              }
            }
          }
        }
    """
    class_uuid = "4e337d8e-1fd2-4449-8110-e0c8a22958ed"

    response = await execute_graphql(
        query=read_query,
        variable_values={"uuid": class_uuid},
    )
    assert response.errors is None
    assert response.data == {
        "classes": {
            "objects": [{"current": {"name": "Postadresse", "uuid": class_uuid}}]
        }
    }

    delete_query = """
        mutation ($uuid: UUID!) {
          class_delete(uuid: $uuid) {
            uuid
          }
        }
    """
    response = await execute_graphql(
        query=delete_query,
        variable_values={"uuid": class_uuid},
    )
    assert response.errors is None
    assert response.data == {"class_delete": {"uuid": class_uuid}}

    response = await execute_graphql(
        query=read_query,
        variable_values={"uuid": class_uuid},
    )
    assert response.errors is None
    assert response.data == {"classes": {"objects": []}}


@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
async def test_update_class() -> None:
    """Unit test for create class mutator."""
    read_query = """
        query ($uuid: [UUID!]!) {
          classes(filter: {uuids: $uuid}) {
            objects {
              current {
                uuid
                name
                user_key
                facet_uuid
              }
            }
          }
        }
    """
    class_uuid = "4e337d8e-1fd2-4449-8110-e0c8a22958ed"

    response = await execute_graphql(
        query=read_query,
        variable_values={"uuid": class_uuid},
    )
    assert response.errors is None
    assert one(response.data.keys()) == "classes"
    klass = one(response.data["classes"]["objects"])["current"]
    assert klass == {
        "uuid": class_uuid,
        "name": "Postadresse",
        "facet_uuid": "baddc4eb-406e-4c6b-8229-17e4a21d3550",
        "user_key": "BrugerPostadresse",
    }

    update_query = """
        mutation UpdateClass($input: ClassUpdateInput!) {
            class_update(input: $input) {
                uuid
            }
        }
    """
    response = await execute_graphql(
        query=update_query,
        variable_values={
            "input": {
                "uuid": class_uuid,
                "name": "Postal Address",
                "user_key": klass["user_key"],
                "facet_uuid": klass["facet_uuid"],
            },
        },
    )
    assert response.errors is None
    assert response.data == {"class_update": {"uuid": class_uuid}}

    response = await execute_graphql(
        query=read_query,
        variable_values={"uuid": class_uuid},
    )
    assert response.errors is None
    assert one(response.data.keys()) == "classes"
    klass = one(response.data["classes"]["objects"])["current"]
    assert klass == {
        "uuid": class_uuid,
        "name": "Postal Address",
        "facet_uuid": "baddc4eb-406e-4c6b-8229-17e4a21d3550",
        "user_key": "BrugerPostadresse",
    }

    delete_query = """
        mutation ($uuid: UUID!) {
          class_delete(uuid: $uuid) {
            uuid
          }
        }
    """
    response = await execute_graphql(
        query=delete_query,
        variable_values={"uuid": class_uuid},
    )
    assert response.errors is None
    assert response.data == {"class_delete": {"uuid": class_uuid}}

    response = await execute_graphql(
        query=read_query,
        variable_values={"uuid": class_uuid},
    )
    assert response.errors is None
    assert response.data == {"classes": {"objects": []}}

    update_query = """
        mutation UpdateClass($input: ClassUpdateInput!) {
            class_update(input: $input) {
                uuid
            }
        }
    """
    response = await execute_graphql(
        query=update_query,
        variable_values={
            "input": {
                "uuid": class_uuid,
                "name": "Postal Address",
                "user_key": klass["user_key"],
                "facet_uuid": klass["facet_uuid"],
            },
        },
    )
    assert response.errors is None
    assert response.data == {"class_update": {"uuid": class_uuid}}

    response = await execute_graphql(
        query=read_query,
        variable_values={"uuid": class_uuid},
    )
    assert response.errors is None
    assert one(response.data.keys()) == "classes"
    klass = one(response.data["classes"]["objects"])["current"]
    assert klass == {
        "uuid": class_uuid,
        "name": "Postal Address",
        "facet_uuid": "baddc4eb-406e-4c6b-8229-17e4a21d3550",
        "user_key": "BrugerPostadresse",
    }


@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
async def test_terminate_class(graphapi_post) -> None:
    """Test that we can terminate class."""

    # test class: "Niveau1"
    class_to_terminate = UUID("3c791935-2cfa-46b5-a12e-66f7f54e70fe")

    # Verify existing state
    classes_map = read_classes(graphapi_post)
    assert len(classes_map.keys()) == 39
    assert class_to_terminate in classes_map.keys()

    # Terminate the class
    mutation = """
        mutation TerminateClass($input: ClassTerminateInput!) {
            class_terminate(input: $input) {
                uuid
            }
        }
    """
    dt_now = util.now()
    response: GQLResponse = graphapi_post(
        mutation,
        {
            "input": {
                "uuid": str(class_to_terminate),
                "validity": {"to": dt_now.date().isoformat()},
            }
        },
    )

    assert response.errors is None
    assert response.data
    terminated_uuid = UUID(response.data["class_terminate"]["uuid"])
    assert terminated_uuid == class_to_terminate

    # Verify class history
    new_class_map = read_history(graphapi_post)
    assert new_class_map.keys() == set(classes_map.keys())

    # Verify facet history
    class_history = new_class_map[terminated_uuid]
    assert class_history == [
        {
            "uuid": str(class_to_terminate),
            "user_key": "Niveau1",
            "validity": {
                "from": "1900-01-01T00:00:00+01:00",
                "to": datetime.datetime.combine(dt_now.date(), datetime.time.min)
                .replace(tzinfo=util.DEFAULT_TIMEZONE)
                .isoformat(),
            },
        }
    ]
