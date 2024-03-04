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
from hypothesis import HealthCheck
from hypothesis import settings
from hypothesis import strategies as st
from more_itertools import one

from ..conftest import GraphAPIPost
from .strategies import graph_data_momodel_validity_strat
from mora import util
from mora.auth.keycloak.oidc import noauth
from mora.graphapi.shim import execute_graphql
from mora.graphapi.versions.latest.classes import ClassCreate
from mora.graphapi.versions.latest.graphql_utils import PrintableStr

# Helpers
# -------------------
OPTIONAL = {
    "published": st.sampled_from(["Publiceret", "IkkePubliceret"]),
    "scope": st.none() | st.from_regex(PrintableStr.regex),
    "parent_uuid": st.none() | st.uuids(),
    "example": st.none() | st.from_regex(PrintableStr.regex),
    "owner": st.none() | st.uuids(),
}


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


def read_classes_helper(
    graphapi_post: GraphAPIPost, query: str, extract: str
) -> dict[UUID, Any]:
    response = graphapi_post(query)
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


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
def test_query_all(graphapi_post: GraphAPIPost):
    """Test that we can query all attributes of the classes data model."""
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
                        it_system_uuid
                        validity {
                            from
                            to
                        }
                    }
                }
            }
        }
    """
    response = graphapi_post(query)
    assert response.errors is None
    assert response.data


@settings(
    suppress_health_check=[
        # Running multiple tests on the same database is okay in this instance
        HealthCheck.function_scoped_fixture,
    ],
)
@given(
    test_data=graph_data_momodel_validity_strat(
        ClassCreate,
        now=datetime.datetime.combine(
            datetime.datetime(2016, 1, 1).date(), datetime.time.min
        ),
    )
)
@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
async def test_integration_create_class(test_data, graphapi_post: GraphAPIPost) -> None:
    """Integrationtest for create class mutator."""

    test_data_model = ClassCreate(**test_data)

    mutate_query = """
        mutation CreateClass($input: ClassCreateInput!) {
          class_create(input: $input) {
            uuid
          }
        }
    """

    # test_data = prepare_mutator_data(test_data)
    create_payload = {
        **test_data_model.dict(),
        "validity": {
            "from": test_data_model.validity.from_date.date(),
            "to": test_data_model.validity.to_date.date()
            if test_data_model.validity.to_date
            else None,
        },
    }

    mut_response = graphapi_post(
        query=mutate_query, variables={"input": jsonable_encoder(create_payload)}
    )

    assert mut_response.errors is None
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
                user_key
                name
                facet_uuid
                validity {
                    from
                    to
                }
              }
            }
          }
        }
    """
    query_response = await execute_graphql(
        query=query_query,
        variable_values={"uuid": str(response_uuid)},
    )

    assert query_response.errors is None
    assert query_response.data

    created_class = one(query_response.data.get("classes")["objects"])["current"]
    assert created_class == {
        "uuid": response_uuid,
        "type": "class",
        "user_key": test_data_model.user_key,
        "name": test_data_model.name,
        "facet_uuid": str(test_data_model.facet_uuid),
        "validity": {
            "from": datetime.datetime.combine(
                test_data_model.validity.from_date.date(), datetime.time.min
            )
            .replace(tzinfo=util.DEFAULT_TIMEZONE)
            .isoformat(),
            "to": datetime.datetime.combine(
                (test_data_model.validity.to_date - datetime.timedelta(days=1)).date(),
                datetime.time.min,
            )
            .replace(tzinfo=util.DEFAULT_TIMEZONE)
            .isoformat()
            if test_data_model.validity.to_date
            and test_data_model.validity.to_date.year != util.POSITIVE_INFINITY.year
            else None,
        },
    }


@given(
    test_data=graph_data_momodel_validity_strat(
        ClassCreate,
        now=datetime.datetime.combine(
            datetime.datetime(2016, 1, 1).date(), datetime.time.min
        ),
    )
)
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
@pytest.mark.usefixtures("fixture_db")
@pytest.mark.parametrize(
    "filter,expected",
    [
        ({}, 39),
        # Facet filters
        # -------------
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
        # Scope filters
        # -------------
        ({"scope": ""}, 0),
        ({"scope": "360NoScope"}, 0),
        # Address type scopes
        ({"scope": "DAR"}, 2),
        ({"scope": "EMAIL"}, 2),
        ({"scope": "EAN"}, 1),
        ({"scope": "PHONE"}, 2),
        ({"scope": "WWW"}, 0),
        # Text input scopes
        ({"scope": "TEXT"}, 6),
        ({"scope": "INTEGER"}, 0),
        # Engagement type scopes
        ({"scope": "10"}, 1),
        ({"scope": "1000"}, 1),
    ],
)
async def test_class_filter(graphapi_post: GraphAPIPost, filter, expected) -> None:
    """Test class filters on classes."""
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
    response = graphapi_post(class_query, variables=dict(filter=filter))
    assert response.errors is None
    assert len(response.data["classes"]["objects"]) == expected


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
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
@pytest.mark.usefixtures("fixture_db")
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
                validity {
                    from
                    to
                }
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
        "validity": {
            "from": "2016-01-01T00:00:00+01:00",
            "to": None,
        },
    }

    update_query = """
        mutation UpdateClass($input: ClassUpdateInput!) {
            class_update(input: $input) {
                uuid
            }
        }
    """

    dt_now = datetime.datetime.combine(
        datetime.datetime.now().date(), datetime.time.min
    ).replace(tzinfo=util.DEFAULT_TIMEZONE)

    response = await execute_graphql(
        query=update_query,
        variable_values={
            "input": {
                "uuid": class_uuid,
                "name": "Postal Address",
                "user_key": klass["user_key"],
                "facet_uuid": klass["facet_uuid"],
                "validity": {"from": dt_now.date().isoformat()},
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
        "validity": {
            "from": dt_now.isoformat(),
            "to": None,
        },
    }


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
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
    response = graphapi_post(
        mutation,
        {"input": {"uuid": str(class_to_terminate), "to": "1990-01-01"}},
    )
    assert response.errors is None
    assert response.data
    terminated_uuid = UUID(response.data["class_terminate"]["uuid"])
    assert terminated_uuid == class_to_terminate

    # Verify class history
    new_class_map = read_history(graphapi_post)
    assert new_class_map.keys() == set(classes_map.keys())

    # Verify class history
    class_history = new_class_map[terminated_uuid]
    assert class_history == [
        {
            "uuid": str(class_to_terminate),
            "user_key": "Niveau1",
            "validity": {
                "from": "1900-01-01T00:00:00+01:00",
                "to": "1990-01-01T00:00:00+01:00",
            },
        }
    ]


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
async def test_integration_it_system() -> None:
    role_type_facet_uuid = "68ba77bc-4d57-43e2-9c24-0c9eda5fddc7"
    sap_it_system_uuid = "14466fb0-f9de-439c-a6c2-b3262c367da7"
    ad_it_system_uuid = "59c135c9-2b15-41cc-97c8-b5dff7180beb"

    # Create
    create_response = await execute_graphql(
        query="""
            mutation Create($facet_uuid: UUID!, $it_system_uuid: UUID!) {
              class_create(
                input: {
                    facet_uuid: $facet_uuid,
                    user_key: "test",
                    name: "test",
                    it_system_uuid: $it_system_uuid,
                    validity: {from: "2010-02-03"}
                }
              ) {
                uuid
              }
            }
        """,
        variable_values={
            "facet_uuid": role_type_facet_uuid,
            "it_system_uuid": sap_it_system_uuid,
        },
    )
    assert create_response.errors is None
    class_uuid = create_response.data["class_create"]["uuid"]

    # Verify
    read_query = """
        query Read($uuid: UUID!) {
          classes(filter: {uuids: [$uuid]}) {
            objects {
              current {
                it_system {
                  uuid
                }
              }
            }
          }
        }
    """
    response = await execute_graphql(
        query=read_query,
        variable_values={"uuid": class_uuid},
    )
    assert response.errors is None
    assert response.data == {
        "classes": {
            "objects": [{"current": {"it_system": {"uuid": sap_it_system_uuid}}}]
        }
    }

    # Update
    update_response = await execute_graphql(
        query="""
            mutation Update(
                $class_uuid: UUID!,
                $facet_uuid: UUID!,
                $it_system_uuid: UUID!,
            ) {
              class_update(
                input: {
                    uuid: $class_uuid,
                    facet_uuid: $facet_uuid,
                    user_key: "test",
                    name: "test",
                    it_system_uuid: $it_system_uuid,
                    validity: {from: "2020-03-04"}
                }
              ) {
                uuid
              }
            }
        """,
        variable_values={
            "class_uuid": class_uuid,
            "facet_uuid": role_type_facet_uuid,
            "it_system_uuid": ad_it_system_uuid,
        },
    )
    assert update_response.errors is None

    # Verify
    response = await execute_graphql(
        query=read_query,
        variable_values={"uuid": class_uuid},
    )
    assert response.errors is None
    assert response.data == {
        "classes": {
            "objects": [{"current": {"it_system": {"uuid": ad_it_system_uuid}}}]
        }
    }


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
async def test_integration_it_system_filter() -> None:
    role_type_facet_uuid = "68ba77bc-4d57-43e2-9c24-0c9eda5fddc7"
    sap_it_system_uuid = "14466fb0-f9de-439c-a6c2-b3262c367da7"
    ad_it_system_uuid = "59c135c9-2b15-41cc-97c8-b5dff7180beb"

    # Create
    create_mutation = """
        mutation Create(
            $facet_uuid: UUID!,
            $it_system_uuid: UUID!,
            $user_key: String!,
        ) {
          class_create(
            input: {
                facet_uuid: $facet_uuid,
                user_key: $user_key,
                name: "test",
                it_system_uuid: $it_system_uuid,
                validity: {from: "2010-02-03"}
            }
          ) {
            uuid
          }
        }
    """
    await execute_graphql(
        query=create_mutation,
        variable_values={
            "facet_uuid": role_type_facet_uuid,
            "it_system_uuid": sap_it_system_uuid,
            "user_key": "sap",
        },
    )
    await execute_graphql(
        query=create_mutation,
        variable_values={
            "facet_uuid": role_type_facet_uuid,
            "it_system_uuid": ad_it_system_uuid,
            "user_key": "ad",
        },
    )

    # Filter SAP
    read_query = """
        query Read($it_system_uuid: UUID!) {
          classes(filter: {it_system: {uuids: [$it_system_uuid]}}) {
            objects {
              current {
                user_key
              }
            }
          }
        }
    """
    response = await execute_graphql(
        query=read_query,
        variable_values={"it_system_uuid": sap_it_system_uuid},
    )
    assert response.errors is None
    assert response.data == {"classes": {"objects": [{"current": {"user_key": "sap"}}]}}

    # Filter AD
    response = await execute_graphql(
        query=read_query,
        variable_values={"it_system_uuid": ad_it_system_uuid},
    )
    assert response.errors is None
    assert response.data == {"classes": {"objects": [{"current": {"user_key": "ad"}}]}}
