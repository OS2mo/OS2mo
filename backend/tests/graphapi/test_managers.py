# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock
from unittest.mock import patch
from uuid import UUID

import pytest
from fastapi.encoders import jsonable_encoder
from hypothesis import given
from hypothesis import HealthCheck
from hypothesis import settings
from hypothesis import strategies as st
from more_itertools import one

from ..conftest import GraphAPIPost
from .utils import fetch_class_uuids
from .utils import fetch_employee_validity
from .utils import fetch_org_unit_validity
from mora.graphapi.gmodels.mo import Validity as RAValidity
from mora.graphapi.shim import execute_graphql
from mora.graphapi.versions.latest.models import ManagerCreate
from mora.graphapi.versions.latest.models import ManagerUpdate
from mora.util import POSITIVE_INFINITY


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
def test_query_all(graphapi_post: GraphAPIPost):
    """Test that we can query all attributes of the manager data model."""
    query = """
        query {
            managers {
                objects {
                    uuid
                    objects {
                        uuid
                        user_key
                        employee_uuid
                        manager_level_uuid
                        manager_type_uuid
                        org_unit_uuid
                        responsibility_uuids
                        type
                        validity {from to}
                    }
                }
            }
        }
    """
    response = graphapi_post(query)
    assert response.errors is None
    assert response.data


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
@pytest.mark.parametrize(
    "filter,expected",
    [
        ({}, 1),
        # Employee filters
        ({"employees": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a"}, 1),
        ({"employees": "6ee24785-ee9a-4502-81c2-7697009c9053"}, 0),
        (
            {
                "employees": [
                    "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
                    "6ee24785-ee9a-4502-81c2-7697009c9053",
                ]
            },
            1,
        ),
        # Organisation Unit filter
        ({"org_units": "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e"}, 1),
        ({"org_units": "2874e1dc-85e6-4269-823a-e1125484dfd3"}, 0),
        (
            {
                "org_units": [
                    "2874e1dc-85e6-4269-823a-e1125484dfd3",
                    "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e",
                ]
            },
            1,
        ),
        # Mixed filters
        (
            {
                "employees": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
                "org_units": "2874e1dc-85e6-4269-823a-e1125484dfd3",
            },
            0,
        ),
        (
            {
                "employees": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
                "org_units": "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e",
            },
            1,
        ),
        # UUID filter
        ({"uuids": "05609702-977f-4869-9fb4-50ad74c6999a"}, 1),
        ({"uuids": "fa11c0de-baad-baaad-baad-cafebabebad"}, 0),
        # Responsibility filters
        ({"responsibility": {"uuids": "4311e351-6a3c-4e7e-ae60-8a3b2938fbd6"}}, 1),
        ({"responsibility": {"uuids": "fa11c0de-baad-baaad-baad-cafebabebad"}}, 0),
        ({"responsibility": {"user_keys": "fak"}}, 1),
        ({"responsibility": {"user_keys": "failcode"}}, 0),
    ],
)
async def test_manager_filters(graphapi_post: GraphAPIPost, filter, expected) -> None:
    """Test filters on managers."""
    manager_query = """
        query Managers($filter: ManagerFilter!) {
            managers(filter: $filter) {
                objects {
                    uuid
                }
            }
        }
    """
    response = graphapi_post(manager_query, variables=dict(filter=filter))
    assert response.errors is None
    assert len(response.data["managers"]["objects"]) == expected

    # Org-unit filters are implicit in org-unit manager queries, and thus ignored here
    if "org_units" in filter:
        return

    manager_query = """
        query OrgUnitManagers($filter: OrgUnitsboundmanagerfilter!) {
            org_units(filter: {uuids: "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e"}) {
                objects {
                    current {
                        managers(filter: $filter) {
                            uuid
                        }
                    }
                }
            }
        }
    """
    response = graphapi_post(manager_query, variables=dict(filter=filter))
    assert response.errors is None
    org_unit = one(response.data["org_units"]["objects"])
    assert len(org_unit["current"]["managers"]) == expected


@given(test_data=...)
@patch("mora.graphapi.versions.latest.mutators.create_manager", new_callable=AsyncMock)
async def test_create_manager_mutation_unit_test(
    create_manager: AsyncMock, test_data: ManagerCreate
) -> None:
    """Tests that the mutator function for creating a manager passes through, with the
    defined pydantic model."""

    mutation = """
        mutation CreateManager($input: ManagerCreateInput!) {
            manager_create(input: $input) {
                uuid
            }
        }
    """

    create_manager.return_value = test_data.uuid

    payload = jsonable_encoder(test_data)
    response = await execute_graphql(query=mutation, variable_values={"input": payload})
    assert response.errors is None
    assert response.data == {"manager_create": {"uuid": str(test_data.uuid)}}

    create_manager.assert_called_with(test_data)


@settings(
    suppress_health_check=[
        # Running multiple tests on the same database is okay in this instance
        HealthCheck.function_scoped_fixture,
    ],
)
@given(data=st.data())
@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
async def test_create_manager_integration_test(
    data, graphapi_post: GraphAPIPost, employee_uuids, org_uuids
) -> None:
    """Test that managers can be created in LoRa via GraphQL."""

    # This must be done as to not receive validation errors of the employee upon
    # creating the employee conflicting the dates.
    employee_uuid = data.draw(st.sampled_from(employee_uuids))
    parent_from, parent_to = fetch_employee_validity(graphapi_post, employee_uuid)

    test_data_validity_start = data.draw(
        st.datetimes(min_value=parent_from, max_value=parent_to or datetime.max)
    )
    if parent_to:
        test_data_validity_end_strat = st.datetimes(
            min_value=test_data_validity_start, max_value=parent_to
        )
    else:
        test_data_validity_end_strat = st.none() | st.datetimes(
            min_value=test_data_validity_start,
        )

    manager_level_uuids = fetch_class_uuids(graphapi_post, "manager_level")
    manager_type_uuids = fetch_class_uuids(graphapi_post, "manager_type")
    responsibility_uuids = fetch_class_uuids(graphapi_post, "responsibility")

    test_data = data.draw(
        st.builds(
            ManagerCreate,
            uuid=st.uuids() | st.none(),
            person=st.just(employee_uuid),
            responsibility=st.just(responsibility_uuids),
            org_unit=st.sampled_from(org_uuids),
            manager_type=st.sampled_from(manager_type_uuids),
            manager_level=st.sampled_from(manager_level_uuids),
            validity=st.builds(
                RAValidity,
                from_date=st.just(test_data_validity_start),
                to_date=test_data_validity_end_strat,
            ),
        )
    )

    mutation = """
        mutation CreateManager($input: ManagerCreateInput!) {
            manager_create(input: $input) {
                uuid
            }
        }
    """
    response = graphapi_post(mutation, {"input": jsonable_encoder(test_data)})
    assert response.errors is None
    uuid = UUID(response.data["manager_create"]["uuid"])

    verify_query = """
        query VerifyQuery($uuid: UUID!) {
            managers(filter: {uuids: [$uuid], from_date: null, to_date: null}) {
                objects {
                    objects {
                        user_key
                        type
                        employee: employee_uuid
                        responsibility: responsibility_uuids
                        org_unit: org_unit_uuid
                        manager_type: manager_type_uuid
                        manager_level: manager_level_uuid
                        validity {
                            from
                            to
                        }
                    }
                }
            }
        }
    """

    response = graphapi_post(verify_query, {"uuid": str(uuid)})
    assert response.errors is None
    obj = one(one(response.data["managers"]["objects"])["objects"])

    responsibility_list = [
        UUID(responsibility) for responsibility in obj["responsibility"]
    ]

    assert responsibility_list == test_data.responsibility
    assert UUID(obj["org_unit"]) == test_data.org_unit
    assert UUID(obj["employee"]) == test_data.person
    assert UUID(obj["manager_type"]) == test_data.manager_type
    assert UUID(obj["manager_level"]) == test_data.manager_level
    assert obj["user_key"] == test_data.user_key or str(uuid)

    assert (
        datetime.fromisoformat(obj["validity"]["from"]).date()
        == test_data.validity.from_date.date()
    )

    # FYI: "backend/mora/util.py::to_iso_date()" does a check for POSITIVE_INFINITY.year
    if (
        not test_data.validity.to_date
        or test_data.validity.to_date.year == POSITIVE_INFINITY.year
    ):
        assert obj["validity"]["to"] is None
    else:
        assert (
            datetime.fromisoformat(obj["validity"]["to"]).date()
            == test_data.validity.to_date.date()
        )


@settings(
    suppress_health_check=[
        # Running multiple tests on the same database is okay in this instance
        HealthCheck.function_scoped_fixture,
    ],
)
@given(data=st.data())
@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
async def test_create_multiple_managers_integration_test(
    data, graphapi_post: GraphAPIPost, org_uuids, employee_uuids
) -> None:
    """Test that multiple managers can be created using the list mutator."""

    org_uuid = data.draw(st.sampled_from(org_uuids))
    org_from, org_to = fetch_org_unit_validity(graphapi_post, org_uuid)

    test_data_validity_start = data.draw(
        st.datetimes(min_value=org_from, max_value=org_to or datetime.max)
    )
    if org_to:
        test_data_validity_end_strat = st.datetimes(
            min_value=test_data_validity_start, max_value=org_to
        )
    else:
        test_data_validity_end_strat = st.none() | st.datetimes(
            min_value=test_data_validity_start,
        )

    manager_type_uuids = fetch_class_uuids(graphapi_post, "manager_type")
    manager_level_uuids = fetch_class_uuids(graphapi_post, "manager_level")
    responsibility_uuids = fetch_class_uuids(graphapi_post, "responsibility")

    test_data = data.draw(
        st.lists(
            st.builds(
                ManagerCreate,
                org_unit=st.just(org_uuid),
                person=st.sampled_from(employee_uuids),
                manager_type=st.sampled_from(manager_type_uuids),
                manager_level=st.sampled_from(manager_level_uuids),
                responsibility=st.just(responsibility_uuids),
                validity=st.builds(
                    RAValidity,
                    from_date=st.just(test_data_validity_start),
                    to_date=test_data_validity_end_strat,
                ),
            ),
        )
    )

    CREATE_MANAGERS_QUERY = """
        mutation CreateManagers($input: [ManagerCreateInput!]!) {
            managers_create(input: $input) {
                uuid
            }
        }
    """

    response = graphapi_post(
        CREATE_MANAGERS_QUERY, {"input": jsonable_encoder(test_data)}
    )
    assert response.errors is None
    uuids = [manager["uuid"] for manager in response.data["managers_create"]]
    assert len(uuids) == len(test_data)


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
@pytest.mark.parametrize(
    "test_data",
    [
        {
            "uuid": "05609702-977f-4869-9fb4-50ad74c6999a",
            "user_key": None,
            "person": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
            "responsibility": None,
            "org_unit": "dad7d0ad-c7a9-4a94-969d-464337e31fec",
            "manager_level": None,
            "manager_type": None,
            "validity": {"from": "2017-01-01T00:00:00+01:00", "to": None},
        },
        {
            "uuid": "05609702-977f-4869-9fb4-50ad74c6999a",
            "user_key": None,
            "person": None,
            "responsibility": None,
            "org_unit": None,
            "manager_type": None,
            "manager_level": None,
            "validity": {"from": "2017-01-01T00:00:00+01:00", "to": None},
        },
        {
            "uuid": "05609702-977f-4869-9fb4-50ad74c6999a",
            "user_key": None,
            "person": None,
            "responsibility": ["93ea44f9-127c-4465-a34c-77d149e3e928"],
            "org_unit": None,
            "manager_level": None,
            "manager_type": None,
            "validity": {"from": "2017-01-01T00:00:00+01:00", "to": None},
        },
        {
            "uuid": "05609702-977f-4869-9fb4-50ad74c6999a",
            "user_key": "-",
            "person": None,
            "responsibility": None,
            "org_unit": "dad7d0ad-c7a9-4a94-969d-464337e31fec",
            "manager_level": "ca76a441-6226-404f-88a9-31e02e420e52",
            "manager_type": "a22f8575-89b4-480b-a7ba-b3f1372e25a4",
            "validity": {"from": "2017-01-01T00:00:00+01:00", "to": None},
        },
        {
            "uuid": "05609702-977f-4869-9fb4-50ad74c6999a",
            "user_key": "-",
            "person": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
            "responsibility": [
                "4311e351-6a3c-4e7e-ae60-8a3b2938fbd6",
                "452e1dd0-658b-477a-8dd8-efba105c06d6",
                "93ea44f9-127c-4465-a34c-77d149e3e928",
            ],
            "org_unit": "dad7d0ad-c7a9-4a94-969d-464337e31fec",
            "manager_level": "d56f174d-c45d-4b55-bdc6-c57bf68238b9",
            "manager_type": "a22f8575-89b4-480b-a7ba-b3f1372e25a4",
            "validity": {"from": "2017-01-01T00:00:00+01:00", "to": None},
        },
    ],
)
async def test_update_manager_integration_test(
    test_data, graphapi_post: GraphAPIPost
) -> None:
    """Test that managers can be updated in LoRa via GraphQL."""

    uuid = test_data["uuid"]

    query = """
        query MyQuery($uuid: UUID!) {
            managers(filter: {uuids: [$uuid]}) {
                objects {
                    objects {
                        uuid
                        user_key
                        person: employee_uuid
                        responsibility: responsibility_uuids
                        org_unit: org_unit_uuid
                        manager_type: manager_type_uuid
                        manager_level: manager_level_uuid
                        validity {
                            from
                            to
                        }
                    }
                }
            }
        }
    """
    response = graphapi_post(query, {"uuid": str(uuid)})
    assert response.errors is None

    pre_update_manager = one(one(response.data["managers"]["objects"])["objects"])

    mutation = """
        mutation UpdateManager($input: ManagerUpdateInput!) {
            manager_update(input: $input) {
                uuid
            }
        }
    """
    mutation_response = graphapi_post(mutation, {"input": jsonable_encoder(test_data)})

    assert mutation_response.errors is None

    # Writing verify query to retrieve objects containing data on the desired uuids.
    verify_query = """
        query VerifyQuery($uuid: UUID!) {
            managers(filter: {uuids: [$uuid]}){
                objects {
                    objects {
                        uuid
                        user_key
                        person: employee_uuid
                        responsibility: responsibility_uuids
                        org_unit: org_unit_uuid
                        manager_type: manager_type_uuid
                        manager_level: manager_level_uuid
                        validity {
                            from
                            to
                        }
                    }
                }
            }
        }
    """

    verify_response = graphapi_post(verify_query, {"uuid": str(uuid)})
    assert verify_response.errors is None

    manager_objects_post_update = one(
        one(verify_response.data["managers"]["objects"])["objects"]
    )

    expected_updated_manager = {
        k: v if v is not None or k == "person" else pre_update_manager[k]
        for k, v in test_data.items()
    }
    assert manager_objects_post_update == expected_updated_manager


@given(test_data=...)
@patch("mora.graphapi.versions.latest.mutators.update_manager", new_callable=AsyncMock)
async def test_update_manager_mutation_unit_test(
    update_manager: AsyncMock, test_data: ManagerUpdate
) -> None:
    """Tests that the mutator function for updating a manager passes through, with the
    defined pydantic model."""

    mutation = """
        mutation UpdateManager($input: ManagerUpdateInput!) {
            manager_update(input: $input) {
                uuid
            }
        }
    """

    update_manager.return_value = test_data.uuid

    payload = jsonable_encoder(test_data)
    response = await execute_graphql(query=mutation, variable_values={"input": payload})
    assert response.errors is None
    assert response.data == {"manager_update": {"uuid": str(test_data.uuid)}}

    update_manager.assert_called_with(test_data)


async def read_manager_validities(
    graphapi_post: GraphAPIPost, uuid: UUID
) -> list[dict[str, Any]]:
    query = """
        query ReadManager($uuid: UUID!) {
          managers(filter: {uuids: [$uuid], from_date: null, to_date: null}) {
            objects {
              objects {
                employee_uuid
                uuid
                validity {
                    from
                    to
                }
              }
            }
          }
        }
    """
    query_response = graphapi_post(query, {"uuid": str(uuid)})
    assert query_response.errors is None
    manager_validities = one(query_response.data["managers"]["objects"])
    return manager_validities["objects"]


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
async def test_update_manager_vacate_integration_test(
    graphapi_post: GraphAPIPost,
) -> None:
    """Test that managers can be vacated via GraphQL."""

    employee_uuid = UUID("53181ed2-f1de-4c4a-a8fd-ab358c2c454a")
    uuid = UUID("05609702-977f-4869-9fb4-50ad74c6999a")

    manager_validities = await read_manager_validities(graphapi_post, uuid)
    assert manager_validities == [
        {
            "employee_uuid": str(employee_uuid),
            "uuid": str(uuid),
            "validity": {"from": "2017-01-01T00:00:00+01:00", "to": None},
        }
    ]

    mutation = """
        mutation TerminateManager($input: ManagerUpdateInput!) {
            manager_update(input: $input) {
                uuid
            }
        }
    """
    input = {"uuid": uuid, "validity": {"from": datetime(2020, 1, 1)}, "person": None}
    mutation_response = graphapi_post(mutation, {"input": jsonable_encoder(input)})
    assert mutation_response.errors is None
    assert UUID(mutation_response.data["manager_update"]["uuid"]) == uuid

    # Verify change
    manager_validities = await read_manager_validities(graphapi_post, uuid)
    assert manager_validities == [
        {
            "employee_uuid": str(employee_uuid),
            "uuid": str(uuid),
            "validity": {
                "from": "2017-01-01T00:00:00+01:00",
                "to": "2019-12-31T00:00:00+01:00",
            },
        },
        {
            "employee_uuid": None,
            "uuid": str(uuid),
            "validity": {"from": "2020-01-01T00:00:00+01:00", "to": None},
        },
    ]
