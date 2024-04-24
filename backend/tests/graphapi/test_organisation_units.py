# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from datetime import datetime
from functools import partial
from unittest.mock import AsyncMock
from unittest.mock import patch
from uuid import UUID
from uuid import uuid4

import pytest
from hypothesis import given
from hypothesis import HealthCheck
from hypothesis import settings
from hypothesis import strategies as st
from more_itertools import one
from strawberry import UNSET
from strawberry.unset import UnsetType

from ..conftest import GraphAPIPost
from .utils import fetch_class_uuids
from .utils import fetch_org_unit_validity
from .utils import gen_read_parent
from .utils import gen_set_parent
from .utils import sjsonable_encoder
from mora.graphapi.shim import execute_graphql
from mora.graphapi.versions.latest.inputs import OrganisationUnitCreateInput
from mora.graphapi.versions.latest.inputs import OrganisationUnitUpdateInput
from mora.util import POSITIVE_INFINITY
from ramodels.mo import Validity as RAValidity


validity_builder = st.builds(
    RAValidity,
    from_date=st.datetimes(
        min_value=datetime(1970, 1, 1), max_value=datetime(2000, 1, 1)
    ),
    to_date=st.none(),
)


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
def test_query_all(graphapi_post: GraphAPIPost):
    """Test that we can query all our organisation units."""
    query = """
        query {
            org_units {
                objects {
                    uuid
                    objects {
                        uuid
                        user_key
                        name
                        type
                        validity {from to}
                        parent_uuid
                        unit_type_uuid
                        org_unit_hierarchy
                        org_unit_level_uuid
                        time_planning_uuid
                    }
                }
            }
        }
    """
    response = graphapi_post(query)
    assert response.errors is None
    assert response.data


@given(test_data=st.builds(OrganisationUnitCreateInput, validity=validity_builder))
@patch("mora.graphapi.versions.latest.mutators.create_org_unit", new_callable=AsyncMock)
async def test_create_org_unit(
    create_org_unit: AsyncMock, test_data: OrganisationUnitCreateInput
) -> None:
    """Test that pydantic jsons are passed through to create_org_unit."""

    mutate_query = """
        mutation CreateOrgUnit($input: OrganisationUnitCreateInput!) {
            org_unit_create(input: $input) {
                uuid
            }
        }
    """
    created_uuid = uuid4()
    create_org_unit.return_value = created_uuid

    payload = sjsonable_encoder(test_data)
    response = await execute_graphql(
        query=mutate_query, variable_values={"input": payload}
    )
    assert response.errors is None
    assert response.data == {"org_unit_create": {"uuid": str(created_uuid)}}

    create_org_unit.assert_called_once()


@settings(
    suppress_health_check=[
        # Running multiple tests on the same database is okay in this instance
        HealthCheck.function_scoped_fixture,
    ],
)
@given(data=st.data())
@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
def test_create_org_unit_integration_test(
    data, graphapi_post: GraphAPIPost, org_uuids
) -> None:
    """Test that organisation units can be created in LoRa via GraphQL."""
    # org_uuids = fetch_org_uuids(graphapi_post)

    parent_uuid = data.draw(st.sampled_from(org_uuids))
    parent_from, parent_to = fetch_org_unit_validity(graphapi_post, parent_uuid)

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

    org_unit_type_uuids = fetch_class_uuids(graphapi_post, "org_unit_type")
    time_planning_uuids = fetch_class_uuids(graphapi_post, "time_planning")
    org_unit_level_uuids = fetch_class_uuids(graphapi_post, "org_unit_level")

    test_data = data.draw(
        st.builds(
            OrganisationUnitCreateInput,
            uuid=st.uuids(),
            # TODO: Allow all text
            name=st.text(
                alphabet=st.characters(whitelist_categories=("L",)), min_size=1
            ),
            parent=st.just(parent_uuid),
            org_unit_type=st.sampled_from(org_unit_type_uuids),
            time_planning=st.sampled_from(time_planning_uuids),
            org_unit_level=st.sampled_from(org_unit_level_uuids),
            # TODO: Handle org_unit_hierarchy as we do with the above
            # NOTE: org_unit_hierarchy does not exist in the sample data
            org_unit_hierarchy=st.none(),
            validity=st.builds(
                RAValidity,
                from_date=st.just(test_data_validity_start),
                to_date=test_data_validity_end_strat,
            ),
        )
    )
    payload = sjsonable_encoder(test_data)

    mutate_query = """
        mutation CreateOrgUnit($input: OrganisationUnitCreateInput!) {
            org_unit_create(input: $input) {
                uuid
            }
        }
    """
    response = graphapi_post(mutate_query, {"input": payload})
    assert response.errors is None
    assert response.data is not None
    uuid = UUID(response.data["org_unit_create"]["uuid"])

    verify_query = """
        query VerifyQuery($uuid: UUID!) {
            org_units(filter: {uuids: [$uuid], from_date: null, to_date: null}) {
                objects {
                    objects {
                        uuid
                        user_key
                        name
                        parent_uuid
                        unit_type_uuid
                        time_planning_uuid
                        org_unit_level_uuid
                        org_unit_hierarchy_uuid: org_unit_hierarchy
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
    assert response.data is not None
    obj = one(one(response.data["org_units"]["objects"])["objects"])
    assert obj["name"] == test_data.name
    assert obj["user_key"] == test_data.user_key or str(uuid)
    assert UUID(obj["parent_uuid"]) == test_data.parent
    assert UUID(obj["unit_type_uuid"]) == test_data.org_unit_type
    assert UUID(obj["time_planning_uuid"]) == test_data.time_planning
    assert UUID(obj["org_unit_level_uuid"]) == test_data.org_unit_level
    # assert UUID(obj["org_unit_hierarchy_uuid"]) == test_data.org_unit_hierarchy
    assert obj["org_unit_hierarchy_uuid"] is None
    assert test_data.org_unit_hierarchy is None

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


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
@pytest.mark.parametrize(
    "filter,expected",
    [
        ({}, 10),
        # Filter roots
        ({"parents": None}, 3),
        # Filter under node
        ({"parents": "2874e1dc-85e6-4269-823a-e1125484dfd3"}, 4),
        ({"parents": "b1f69701-86d8-496e-a3f1-ccef18ac1958"}, 1),
        (
            {
                "parents": [
                    "2874e1dc-85e6-4269-823a-e1125484dfd3",
                    "b1f69701-86d8-496e-a3f1-ccef18ac1958",
                ]
            },
            5,
        ),
    ],
)
async def test_org_unit_parent_filter(
    graphapi_post: GraphAPIPost, filter, expected
) -> None:
    """Test parent filter on organisation units."""
    org_unit_query = """
        query OrgUnit($filter: OrganisationUnitFilter!) {
            org_units(filter: $filter) {
                objects {
                    uuid
                }
            }
        }
    """
    response = graphapi_post(org_unit_query, variables=dict(filter=filter))
    assert response.errors is None
    assert len(response.data["org_units"]["objects"]) == expected


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
@pytest.mark.parametrize(
    "filter,expected",
    [
        # Filter none
        ({}, 10),
        ({"hierarchies": None}, 10),
        # Filter 'linjeorg'
        ({"hierarchies": "f805eb80-fdfe-8f24-9367-68ea955b9b9b"}, 2),
        # Filter 'hidden'
        ({"hierarchies": "8c30ab5a-8c3a-566c-bf12-790bdd7a9fef"}, 1),
        # Filter 'selvejet'
        ({"hierarchies": "69de6410-bfe7-bea5-e6cc-376b3302189c"}, 1),
        # Filter 'linjeorg' + 'hidden'
        (
            {
                "hierarchies": [
                    "f805eb80-fdfe-8f24-9367-68ea955b9b9b",
                    "8c30ab5a-8c3a-566c-bf12-790bdd7a9fef",
                ]
            },
            3,
        ),
    ],
)
async def test_org_unit_hierarchy_filter(
    graphapi_post: GraphAPIPost, filter, expected
) -> None:
    """Test hierarchies filter on organisation units."""
    org_unit_query = """
        query OrgUnit($filter: OrganisationUnitFilter!) {
            org_units(filter: $filter) {
                objects {
                    uuid
                }
            }
        }
    """
    response = graphapi_post(org_unit_query, variables=dict(filter=filter))
    assert response.errors is None
    assert len(response.data["org_units"]["objects"]) == expected


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
async def test_org_unit_subtree_filter(graphapi_post: GraphAPIPost) -> None:
    """Test subtree filter on organisation units."""
    # Ensure that the subtree filter respects the date filtering by changing the tree
    # from 'root > skole-børn > it_sup' to 'root > skole-børn | it_sup'.
    root = "2874e1dc-85e6-4269-823a-e1125484dfd3"
    skole_born = "dad7d0ad-c7a9-4a94-969d-464337e31fec"
    it_sup = "fa2e23c9-860a-4c90-bcc6-2c0721869a25"
    response = graphapi_post(
        """
        mutation MoveOrgUnit($uuid: UUID!, $parent: UUID!) {
          org_unit_update(
            input: {
                uuid: $uuid,
                parent: $parent,
                validity: {from: "2024-04-04"},
            }
          ) {
            uuid
          }
        }
        """,
        {
            "uuid": it_sup,
            "parent": root,
        },
    )
    assert response.errors is None

    subtree_query = """
        query SubtreeQuery($from_date: DateTime, $to_date: DateTime) {
          org_units(
            filter: {
              from_date: $from_date,
              to_date: $to_date,
              subtree: {
                user_keys: "it_sup",
                from_date: $from_date,
                to_date: $to_date,
              }
            }
          ) {
            objects {
              validities {
                user_key
                uuid
                parent { uuid }
              }
            }
          }
        }
    """
    # Querying before the change should give us the original tree
    response = graphapi_post(
        subtree_query,
        {
            "from_date": "2023-03-03",
            "to_date": "2023-03-04",
        },
    )
    assert response.errors is None
    assert response.data is not None
    assert response.data["org_units"]["objects"] == [
        {
            "validities": [
                {
                    "user_key": "root",
                    "uuid": root,
                    "parent": None,
                }
            ]
        },
        {
            "validities": [
                {
                    "user_key": "it_sup",
                    "uuid": it_sup,
                    "parent": {"uuid": skole_born},
                }
            ]
        },
        {
            "validities": [
                {
                    "user_key": "skole-børn",
                    "uuid": skole_born,
                    "parent": {"uuid": root},
                }
            ]
        },
    ]

    # Querying after the change should give us the new tree
    response = graphapi_post(
        subtree_query,
        {
            "from_date": "2025-05-05",
            "to_date": "2025-05-06",
        },
    )
    assert response.errors is None
    assert response.data is not None
    assert response.data["org_units"]["objects"] == [
        {
            "validities": [
                {
                    "user_key": "root",
                    "uuid": root,
                    "parent": None,
                }
            ]
        },
        {
            "validities": [
                {
                    "user_key": "it_sup",
                    "uuid": it_sup,
                    "parent": {"uuid": root},
                }
            ]
        },
    ]


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
@pytest.mark.parametrize(
    "test_data",
    [
        {
            "uuid": "dad7d0ad-c7a9-4a94-969d-464337e31fec",
            "validity": {"from": "2017-01-01T00:00:00+01:00", "to": None},
        },
        {
            "uuid": "dad7d0ad-c7a9-4a94-969d-464337e31fec",
            "user_key": "-",
            "validity": {"from": "2017-01-01T00:00:00+01:00", "to": None},
        },
        {
            "uuid": "dad7d0ad-c7a9-4a94-969d-464337e31fec",
            "user_key": "Testing user key for tests",
            "name": "Testing name for tests",
            "parent": "2874e1dc-85e6-4269-823a-e1125484dfd3",
            "org_unit_type": "32547559-cfc1-4d97-94c6-70b192eff825",
            "time_planning": "27935dbb-c173-4116-a4b5-75022315749d",
            "org_unit_level": "0f015b67-f250-43bb-9160-043ec19fad48",
            "org_unit_hierarchy": "89b6cef8-3d03-49ac-816f-f7530b383411",
            "validity": {"from": "2020-01-01T00:00:00+01:00", "to": None},
        },
        {
            "uuid": "dad7d0ad-c7a9-4a94-969d-464337e31fec",
            "user_key": "skole-børn",
            "name": "Skole og Børn",
            "parent": "2874e1dc-85e6-4269-823a-e1125484dfd3",
            "org_unit_type": "4311e351-6a3c-4e7e-ae60-8a3b2938fbd6",
            "validity": {"from": "2017-01-01T00:00:00+01:00", "to": None},
        },
    ],
)
async def test_update_org_unit_mutation_integration_test(
    graphapi_post: GraphAPIPost, test_data
) -> None:
    """Test that organisation units can be updated in LoRa via GraphQL."""
    # NOTE: A similar tests exists in test_v21.py
    #       However that test will eventually be deleted, while this should remain

    uuid = test_data["uuid"]

    query = """
        query OrgUnitQuery($uuid: UUID!) {
            org_units(filter: {uuids: [$uuid]}) {
                objects {
                    current {
                        uuid
                        user_key
                        name
                        parent: parent_uuid
                        org_unit_type: unit_type_uuid
                        time_planning: time_planning_uuid
                        org_unit_level: org_unit_level_uuid
                        org_unit_hierarchy: org_unit_hierarchy
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
    assert response.data is not None
    obj = one(response.data["org_units"]["objects"])
    assert obj["current"] is not None
    pre_update_org_unit = obj["current"]

    mutate_query = """
        mutation UpdateOrgUnit($input: OrganisationUnitUpdateInput!) {
            org_unit_update(input: $input) {
                uuid
            }
        }
    """
    mutation_response = graphapi_post(
        mutate_query, {"input": sjsonable_encoder(test_data)}
    )
    assert mutation_response.errors is None

    response = graphapi_post(query, {"uuid": str(uuid)})
    assert response.errors is None
    assert response.data is not None
    obj = one(response.data["org_units"]["objects"])
    assert obj["current"] is not None
    post_update_org_unit = obj["current"]

    expected_updated_org_unit = {
        k: test_data.get(k) or v for k, v in pre_update_org_unit.items()
    }

    assert post_update_org_unit == expected_updated_org_unit


@given(test_data=st.builds(OrganisationUnitUpdateInput, validity=validity_builder))
@patch("mora.graphapi.versions.latest.mutators.update_org_unit", new_callable=AsyncMock)
async def test_update_org_unit_mutation_unit_test(
    update_org_unit: AsyncMock, test_data: OrganisationUnitUpdateInput
) -> None:
    """Tests that the mutator function for takes our input type."""

    mutation = """
        mutation UpdateOrganisationUnit($input: OrganisationUnitUpdateInput!) {
            org_unit_update(input: $input) {
                uuid
            }
        }
    """

    update_org_unit.return_value = test_data.uuid

    payload = sjsonable_encoder(test_data)

    response = await execute_graphql(query=mutation, variable_values={"input": payload})
    assert response.errors is None
    assert response.data == {"org_unit_update": {"uuid": str(test_data.uuid)}}

    update_org_unit.assert_called_once()


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
@pytest.mark.parametrize(
    "expected",
    [
        {
            "user_key": "social_og_sundhed-løn",
            "uuid": "5942ce50-2be8-476f-914b-6769a888a7c8",
            "ancestors": [
                {
                    "uuid": "b1f69701-86d8-496e-a3f1-ccef18ac1958",
                    "user_key": "løn",
                    "name": "Lønorganisation",
                    "type": "org_unit",
                    "validity": {"from": "2017-01-01T00:00:00+01:00", "to": None},
                }
            ],
        },
        {
            "user_key": "social-sundhed",
            "uuid": "68c5d78e-ae26-441f-a143-0103eca8b62a",
            "ancestors": [
                {
                    "uuid": "2874e1dc-85e6-4269-823a-e1125484dfd3",
                    "user_key": "root",
                    "name": "Overordnet Enhed",
                    "type": "org_unit",
                    "validity": {"from": "2016-01-01T00:00:00+01:00", "to": None},
                }
            ],
        },
        {
            "user_key": "fil",
            "uuid": "85715fc7-925d-401b-822d-467eb4b163b6",
            "ancestors": [
                {
                    "uuid": "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e",
                    "user_key": "hum",
                    "name": "Humanistisk fakultet",
                    "type": "org_unit",
                    "validity": {"from": "2016-12-31T00:00:00+01:00", "to": None},
                },
                {
                    "uuid": "2874e1dc-85e6-4269-823a-e1125484dfd3",
                    "user_key": "root",
                    "name": "Overordnet Enhed",
                    "type": "org_unit",
                    "validity": {"from": "2016-01-01T00:00:00+01:00", "to": None},
                },
            ],
        },
        {
            "user_key": "hum",
            "uuid": "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e",
            "ancestors": [
                {
                    "uuid": "2874e1dc-85e6-4269-823a-e1125484dfd3",
                    "user_key": "root",
                    "name": "Overordnet Enhed",
                    "type": "org_unit",
                    "validity": {"from": "2016-01-01T00:00:00+01:00", "to": None},
                }
            ],
        },
    ],
)
async def test_get_org_unit_ancestors(graphapi_post: GraphAPIPost, expected):
    """Tests that ancestors are properly returned on Organisation Units."""
    uuid = expected["uuid"]

    graphql_query = """
        query MyAncestorQuery($uuid: UUID!) {
          org_units(filter: {uuids: [$uuid]}) {
            objects {
              objects {
                user_key
                uuid
                ancestors {
                  uuid
                  user_key
                  name
                  type
                  validity {
                    from
                    to
                  }
                }
              }
            }
          }
        }
    """

    response = graphapi_post(query=graphql_query, variables={"uuid": str(uuid)})

    assert response.errors is None
    assert response.status_code == 200
    assert response.data is not None
    obj = one(one(response.data["org_units"]["objects"])["objects"])
    assert obj == expected
    assert len(obj) == len(expected)
    assert obj["ancestors"] == expected["ancestors"]


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
async def test_empty_user_key(graphapi_post: GraphAPIPost):
    """Test that org units with empty user keys can be created and read back out."""
    graphql_mutation = """
        mutation MyMutation {
          org_unit_create(
            input: {
              name: "Foo",
              user_key: "",
              org_unit_type: "4311e351-6a3c-4e7e-ae60-8a3b2938fbd6",
              validity: {from: "2012-03-04"}
            }
          ) {
            uuid
            current {
              user_key
            }
          }
        }
    """
    response = graphapi_post(query=graphql_mutation)
    assert response.errors is None
    assert response.data is not None
    assert response.data["org_unit_create"]["current"]["user_key"] == ""


fixture_parent_uuid = UUID("2874e1dc-85e6-4269-823a-e1125484dfd3")


@pytest.mark.integration_test
@pytest.mark.usefixtures("fixture_db")
@pytest.mark.parametrize(
    "initial,new,expected",
    [
        # Starting with UUID set
        # Using same UUID does nothing
        (fixture_parent_uuid, fixture_parent_uuid, fixture_parent_uuid),
        # Using unset does nothing
        (fixture_parent_uuid, UNSET, fixture_parent_uuid),
        # Using None clears the field
        (fixture_parent_uuid, None, None),
        # Starting with None
        # Using UUID sets UUID
        (None, fixture_parent_uuid, fixture_parent_uuid),
        # Using unset does nothing
        (None, UNSET, None),
        # Using None does nothing
        (None, None, None),
    ],
)
async def test_parent_changes(
    graphapi_post: GraphAPIPost,
    latest_graphql_url: str,
    initial: UUID | None,
    new: UUID | UnsetType | None,
    expected: UUID | None,
) -> None:
    """Test that we can change, noop and clear parent."""
    # NOTE: A similar tests exists in test_v21.py
    #       However that test will eventually be deleted, while this should remain
    url = latest_graphql_url

    uuid = UUID("dad7d0ad-c7a9-4a94-969d-464337e31fec")

    read_parent = partial(gen_read_parent, graphapi_post, url, uuid)
    set_parent = partial(gen_set_parent, graphapi_post, url, uuid)

    # Setup and assert initial state
    set_parent(initial)
    parent_uuid = read_parent()
    assert parent_uuid == initial

    # Fire our change and assert result
    set_parent(new)
    parent_uuid = read_parent()
    assert parent_uuid == expected
