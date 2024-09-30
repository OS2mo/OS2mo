# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import pytest
from more_itertools import one

from ..conftest import GraphAPIPost


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
    response = graphapi_post(
        manager_query, variables=dict(filter=filter), url="/graphql/v22"
    )
    assert response.errors is None
    assert len(response.data["managers"]["objects"]) == expected

    # Org-unit filters are implicit in org-unit manager queries, and thus ignored here
    if "org_units" in filter:
        return

    manager_query = """
        query OrgUnitManagers($filter: ManagerFilter!) {
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
    response = graphapi_post(
        manager_query, variables=dict(filter=filter), url="/graphql/v22"
    )
    assert response.errors is None
    org_unit = one(response.data["org_units"]["objects"])
    assert len(org_unit["current"]["managers"]) == expected
