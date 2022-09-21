# SPDX-FileCopyrightText: 2021- Magenta ApS
# SPDX-License-Identifier: MPL-2.0
from hypothesis import given
from pytest import MonkeyPatch

from .strategies import graph_data_strat
from .strategies import graph_data_uuids_strat
from mora.graphapi.shim import flatten_data
from mora.graphapi.versions.latest import dataloaders
from ramodels.mo.details import LeaveRead
from tests.conftest import GQLResponse


@given(test_data=graph_data_strat(LeaveRead))
def test_query_all(test_data, graphapi_post, patch_loader):
    """Test that we can query all attributes of the leave data model."""
    # Patch dataloader
    with MonkeyPatch.context() as patch:
        patch.setattr(dataloaders, "search_role_type", patch_loader(test_data))
        query = """
            query {
                leaves {
                    uuid
                    objects {
                        uuid
                        user_key
                        employee_uuid
                        engagement_uuid
                        leave_type_uuid
                        type
                        validity {from to}
                    }
                }
            }
        """
        response: GQLResponse = graphapi_post(query)

    assert response.errors is None
    assert response.data
    assert flatten_data(response.data["leaves"]) == test_data


@given(test_input=graph_data_uuids_strat(LeaveRead))
def test_query_by_uuid(test_input, graphapi_post, patch_loader):
    """Test that we can query leaves by UUID."""
    test_data, test_uuids = test_input

    # Patch dataloader
    with MonkeyPatch.context() as patch:
        patch.setattr(dataloaders, "get_role_type_by_uuid", patch_loader(test_data))
        query = """
                query TestQuery($uuids: [UUID!]) {
                    leaves(uuids: $uuids) {
                        uuid
                    }
                }
            """
        response: GQLResponse = graphapi_post(query, {"uuids": test_uuids})

    assert response.errors is None
    assert response.data

    # Check UUID equivalence
    result_uuids = [leave.get("uuid") for leave in response.data["leaves"]]
    assert set(result_uuids) == set(test_uuids)
    assert len(result_uuids) == len(set(test_uuids))
