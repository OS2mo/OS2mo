# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from hypothesis import given
from pytest import MonkeyPatch

from .strategies import graph_data_strat
from .strategies import graph_data_uuids_strat
from mora.graphapi.shim import flatten_data
from mora.graphapi.versions.latest import dataloaders
from ramodels.mo.details import RelatedUnitRead
from tests.conftest import GQLResponse


@given(test_data=graph_data_strat(RelatedUnitRead))
def test_query_all(test_data, graphapi_post, patch_loader):
    """Test that we can query all attributes of the related_unit data model."""
    # Patch dataloader
    with MonkeyPatch.context() as patch:
        patch.setattr(dataloaders, "search_role_type", patch_loader(test_data))
        query = """
            query {
                related_units {
                    objects {
                        uuid
                        objects {
                            uuid
                            user_key
                            org_unit_uuids
                            type
                            validity {from to}
                        }
                    }
                }
            }
        """
        response: GQLResponse = graphapi_post(query)

    assert response.errors is None
    assert response.data
    assert flatten_data(response.data["related_units"]["objects"]) == test_data


@given(test_input=graph_data_uuids_strat(RelatedUnitRead))
def test_query_by_uuid(test_input, graphapi_post, patch_loader):
    """Test that we can query related_units by UUID."""
    test_data, test_uuids = test_input

    # Patch dataloader
    with MonkeyPatch.context() as patch:
        patch.setattr(dataloaders, "get_role_type_by_uuid", patch_loader(test_data))
        query = """
                query TestQuery($uuids: [UUID!]) {
                    related_units(uuids: $uuids) {
                        objects {
                            uuid
                        }
                    }
                }
            """
        response = graphapi_post(query, {"uuids": test_uuids})

    assert response.errors is None
    assert response.data

    # Check UUID equivalence
    result_uuids = [
        related.get("uuid") for related in response.data["related_units"]["objects"]
    ]
    assert set(result_uuids) == set(test_uuids)
    assert len(result_uuids) == len(set(test_uuids))
