# SPDX-FileCopyrightText: 2021- Magenta ApS
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
from fastapi.encoders import jsonable_encoder
from hypothesis import given
from pytest import MonkeyPatch
from ramodels.mo.details import AddressRead

import mora.graphapi.dataloaders as dataloaders
from .strategies import graph_data_strat
from .strategies import graph_data_uuids_strat
from mora.graphapi.address import terminate_addr
from mora.graphapi.models import AddressTerminate
from mora.graphapi.shim import flatten_data
from tests.conftest import GQLResponse

# --------------------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------------------


class TestAddresssQuery:
    """Class collecting addresses query tests.

    Data loaders are mocked to return specific values, generated via
    Hypothesis.
    MonkeyPatch.context is used as a context manager to achieve this,
    because mocks are *not* reset between invocations of Hypothesis examples.
    """

    @given(test_data=graph_data_strat(AddressRead))
    def test_query_all(self, test_data, graphapi_post, patch_loader):
        """Test that we can query all attributes of the address data model."""
        # JSON encode test data
        test_data = jsonable_encoder(test_data)

        # Patch dataloader
        with MonkeyPatch.context() as patch:
            patch.setattr(dataloaders, "search_role_type", patch_loader(test_data))
            query = """
                query {
                    addresses {
                        uuid
                        objects {
                            uuid
                            user_key
                            address_type_uuid
                            employee_uuid
                            org_unit_uuid
                            engagement_uuid
                            visibility_uuid
                            type
                            value
                            value2
                            validity {from to}
                        }
                    }
                }
            """
            response: GQLResponse = graphapi_post(query)

        assert response.errors is None
        assert response.data
        assert flatten_data(response.data["addresses"]) == test_data

    @given(test_input=graph_data_uuids_strat(AddressRead))
    def test_query_by_uuid(self, test_input, graphapi_post, patch_loader):
        """Test that we can query addresses by UUID."""
        test_data, test_uuids = test_input

        # Patch dataloader
        with MonkeyPatch.context() as patch:
            patch.setattr(dataloaders, "get_role_type_by_uuid", patch_loader(test_data))
            query = """
                    query TestQuery($uuids: [UUID!]) {
                        addresses(uuids: $uuids) {
                            uuid
                        }
                    }
                """
            response: GQLResponse = graphapi_post(query, {"uuids": test_uuids})

        assert response.errors is None
        assert response.data

        # Check UUID equivalence
        result_uuids = [addr.get("uuid") for addr in response.data["addresses"]]
        assert set(result_uuids) == set(test_uuids)
        assert len(result_uuids) == len(set(test_uuids))

    def test_terminate(self):
        # Init
        at = AddressTerminate()

        # Invoke
        result = terminate_addr()
