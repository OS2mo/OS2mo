# SPDX-FileCopyrightText: 2021- Magenta ApS
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
import asyncio
import datetime
from uuid import UUID
from unittest.mock import patch
from uuid import UUID

from fastapi.encoders import jsonable_encoder
from hypothesis import given
from hypothesis import strategies as st
from pytest import MonkeyPatch

import mora.graphapi.dataloaders as dataloaders
import tests.cases
from .strategies import graph_data_strat
from .strategies import graph_data_uuids_strat
from mora import lora
from mora.graphapi.address import terminate as address_terminate
from mora.graphapi.inputs import AddressRelationInput
from mora.graphapi.main import get_schema
from mora.graphapi.models import AddressTerminate
from mora.graphapi.models import Validity
from mora.graphapi.shim import flatten_data
from mora.graphapi.versions.latest import dataloaders
from mora.graphapi.versions.latest.address import terminate_addr
from mora.graphapi.versions.latest.models import AddressTerminate
from ramodels.mo.details import AddressRead
from tests.conftest import GQLResponse

# from mora.graphapi.models import AddressType
# from mora.graphapi.models import AddressVisibility
# from mora.graphapi.models import Organisation


# --------------------------------------------------------------------------------------
# Mocks
# --------------------------------------------------------------------------------------
def async_lora_return(*args):
    """Returns last positional argument using asyncio.Future.

    This is used to mock lora.Scope methods like 'get' and 'update'."""

    f = asyncio.Future()
    f.set_result(args[-1])
    return f


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


class TestAddressCreate(tests.cases.AsyncLoRATestCase):
    # @parameterized.expand(
    #     [
    #         ("test",),
    #     ]
    # )
    async def test_mutator(self):
        # INPUT params - before using parameterized
        given_address_type = "61c22b75-01b0-4e83-954c-9cf0c8dc79fe"
        given_visibility = "940b39cd-828e-4b6d-a98c-007e512f694c"

        given_relation = {
            "type": "org_unit",
            "uuid": "3b866d97-0b1f-48e0-8078-686d96f430b4",
        }
        # given_relation = AddressRelationInput(
        #     type="org_unit",
        #     uuid=UUID("3b866d97-0b1f-48e0-8078-686d96f430b4")
        # )

        given_org = "3b866d97-0b1f-48e0-8078-686d96f430b3"

        # OBS: Below UUIDs are made up
        given_org_unit = "3b866d97-0b1f-48e0-8078-686d96f430b4"
        given_person = "3b866d97-0b1f-48e0-8078-686d96f430b5"
        given_engagement = "3b866d97-0b1f-48e0-8078-686d96f430b6"

        given_validity = Validity(from_date=datetime.datetime.now())

        given_value = "yeehaaa@magenta-aps.dk"
        # expected_result = True

        # GraphQL
        mutation_func = "address_create"
        query = (
            "mutation($value: String!, $addressType: UUID!, $visibility: UUID!, $relation: AddressRelationInput, $from: DateTime, $to: DateTime) {"
            f"{mutation_func}(input: {{value: $value, address_type: $addressType, visibility: $visibility, relation: $relation, from: $from, to: $to}})"
            "{ uuid }"
            "}"
        )

        # query = (
        #     "mutation($value: String!, $addressType: UUID!, $visibility: UUID!, "
        #     "$org: UUID, $orgUnit: UUID, $person: UUID, $engagement: UUID, "
        #     "$from: DateTime, $to: DateTime) {"
        #     f"{mutation_func}(input: {{value: $value, address_type: $addressType, "
        #     "visibility: $visibility, org: $org, org_unit: $orgUnit, person: $person, "
        #     "engagement: $engagement, from: $from, to: $to})"
        #     "{ uuid }"
        #     "}"
        # )

        # Create GraphQL arguments, starting with the required ones
        var_values = {
            "value": given_value,
            "addressType": given_address_type,
            "visibility": given_visibility,
            "relation": given_relation,
        }

        # if given_org:
        #     var_values["org"] = given_org
        #
        # if given_org_unit:
        #     var_values["orgUnit"] = given_org_unit
        #
        # if given_person:
        #     var_values["person"] = given_person
        #
        # if given_engagement:
        #     var_values["engagement"] = given_engagement

        if given_validity.from_date:
            var_values["from"] = given_validity.from_date.date().isoformat()

        if given_validity.to_date:
            var_values["to"] = given_validity.to_date.date().isoformat()

        response = await get_schema().execute(query, variable_values=var_values)
        tap = "test"


class TestAddressTerminate:
    @given(
        given_uuid=st.uuids(),
        triggerless=st.booleans(),
        given_validity_dts=st.tuples(st.datetimes() | st.none(), st.datetimes()).filter(
            lambda dts: dts[0] <= dts[1] if dts[0] and dts[1] else True
        ),
    )
    @patch.object(lora.Scope, "update", async_lora_return)
    @patch.object(lora.Scope, "get", async_lora_return)
    async def test_terminate(self, given_uuid, triggerless, given_validity_dts):
        from_date, to_date = given_validity_dts

        # The terminate logic have a check that verifies we don't use times other than:
        # 00:00:00, to the endpoint.. so if we get one of these from hypothesis, we will
        # expect an exception.
        expect_exception = False
        if to_date.time() != datetime.time.min:
            expect_exception = True

        # Configure the addr-terminate we want to perform
        at = AddressTerminate(
            uuid=given_uuid,
            triggerless=triggerless,
            from_date=from_date,
            to_date=to_date,
        )

        terminate_result_uuid = None
        caught_exception = None
        try:
            tr = await address_terminate(address_terminate=at)
            terminate_result_uuid = tr.uuid if tr else terminate_result_uuid
        except Exception as e:
            caught_exception = e

        # Assert
        if not expect_exception:
            assert terminate_result_uuid == at.uuid
        else:
            assert caught_exception is not None
