# SPDX-FileCopyrightText: 2021- Magenta ApS
# SPDX-License-Identifier: MPL-2.0
import asyncio
import datetime
from unittest.mock import patch
from uuid import UUID
from uuid import uuid4
from zoneinfo import ZoneInfo

import pytest
from fastapi.encoders import jsonable_encoder
from hypothesis import given
from hypothesis import infer
from hypothesis import strategies as st
from pytest import MonkeyPatch

from .strategies import graph_data_strat
from .strategies import graph_data_uuids_strat
from mora import lora
from mora import mapping
from mora.graphapi.shim import execute_graphql
from mora.graphapi.shim import flatten_data
from mora.graphapi.versions.latest import dataloaders
from mora.graphapi.versions.latest.address import terminate as terminate_addr
from mora.graphapi.versions.latest.models import AddressCreate
from mora.graphapi.versions.latest.models import AddressRelation
from mora.graphapi.versions.latest.models import AddressTerminate
from ramodels.mo.details import AddressRead
from tests.conftest import GQLResponse


def async_lora_return(*args):
    """Returns last positional argument using asyncio.Future.

    This is used to mock lora.Scope methods like 'get' and 'update'."""

    f = asyncio.Future()
    f.set_result(args[-1])
    return f


@given(test_data=graph_data_strat(AddressRead))
def test_query_all(test_data, graphapi_post, patch_loader):
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
def test_query_by_uuid(test_input, graphapi_post, patch_loader):
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


@given(
    given_uuid=st.uuids(),
    triggerless=st.booleans(),
    given_validity_dts=st.tuples(st.datetimes() | st.none(), st.datetimes()).filter(
        lambda dts: dts[0] <= dts[1] if dts[0] and dts[1] else True
    ),
)
@patch.object(lora.Scope, "update", async_lora_return)
@patch.object(lora.Scope, "get", async_lora_return)
async def test_terminate(given_uuid, triggerless, given_validity_dts):
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
        tr = await terminate_addr(address_terminate=at)
        terminate_result_uuid = tr.uuid if tr else terminate_result_uuid
    except Exception as e:
        caught_exception = e

    # Assert
    if not expect_exception:
        assert terminate_result_uuid == at.uuid
    else:
        assert caught_exception is not None


visibility_uuid_public = UUID("f63ad763-0e53-4972-a6a9-63b42a0f8cb7")


@given(data=st.data())
async def test_create_mutator(data):
    # Create test data
    tz: ZoneInfo = data.draw(st.sampled_from([ZoneInfo("Europe/Copenhagen")]))

    dt_options = {
        "min_value": datetime.datetime(1930, 1, 1, 1),
        "timezones": st.just(tz),
    }
    validity_tuple = data.draw(
        st.tuples(
            st.datetimes(**dt_options),
            st.datetimes(**dt_options) | st.none(),
        ).filter(lambda dts: dts[0] <= dts[1] if dts[0] and dts[1] else True)
    )
    test_data_from, test_data_to = validity_tuple

    test_data_relation = data.draw(
        st.builds(
            AddressRelation,
            type=st.sampled_from(
                [mapping.ORG_UNIT, mapping.PERSON, mapping.ENGAGEMENT]
            ),
        )
    )

    test_data = data.draw(
        st.builds(
            AddressCreate,
            from_date=st.just(test_data_from),
            to_date=st.just(test_data_to),
            relation=st.just(test_data_relation),
            org=infer,
        )
    )
    payload = jsonable_encoder(test_data.dict(by_alias=True))

    # Execute the mutation query
    with patch(
        "mora.graphapi.versions.latest.address.handlers.generate_requests"
    ), patch(
        "mora.graphapi.versions.latest.address.handlers.submit_requests"
    ) as mock_submit_requests:
        mock_submit_requests.return_value = [uuid4()]

        mutate_query = """
            mutation($input: AddressCreateInput!) {
                address_create(input: $input) {
                    uuid
                }
            }
        """
        mutation_response = await execute_graphql(
            query=mutate_query, variable_values={"input": payload}
        )
        assert mutation_response.errors is None

        mutation_response_uuid = mutation_response.data.get("address_create", {}).get(
            "uuid", None
        )
        assert str(mock_submit_requests.return_value[0]) == mutation_response_uuid


@pytest.mark.parametrize(
    "given_mutator_args",
    [
        {
            # address_type="bruger_email"
            "value": "YeeHaaa@magenta.dk",
            "address_type": UUID("c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0"),
            "visibility": visibility_uuid_public,
            "relation": {
                "type": mapping.PERSON,
                "uuid": UUID("53181ed2-f1de-4c4a-a8fd-ab358c2c454a"),
            },
            "org": UUID("456362c4-0ee4-4e5e-a72c-751239745e62"),
        },
        {
            # Addr: Nordre Ringgade 1, 8000 Aarhus C
            "value": "b1f1817d-5f02-4331-b8b3-97330a5d3197",
            "address_type": UUID("4e337d8e-1fd2-4449-8110-e0c8a22958ed"),
            "visibility": visibility_uuid_public,
            "relation": {
                "type": mapping.PERSON,
                "uuid": UUID("53181ed2-f1de-4c4a-a8fd-ab358c2c454a"),
            },
            "org": UUID("456362c4-0ee4-4e5e-a72c-751239745e62"),
        },
        {
            "value": "11223344",
            "address_type": UUID("cbadfa0f-ce4f-40b9-86a0-2e85d8961f5d"),
            "visibility": visibility_uuid_public,
            "relation": {
                "type": mapping.PERSON,
                "uuid": UUID("53181ed2-f1de-4c4a-a8fd-ab358c2c454a"),
            },
            "org": UUID("456362c4-0ee4-4e5e-a72c-751239745e62"),
        },
        {
            "value": "YeeHaaa@magenta.dk",
            "address_type": UUID("c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0"),
            "visibility": visibility_uuid_public,
            "relation": {
                # engagement_type="ansat"
                # which is why above addr type is a "bruger_email"
                "type": mapping.ENGAGEMENT,
                "uuid": UUID("06f95678-166a-455a-a2ab-121a8d92ea23"),
            },
            "org": UUID("456362c4-0ee4-4e5e-a72c-751239745e62"),
        },
        {
            # Addr: Nordre Ringgade 1, 8000 Aarhus C
            "value": "b1f1817d-5f02-4331-b8b3-97330a5d3197",
            "address_type": UUID("28d71012-2919-4b67-a2f0-7b59ed52561e"),
            "visibility": visibility_uuid_public,
            "relation": {
                "type": mapping.ORG_UNIT,
                "uuid": UUID("2874e1dc-85e6-4269-823a-e1125484dfd3"),
            },
            "org": UUID("456362c4-0ee4-4e5e-a72c-751239745e62"),
        },
        {
            "value": "YeeHaaa@magenta.dk",
            "address_type": UUID("73360db1-bad3-4167-ac73-8d827c0c8751"),
            "visibility": visibility_uuid_public,
            "relation": {
                "type": mapping.ORG_UNIT,
                "uuid": UUID("2874e1dc-85e6-4269-823a-e1125484dfd3"),
            },
            "org": UUID("456362c4-0ee4-4e5e-a72c-751239745e62"),
        },
        {
            # address_type = EAN (validator-regex: ^\d{13}$)
            "value": "8008580085000",
            "address_type": UUID("e34d4426-9845-4c72-b31e-709be85d6fa2"),
            "visibility": visibility_uuid_public,
            "relation": {
                "type": mapping.ORG_UNIT,
                "uuid": UUID("2874e1dc-85e6-4269-823a-e1125484dfd3"),
            },
            "org": UUID("456362c4-0ee4-4e5e-a72c-751239745e62"),
        },
        {
            "value": "55667788",
            "address_type": UUID("1d1d3711-5af4-4084-99b3-df2b8752fdec"),
            "visibility": visibility_uuid_public,
            "relation": {
                "type": mapping.ORG_UNIT,
                "uuid": UUID("2874e1dc-85e6-4269-823a-e1125484dfd3"),
            },
            "org": UUID("456362c4-0ee4-4e5e-a72c-751239745e62"),
        },
        {
            # address_type = contact-open-hours
            "value": "8-17",
            "address_type": UUID("e8ea1a09-d3d4-4203-bfe9-d9a2da100f3b"),
            "visibility": visibility_uuid_public,
            "relation": {
                "type": mapping.ORG_UNIT,
                "uuid": UUID("2874e1dc-85e6-4269-823a-e1125484dfd3"),
            },
            "org": UUID("456362c4-0ee4-4e5e-a72c-751239745e62"),
        },
    ],
)
@pytest.mark.integration_test
@pytest.mark.usefixtures("sample_structures")
async def test_create_integration(graphapi_post, given_mutator_args):
    validity_from = datetime.datetime.combine(
        datetime.datetime.now().date(), datetime.datetime.min.time()
    ).replace(tzinfo=ZoneInfo("Europe/Copenhagen"))

    test_data = AddressCreate(
        from_date=validity_from,
        value=given_mutator_args.get("value"),
        address_type=given_mutator_args.get("address_type"),
        visibility=given_mutator_args.get("visibility"),
        relation=AddressRelation(
            uuid=given_mutator_args.get("relation").get("uuid"),
            type=given_mutator_args.get("relation").get("type"),
        ),
        org=given_mutator_args.get("org", None),
    )
    payload = jsonable_encoder(test_data.dict(by_alias=True))

    # Execute the mutation query
    mutation_query = """
        mutation($input: AddressCreateInput!) {
            address_create(input: $input) {
                uuid
            }
        }
    """
    mutation_response: GQLResponse = graphapi_post(mutation_query, {"input": payload})
    assert mutation_response.errors is None

    # Verify/assert the new address was created
    verify_query = _get_address_query()
    verify_response: GQLResponse = graphapi_post(
        verify_query,
        {"uuid": mutation_response.data.get("address_create", {}).get("uuid", None)},
    )
    assert verify_response.errors is None

    try:
        new_addr = verify_response.data.get("addresses", [])[0].get("objects", [])[0]
    except Exception:
        new_addr = None

    assert new_addr is not None
    assert new_addr[mapping.UUID] is not None
    assert new_addr[mapping.VALUE] == test_data.value
    assert new_addr[mapping.ADDRESS_TYPE][mapping.UUID] == str(test_data.address_type)
    assert new_addr[mapping.VISIBILITY][mapping.UUID] == str(test_data.visibility)
    assert new_addr[mapping.VISIBILITY][mapping.UUID] == str(test_data.visibility)

    rel_uuid_str = str(test_data.relation.uuid)
    if test_data.relation.type == mapping.PERSON:
        assert new_addr[mapping.EMPLOYEE][0][mapping.UUID] == rel_uuid_str
    elif test_data.relation.type == mapping.ORG_UNIT:
        assert new_addr[mapping.ORG_UNIT][0][mapping.UUID] == rel_uuid_str
    elif test_data.relation.type == mapping.ENGAGEMENT:
        assert new_addr["engagement_uuid"] == rel_uuid_str


@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_class_reset")
@pytest.mark.parametrize(
    "filter_snippet,expected",
    [
        ("", 7),
        # Address Type filters
        ('(address_type_user_keys: "BrugerPostadresse")', 1),
        ('(address_types: "4e337d8e-1fd2-4449-8110-e0c8a22958ed")', 1),
        ('(address_type_user_keys: "BrugerEmail")', 2),
        ('(address_types: "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0")', 2),
        ('(address_type_user_keys: ["BrugerPostadresse", "BrugerEmail"])', 3),
        (
            """
            (address_types: [
                "4e337d8e-1fd2-4449-8110-e0c8a22958ed",
                "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0"
            ])
        """,
            3,
        ),
        (
            """
            (
                address_type_user_keys: "BrugerPostadresse"
                address_types: "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0"
            )
        """,
            3,
        ),
        # Employee filters
        ('(employees: "53181ed2-f1de-4c4a-a8fd-ab358c2c454a")', 1),
        ('(employees: "6ee24785-ee9a-4502-81c2-7697009c9053")', 2),
        (
            """
            (employees: [
                "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
                "6ee24785-ee9a-4502-81c2-7697009c9053"
            ])
        """,
            3,
        ),
        # Mixed filters
        (
            """
            (
                employees: "6ee24785-ee9a-4502-81c2-7697009c9053",
                address_types: "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0"
            )
        """,
            1,
        ),
        (
            """
            (
                employees: "6ee24785-ee9a-4502-81c2-7697009c9053",
                address_type_user_keys: "BrugerEmail"
            )
        """,
            1,
        ),
    ],
)
async def test_address_filters(graphapi_post, filter_snippet, expected) -> None:
    """Test filters on addresses."""
    address_query = f"""
        query Addresses {{
            addresses{filter_snippet} {{
                uuid
            }}
        }}
    """
    response: GQLResponse = graphapi_post(address_query)
    assert response.errors is None
    assert len(response.data["addresses"]) == expected


def _get_address_query():
    return """
        query VerifyQuery($uuid: UUID!) {
          addresses(uuids: [$uuid], from_date: null, to_date: null) {
            uuid
            objects {
              uuid

              validity {
                from
                to
              }

              type
              value
              address_type {
                uuid
              }

              visibility {
                uuid
              }

              employee {
                uuid
              }

              org_unit {
                uuid
              }

              engagement_uuid
            }
          }
        }
    """
