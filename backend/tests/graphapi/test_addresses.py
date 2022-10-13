# SPDX-FileCopyrightText: 2021- Magenta ApS
# SPDX-License-Identifier: MPL-2.0
import asyncio
import datetime
from unittest.mock import AsyncMock
from unittest.mock import patch
from uuid import UUID
from uuid import uuid4
from zoneinfo import ZoneInfo

import pytest
from fastapi.encoders import jsonable_encoder
from hypothesis import given
from hypothesis import strategies as st
from more_itertools import one
from pytest import MonkeyPatch

from .strategies import graph_data_strat
from .strategies import graph_data_uuids_strat
from mora import lora
from mora import mapping
from mora.graphapi.shim import execute_graphql
from mora.graphapi.shim import flatten_data
from mora.graphapi.versions.latest import dataloaders
from mora.graphapi.versions.latest.address import terminate_addr
from mora.graphapi.versions.latest.models import AddressCreate
from mora.graphapi.versions.latest.models import AddressTerminate
from mora.graphapi.versions.latest.models import AddressUpdate
from mora.graphapi.versions.latest.types import AddressCreateType
from mora.graphapi.versions.latest.types import AddressType
from ramodels.mo.details import AddressRead
from tests import util
from tests.conftest import GQLResponse
from tests.graphapi.utils import fetch_employee_validity
from tests.graphapi.utils import fetch_org_unit_validity
from tests.util import dar_loader


# HELPERS

# Address UUID: Nordre Ringgade 1, 8000 Aarhus C
# addr_uuid_nordre_ring = "b1f1817d-5f02-4331-b8b3-97330a5d3197"

addr_type_user_address = UUID("4e337d8e-1fd2-4449-8110-e0c8a22958ed")
addr_type_user_email = UUID("c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0")
# addr_type_user_phone = UUID("cbadfa0f-ce4f-40b9-86a0-2e85d8961f5d")

addr_type_orgunit_address = UUID("28d71012-2919-4b67-a2f0-7b59ed52561e")
addr_type_orgunit_email = UUID("73360db1-bad3-4167-ac73-8d827c0c8751")
# addr_type_orgunit_ean = UUID("e34d4426-9845-4c72-b31e-709be85d6fa2") # FYI: regex: ^\d{13}$
# addr_type_orgunit_phone = UUID("1d1d3711-5af4-4084-99b3-df2b8752fdec")
# addr_type_orgunit_openhours = UUID("e8ea1a09-d3d4-4203-bfe9-d9a2da100f3b")

# engagement_type_employee = UUID("06f95678-166a-455a-a2ab-121a8d92ea23")

visibility_uuid_public = UUID("f63ad763-0e53-4972-a6a9-63b42a0f8cb7")

tz_cph = ZoneInfo("Europe/Copenhagen")
now_min_cph = datetime.datetime.combine(
    datetime.datetime.now().date(), datetime.datetime.min.time()
).replace(tzinfo=tz_cph)


def async_lora_return(*args):
    """Returns last positional argument using asyncio.Future.

    This is used to mock lora.Scope methods like 'get' and 'update'."""

    f = asyncio.Future()
    f.set_result(args[-1])
    return f


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


def _get_orgunit_addr_type(value_type):
    if value_type == "email":
        return addr_type_orgunit_email

    return None


def _get_person_addr_type(value_type):
    if value_type == "email":
        return addr_type_user_email

    return None


def _get_engagement_addr_type(value_type):
    if value_type == "email":
        # TODO: Figure out a proper UUID here - I currently cant find
        # an engagement_addr_type in the sample_structure.
        return addr_type_user_email

    return None


def _get_create_addresss_addr_type(
    create_address_value_type,
    test_data_org_unit_uuid,
    test_data_person_uuid,
    test_data_engagement_uuid,
):
    if test_data_org_unit_uuid:
        # return addr_type_orgunit_email
        return _get_orgunit_addr_type(create_address_value_type)
    elif test_data_person_uuid:
        # return addr_type_user_email
        return _get_person_addr_type(create_address_value_type)
    elif test_data_engagement_uuid:
        return _get_engagement_addr_type(create_address_value_type)

    return None


def _create_address_create_hypothesis_test_data(data, graphapi_post):
    (
        test_data_org_unit_uuid,
        test_data_person_uuid,
        test_data_engagement_uuid,
    ) = data.draw(
        st.tuples(
            st.sampled_from(
                [
                    UUID("2874e1dc-85e6-4269-823a-e1125484dfd3"),  # L1
                ]
            )
            | st.none(),
            st.sampled_from(
                [
                    UUID("53181ed2-f1de-4c4a-a8fd-ab358c2c454a"),  # andersand
                    UUID("6ee24785-ee9a-4502-81c2-7697009c9053"),  # fedtmule
                    UUID("236e0a78-11a0-4ed9-8545-6286bb8611c7"),  # erik_smidt_hansen
                    # Doing stuff with this test user makes the addresses-query fail on the new UUID.
                    # OBS: I have expericed similar issues with employee-update
                    # UUID("7626ad64-327d-481f-8b32-36c78eb12f8c"),  # lis_jensen
                ]
            )
            | st.none(),
            st.sampled_from(
                [
                    UUID(
                        "d000591f-8705-4324-897a-075e3623f37b"
                    ),  # engagement_andersand
                    UUID(
                        "d3028e2e-1d7a-48c1-ae01-d4c64e64bbab"
                    ),  # engagement_eriksmidthansen
                    UUID(
                        "301a906b-ef51-4d5c-9c77-386fb8410459"
                    ),  # engagement_eriksmidthansen_sekundaer
                ]
            )
            | st.none(),
        )
        .filter(
            lambda rels: False if not rels[0] and not rels[1] and not rels[2] else True
        )
        .filter(lambda rels: False if rels[0] and (rels[1] or rels[2]) else True)
        .filter(lambda rels: False if rels[1] and (rels[0] or rels[2]) else True)
        .filter(lambda rels: False if rels[2] and (rels[0] or rels[1]) else True)
    )

    address_type = None
    dt_options_min_from = datetime.datetime(1930, 1, 1, 1)
    if test_data_org_unit_uuid:
        address_type = addr_type_orgunit_email

        if graphapi_post:
            org_unit_validity_from, _ = fetch_org_unit_validity(
                graphapi_post, test_data_org_unit_uuid
            )
            dt_options_min_from = org_unit_validity_from
    elif test_data_person_uuid:
        address_type = addr_type_user_email

        if graphapi_post:
            person_validity_from, _ = fetch_employee_validity(
                graphapi_post, test_data_person_uuid
            )
            dt_options_min_from = person_validity_from
    elif test_data_engagement_uuid:
        # TODO: Figure out a proper UUID here - I currently cant find
        # an engagement_addr_type in the sample_structure.
        address_type = addr_type_user_email

    dt_options = {
        "min_value": dt_options_min_from,
        "timezones": st.just(ZoneInfo("Europe/Copenhagen")),
    }
    test_datavalidity_tuple = data.draw(
        st.tuples(
            st.datetimes(**dt_options),
            st.datetimes(**dt_options) | st.none(),
        ).filter(lambda dts: dts[0] <= dts[1] if dts[0] and dts[1] else True)
    )
    test_data_from, test_data_to = test_datavalidity_tuple

    return data.draw(
        st.builds(
            AddressCreate,
            value=st.emails(),
            from_date=st.just(test_data_from),
            to_date=st.just(test_data_to),
            address_type=st.just(address_type),
            visibility=st.just(visibility_uuid_public),
            org_unit=st.just(test_data_org_unit_uuid),
            person=st.just(test_data_person_uuid),
            engagement=st.just(test_data_engagement_uuid),
        )
    )


def _create_address_create_hypothesis_test_data_new(
    data, graphapi_post, test_data_samples
):
    (
        test_data_org_unit_uuid,
        test_data_person_uuid,
        test_data_engagement_uuid,
        address_type,
    ) = data.draw(st.sampled_from(test_data_samples))

    dt_options_min_from = datetime.datetime(1930, 1, 1, 1)
    if test_data_org_unit_uuid and graphapi_post:
        org_unit_validity_from, _ = fetch_org_unit_validity(
            graphapi_post, test_data_org_unit_uuid
        )
        dt_options_min_from = org_unit_validity_from
    elif test_data_person_uuid and graphapi_post:
        person_validity_from, _ = fetch_employee_validity(
            graphapi_post, test_data_person_uuid
        )
        dt_options_min_from = person_validity_from

    dt_options = {
        "min_value": dt_options_min_from,
        "timezones": st.just(ZoneInfo("Europe/Copenhagen")),
    }
    test_datavalidity_tuple = data.draw(
        st.tuples(
            st.datetimes(**dt_options),
            st.datetimes(**dt_options) | st.none(),
        ).filter(lambda dts: dts[0] <= dts[1] if dts[0] and dts[1] else True)
    )
    test_data_from, test_data_to = test_datavalidity_tuple

    if address_type in (addr_type_orgunit_address, addr_type_user_address):
        # FYI: The UUIDs we sample from, are the ones found
        # in: backend\tests\mocking\dawa-addresses.json
        test_data_value = data.draw(
            st.sampled_from(
                [
                    "0a3f50a0-23c9-32b8-e044-0003ba298018",
                    "44c532e1-f617-4174-b144-d37ce9fda2bd",
                    "606cf42e-9dc2-4477-bf70-594830fcbdec",
                    "ae95777c-7ec1-4039-8025-e2ecce5099fb",
                    "b1f1817d-5f02-4331-b8b3-97330a5d3197",
                    "bae093df-3b06-4f23-90a8-92eabedb3622",
                    "d901ff7e-8ad9-4581-84c7-5759aaa82f7b",
                ]
            )
        )
    elif address_type in (addr_type_user_email, addr_type_orgunit_email):
        test_data_value = data.draw(st.emails())
    else:
        test_data_value = data.draw(st.text())

    return data.draw(
        st.builds(
            AddressCreate,
            value=st.just(test_data_value),
            from_date=st.just(test_data_from),
            to_date=st.just(test_data_to),
            address_type=st.just(address_type),
            visibility=st.just(visibility_uuid_public),
            org_unit=st.just(test_data_org_unit_uuid),
            person=st.just(test_data_person_uuid),
            engagement=st.just(test_data_engagement_uuid),
        )
    )


# TESTS


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


@given(data=st.data())
@patch("mora.graphapi.versions.latest.mutators.address_create", new_callable=AsyncMock)
async def test_create_mutator(address_create: AsyncMock, data):
    # Mocking
    address_create.return_value = AddressCreateType(uuid=uuid4())

    # Prepare test_data
    test_data = _create_address_create_hypothesis_test_data(data, graphapi_post=None)
    payload = jsonable_encoder(test_data)

    # Invoke the mutator
    mutate_query = """
        mutation($input: AddressCreateInput!) {
            address_create(input: $input) {
                uuid
            }
        }
    """
    response = await execute_graphql(
        query=mutate_query, variable_values={"input": payload}
    )
    assert response.errors is None
    assert response.data == {
        "address_create": {"uuid": str(address_create.return_value.uuid)}
    }

    address_create.assert_called_with(test_data)


@pytest.mark.parametrize(
    "given_mutator_args",
    [
        {  # Desc: verify fails, when dates are invalid.
            "from_date": now_min_cph,
            "to_date": now_min_cph - datetime.timedelta(days=1),
            "value": "YeeHaaamagenta.dk",
            "address_type": addr_type_user_email,
            "visibility": visibility_uuid_public,
            "person": UUID("53181ed2-f1de-4c4a-a8fd-ab358c2c454a"),
        },
        {  # Desc: verify fails when No relation was supplied
            "from_date": now_min_cph,
            "to_date": None,
            "value": "YeeHaaa@magenta.dk",
            "address_type": addr_type_user_email,
            "visibility": visibility_uuid_public,
        },
    ],
)
@patch("mora.graphapi.versions.latest.mutators.address_create", new_callable=AsyncMock)
async def test_create_mutator_fails(address_create: AsyncMock, given_mutator_args):
    payload = {
        "from": given_mutator_args["from_date"].isoformat(),
        "to": given_mutator_args["to_date"].isoformat()
        if given_mutator_args.get("to_date", None)
        else None,
        "value": given_mutator_args["value"],
        "address_type": str(given_mutator_args["address_type"]),
        "visibility": str(given_mutator_args["visibility"]),
    }

    mutate_query = """
        mutation($input: AddressCreateInput!) {
            address_create(input: $input) {
                uuid
            }
        }
    """
    _ = await execute_graphql(query=mutate_query, variable_values={"input": payload})

    address_create.assert_not_called()


@given(data=st.data())
@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
async def test_create_integration_emails(data, graphapi_post):
    # Test data
    test_data = _create_address_create_hypothesis_test_data(
        data, graphapi_post=graphapi_post
    )
    payload = jsonable_encoder(test_data)

    # mutation invoke
    mutate_query = """
        mutation($input: AddressCreateInput!) {
            address_create(input: $input) {
                uuid
            }
        }
    """
    response = await execute_graphql(
        query=mutate_query, variable_values={"input": payload}
    )
    assert response.errors is None

    test_data_uuid_new = UUID(response.data["address_create"]["uuid"])

    # query invoke after mutation
    verify_query = _get_address_query()
    verify_response: GQLResponse = graphapi_post(
        verify_query,
        {mapping.UUID: str(test_data_uuid_new)},
    )

    assert verify_response.errors is None

    # Asserts
    new_addr = one(one(verify_response.data["addresses"])["objects"])
    assert new_addr[mapping.UUID] is not None

    assert (
        new_addr[mapping.VALIDITY][mapping.FROM]
        == datetime.datetime.combine(
            test_data.from_date.date(), datetime.datetime.min.time()
        )
        .replace(tzinfo=tz_cph)
        .isoformat()
    )

    assert new_addr[mapping.VALIDITY][mapping.TO] == (
        datetime.datetime.combine(
            test_data.to_date.date(), datetime.datetime.min.time()
        )
        .replace(tzinfo=tz_cph)
        .isoformat()
        if test_data.to_date
        else None
    )

    assert new_addr[mapping.VALUE] == test_data.value
    assert new_addr[mapping.ADDRESS_TYPE][mapping.UUID] == str(test_data.address_type)
    assert new_addr[mapping.VISIBILITY][mapping.UUID] == str(test_data.visibility)

    if test_data.org_unit:
        assert one(new_addr[mapping.ORG_UNIT])[mapping.UUID] == str(test_data.org_unit)
    elif test_data.person:
        # INFO: here is a confusing part where we create using PERSON, but fetch using EMPLOYEE:
        assert one(new_addr[mapping.EMPLOYEE])[mapping.UUID] == str(test_data.person)
    elif test_data.engagement:
        assert new_addr["engagement_uuid"] == str(test_data.engagement)


@given(data=st.data())
@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
async def test_create_integration_address(data, graphapi_post):
    # Configre test data samples
    addr_tests_data = [
        # Org units
        (
            UUID("2874e1dc-85e6-4269-823a-e1125484dfd3"),
            None,
            None,
            addr_type_orgunit_address,
        ),
        # Users
        (
            None,
            UUID("53181ed2-f1de-4c4a-a8fd-ab358c2c454a"),
            None,
            addr_type_user_address,
        ),
        (
            None,
            UUID("6ee24785-ee9a-4502-81c2-7697009c9053"),
            None,
            addr_type_user_address,
        ),
        (
            None,
            UUID("236e0a78-11a0-4ed9-8545-6286bb8611c7"),
            None,
            addr_type_user_address,
        ),
    ]

    test_data = _create_address_create_hypothesis_test_data_new(
        data, graphapi_post, addr_tests_data
    )

    payload = jsonable_encoder(test_data)

    # mutation invoke
    mutate_query = """
        mutation($input: AddressCreateInput!) {
            address_create(input: $input) {
                uuid
            }
        }
    """

    with util.darmock("dawa-addresses.json", real_http=True), dar_loader():
        response = await execute_graphql(
            query=mutate_query, variable_values={"input": payload}
        )

    assert response.errors is None
    test_data_uuid_new = UUID(response.data["address_create"]["uuid"])

    # query invoke after mutation
    verify_query = _get_address_query()
    verify_response: GQLResponse = graphapi_post(
        verify_query,
        {mapping.UUID: str(test_data_uuid_new)},
    )

    assert verify_response.errors is None
    new_addr = one(one(verify_response.data["addresses"])["objects"])

    # Asserts
    assert new_addr[mapping.UUID] is not None
    assert (
        new_addr[mapping.VALIDITY][mapping.FROM]
        == datetime.datetime.combine(
            test_data.from_date.date(), datetime.datetime.min.time()
        )
        .replace(tzinfo=tz_cph)
        .isoformat()
    )
    assert new_addr[mapping.VALIDITY][mapping.TO] == (
        datetime.datetime.combine(
            test_data.to_date.date(), datetime.datetime.min.time()
        )
        .replace(tzinfo=tz_cph)
        .isoformat()
        if test_data.to_date
        else None
    )

    assert new_addr[mapping.VALUE] == test_data.value
    assert new_addr[mapping.ADDRESS_TYPE][mapping.UUID] == str(test_data.address_type)
    assert new_addr[mapping.VISIBILITY][mapping.UUID] == str(test_data.visibility)

    if test_data.org_unit:
        assert one(new_addr[mapping.ORG_UNIT])[mapping.UUID] == str(test_data.org_unit)
    elif test_data.person:
        # INFO: here is a confusing part where we create using PERSON, but fetch using EMPLOYEE:
        assert one(new_addr[mapping.EMPLOYEE])[mapping.UUID] == str(test_data.person)
    elif test_data.engagement:
        assert new_addr["engagement_uuid"] == str(test_data.engagement)


# address
# email
# ean
# phone
# openhours


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


@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
@pytest.mark.parametrize(
    "test_data",
    [
        {
            "uuid": "fba61e38-b553-47cc-94bf-8c7c3c2a6887",
            "user_key": "bruger@example.comw",
            "org_unit": None,
            "employee": None,
            "address_type": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
            "engagement": "d3028e2e-1d7a-48c1-ae01-d4c64e64bbab",
            "value": "Giraf@elefant.nu",
            "visibility": None,
            "validity": {"to": None, "from": "1934-06-09T00:00:00+01:00"},
        },
        {
            "uuid": "cd6008bc-1ad2-4272-bc1c-d349ef733f52",
            "user_key": "Christiansborg Slotsplads 1, 1218 København K",
            "org_unit": None,
            "employee": "6ee24785-ee9a-4502-81c2-7697009c9053",
            "address_type": "4e337d8e-1fd2-4449-8110-e0c8a22958ed",
            "engagement": None,
            "value": "b1f1817d-5f02-4331-b8b3-97330a5d3197",
            "visibility": None,
            "validity": {"to": None, "from": "1932-05-12T00:00:00+01:00"},
        },
        {
            "uuid": "55848eca-4e9e-4f30-954b-78d55eec0473",
            "user_key": "8715 0222",
            "org_unit": "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e",
            "employee": None,
            "address_type": "1d1d3711-5af4-4084-99b3-df2b8752fdec",
            "engagement": None,
            "value": "+4587150222",
            "visibility": "1d1d3711-5af4-4084-99b3-df2b8752fdec",
            "validity": {"to": None, "from": "2016-01-01T00:00:00+01:00"},
        },
        {
            "uuid": "a0fe7d43-1e0d-4232-a220-87098024b34d",
            "user_key": "5798000420526",
            "org_unit": "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e",
            "employee": None,
            "address_type": "e34d4426-9845-4c72-b31e-709be85d6fa2",
            "engagement": None,
            "value": "5798000420526",
            "visibility": None,
            "validity": {"to": None, "from": "2016-01-01T00:00:00+01:00"},
        },
    ],
)
async def test_update_address_integration_test(test_data, graphapi_post) -> None:
    async def query_data(uuid: str) -> GQLResponse:

        query = """
            query ($uuid: [UUID!]!){
                __typename
                addresses(uuids: $uuid){
                    objects {
                        uuid
                        user_key
                        org_unit: org_unit_uuid
                        employee: employee_uuid
                        address_type: address_type_uuid
                        engagement: engagement_uuid
                        value
                        visibility: visibility_uuid
                        validity {
                            to
                            from
                        }
                    }
                }
            }

        """
        response: GQLResponse = graphapi_post(query=query, variables={"uuid": uuid})

        return response

    prior_data = await query_data(test_data["uuid"])
    prior_data = one(one(prior_data.data.get("addresses", {})).get("objects"))

    mutate_query = """
        mutation UpdateAddress($input: AddressUpdateInput!) {
            address_update(input: $input) {
                uuid
            }
        }
    """
    response: GQLResponse = graphapi_post(
        mutate_query, {"input": jsonable_encoder(test_data)}
    )

    posterior_data = await query_data(test_data["uuid"])

    response_data = one(one(posterior_data.data.get("addresses", {})).get("objects"))

    """Assert returned UUID from mutator is correct"""
    assert response.errors is None
    assert response.data.get("address_update", {}).get("uuid", {}) == test_data["uuid"]

    updated_test_data = {k: v or prior_data[k] for k, v in test_data.items()}

    """Asssert data written to db is correct when queried"""
    assert posterior_data.errors is None
    assert updated_test_data == response_data


@given(test_data=...)
@patch("mora.graphapi.versions.latest.mutators.update_address", new_callable=AsyncMock)
async def test_update_address_unit_test(
    update_address: AsyncMock, test_data: AddressUpdate
) -> None:
    """Test that pydantic jsons are passed through to address_update."""

    mutate_query = """
        mutation UpdateAddress($input: AddressUpdateInput!) {
            address_update(input: $input) {
                uuid
            }
        }
    """

    address_uuid_to_update = uuid4()
    update_address.return_value = AddressType(uuid=address_uuid_to_update)

    payload = jsonable_encoder(test_data)

    response = await execute_graphql(
        query=mutate_query, variable_values={"input": payload}
    )
    assert response.errors is None
    assert response.data == {"address_update": {"uuid": str(address_uuid_to_update)}}

    update_address.assert_called_with(test_data)
