# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from collections.abc import Callable
from uuid import UUID

import pytest
from more_itertools import one

from tests.conftest import GraphAPIPost


@pytest.fixture
def root_org(graphapi_post: GraphAPIPost) -> UUID:
    mutator = """
    mutation OrganisationCreate {
      org_create(input: {municipality_code: 10}) {
        uuid
      }
    }
    """
    response = graphapi_post(mutator)
    assert response.errors is None
    assert response.data is not None
    return UUID(response.data["org_create"]["uuid"])


@pytest.fixture
def employee_address_type(root_org: UUID, graphapi_post: GraphAPIPost) -> UUID:
    mutator = """
    mutation FacetCreate($input: FacetCreateInput!) {
      facet_create(input: $input) {
        uuid
      }
    }
    """
    response = graphapi_post(
        mutator,
        {
            "input": {
                "user_key": "employee_address_type",
                "validity": {"from": "1970-01-01"},
            }
        },
    )
    assert response.errors is None
    assert response.data is not None
    return UUID(response.data["facet_create"]["uuid"])


@pytest.fixture
def e164_address_class(
    employee_address_type: UUID, graphapi_post: GraphAPIPost
) -> UUID:
    mutator = """
    mutation ClassCreate($input: ClassCreateInput!) {
      class_create(input: $input) {
        uuid
      }
    }
    """
    response = graphapi_post(
        mutator,
        {
            "input": {
                "facet_uuid": str(employee_address_type),
                "name": "E.164",
                "user_key": "E164",
                "scope": "E164",
                "validity": {"from": "1970-01-01"},
            }
        },
    )
    assert response.errors is None
    assert response.data is not None
    return UUID(response.data["class_create"]["uuid"])


@pytest.fixture
def mo_person(root_org: UUID, graphapi_post: GraphAPIPost) -> UUID:
    mutator = """
    mutation PersonCreate {
      employee_create(input: { given_name: "E.164", surname: "Test" }) {
        uuid
      }
    }
    """
    response = graphapi_post(mutator)
    assert response.errors is None
    assert response.data is not None
    return UUID(response.data["employee_create"]["uuid"])


@pytest.mark.integration_test
@pytest.mark.usefixtures("empty_db")
@pytest.mark.parametrize(
    "value,e164,formatted,default_region_code",
    [
        # Danish number
        # E.164 as input
        ("+4588888888", "+4588888888", "+45 88 88 88 88", None),
        # International format as input
        ("+45 88 88 88 88", "+4588888888", "+45 88 88 88 88", None),
        # Non standard 2+3+3 format as input
        ("+45 88 888 888", "+4588888888", "+45 88 88 88 88", None),
        # Local format as input with correct region code
        ("88 88 88 88", "+4588888888", "+45 88 88 88 88", "DK"),
        # Greenlandic number
        # E.164 as input
        ("+299350011", "+299350011", "+299 35 00 11", None),
        # International format as input
        ("+299 35 00 11", "+299350011", "+299 35 00 11", None),
        # Non standard 3+3 format as input
        ("+299 350 011", "+299350011", "+299 35 00 11", None),
        # Local format with correct region code
        ("35 00 11", "+299350011", "+299 35 00 11", "GL"),
        # US number
        # E.164 as input
        ("+16034134124", "+16034134124", "+1 603-413-4124", None),
        # International format as input
        ("+1 603-413-4124", "+16034134124", "+1 603-413-4124", None),
        # Non standard US format as input
        ("+1 (603) 413 4124", "+16034134124", "+1 603-413-4124", None),
        # Local format with correct region code
        ("603 413 4124", "+16034134124", "+1 603-413-4124", "US"),
        # Mixed
        # E.164 as input with correct region code
        ("+4588888888", "+4588888888", "+45 88 88 88 88", "DK"),
        ("+299350011", "+299350011", "+299 35 00 11", "GL"),
        ("+16034134124", "+16034134124", "+1 603-413-4124", "US"),
        # E.164 as input with incorrect region code
        ("+4588888888", "+4588888888", "+45 88 88 88 88", "GB"),
        ("+299350011", "+299350011", "+299 35 00 11", "GB"),
        ("+16034134124", "+16034134124", "+1 603-413-4124", "GB"),
    ],
)
def test_create_e164(
    e164_address_class: UUID,
    mo_person: UUID,
    graphapi_post: GraphAPIPost,
    set_settings: Callable[..., None],
    value: str,
    e164: str,
    formatted: str,
    default_region_code: str | None,
) -> None:
    if default_region_code:
        set_settings(phonenumber_default_region_code=default_region_code)

    mutator = """
    mutation AddressCreate($input: AddressCreateInput!) {
      address_create(input: $input) {
        uuid
      }
    }
    """
    response = graphapi_post(
        mutator,
        {
            "input": {
                "address_type": str(e164_address_class),
                "person": str(mo_person),
                "validity": {"from": "1970-01-01"},
                "value": value,
            }
        },
    )
    assert response.errors is None
    assert response.data is not None
    uuid = UUID(response.data["address_create"]["uuid"])

    query = """
    query ReadAddresses($uuid: UUID!) {
      addresses(filter: { uuids: [$uuid] }) {
        objects {
          current {
            name
            href
            uuid
            value
            value2
            user_key
          }
        }
      }
    }
    """
    response = graphapi_post(query, {"uuid": str(uuid)})
    assert response.errors is None
    assert response.data is not None
    obj = one(response.data["addresses"]["objects"])["current"]
    assert obj["name"] == formatted
    assert obj["value"] == e164
    assert obj["value2"] is None
    assert obj["user_key"] == formatted
    assert obj["href"] == f"tel:{e164}"


@pytest.mark.integration_test
@pytest.mark.usefixtures("empty_db")
@pytest.mark.parametrize(
    "value,error_message,default_region_code",
    [
        # Danish number
        # Missing region code
        (
            "88888888",
            "Unable to parse phone number: (0) Missing or invalid default region.",
            None,
        ),
        # Missing digits
        ("+45 123", "Impossible phonenumber", None),
        ("+45 88 88 88 8", "Impossible phonenumber", None),
        # Invalid number in local format due to default region
        ("88888888", "Impossible phonenumber", "US"),
        ("88888888", "Impossible phonenumber", "GL"),
        # Valid format, but unallocated block
        ("+45 12345678", "Invalid phonenumber", None),
        # Greenlandic number
        # Missing region code
        (
            "35 00 11",
            "Unable to parse phone number: (0) Missing or invalid default region.",
            None,
        ),
        # Missing digits
        ("+299 35 00", "Impossible phonenumber", None),
        ("+299 00 11", "Impossible phonenumber", None),
        # Invalid number in local format due to default region
        ("33 00 11", "Impossible phonenumber", "DK"),
        ("33 00 11", "Impossible phonenumber", "US"),
        # Valid format, but unallocated block
        ("+299 00 11 22", "Invalid phonenumber", None),
        # US number
        # Missing region code
        (
            "6034134124",
            "Unable to parse phone number: (0) Missing or invalid default region.",
            None,
        ),
        # Missing digits
        ("+1 603 413", "Impossible phonenumber", None),
        ("+1 603 413 412", "Impossible phonenumber", None),
        # Invalid number in local format due to default region
        ("603 413 4124", "Impossible phonenumber", "DK"),
        ("603 413 4124", "Impossible phonenumber", "GL"),
        # Valid format, but unallocated block
        ("+1 000 413 4124", "Invalid phonenumber", None),
        ("+1 413 4124", "Invalid phonenumber", None),
    ],
)
def test_create_e164_invalid(
    e164_address_class: UUID,
    mo_person: UUID,
    graphapi_post: GraphAPIPost,
    set_settings: Callable[..., None],
    value: str,
    error_message: str,
    default_region_code: str | None,
) -> None:
    if default_region_code:
        set_settings(phonenumber_default_region_code=default_region_code)

    mutator = """
    mutation AddressCreate($input: AddressCreateInput!) {
      address_create(input: $input) {
        uuid
      }
    }
    """
    response = graphapi_post(
        mutator,
        {
            "input": {
                "address_type": str(e164_address_class),
                "person": str(mo_person),
                "validity": {"from": "1970-01-01"},
                "value": value,
            }
        },
    )
    assert response.data is None
    assert response.errors is not None
    error = one(response.errors)
    assert one(error["path"]) == "address_create"
    assert error["message"] == "ErrorCodes.V_INVALID_ADDRESS_PHONE"

    error_context = error["extensions"]["error_context"]
    assert error_context["description"] == "Invalid phone number"
    assert error_context["error"] is True
    assert error_context["status"] == 400
    assert error_context["value"] == value
    assert error_context["detail"] == error_message
