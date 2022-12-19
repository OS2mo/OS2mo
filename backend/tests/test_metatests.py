# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from uuid import UUID

import freezegun
import pytest
from fastapi.testclient import TestClient

from mora import lora
from mora.db import get_database_connection
from tests.cases import assert_registrations_equal


@pytest.fixture
async def test_db_resets_rollbacks(load_fixture: None) -> None:
    """Used for testing that db actually resets after running tests
    Should be used before a db-reseting method.
    """
    query_last_commit = "select count(*) as count from bruger;"
    user_count_intitial = "initial_commits"
    user_count_after = "user_count_after"

    conn = get_database_connection()
    with conn.cursor() as cursor:
        cursor.execute(query_last_commit)
        user_count_intitial = cursor.fetchone()[0]

    yield

    conn = get_database_connection()
    with conn.cursor() as cursor:
        cursor.execute(query_last_commit)
        user_count_after = cursor.fetchone()[0]

    # assert that all changes are actually rollbacked
    assert user_count_intitial == user_count_after


@pytest.mark.integration_test
@pytest.mark.usefixtures("test_db_resets_rollbacks", "load_fixture_data_with_reset")
@pytest.mark.parametrize(
    "cpr",
    [
        ("0101501234"),
        ("0101501234"),
    ],
)
@freezegun.freeze_time("2017-01-01", tz_offset=1)
async def test_no_changes_persisted(service_client: TestClient, cpr: str) -> None:
    """This test ensures that the db is written to twice, across two test.
    Which will make the test_fixture fail the test if the changes are not rolled back.
    """

    c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")

    first_name = "Torkild"
    last_name = "von Testperson"

    payload = {
        "givenname": first_name,
        "surname": last_name,
        "nickname_givenname": "Torkild",
        "nickname_surname": "Sejfyr",
        "seniority": "2017-01-01",
        "cpr_no": cpr,
        "org": {"uuid": "456362c4-0ee4-4e5e-a72c-751239745e62"},
    }
    response = service_client.post("/service/e/create", json=payload)
    assert response.status_code == 201
    userid = response.json()

    expected = _get_expected_response(
        first_name, last_name, cpr, "1950-01-01 00:00:00+01"
    )
    actual = await c.bruger.get(userid)
    assert actual is not None

    # Make sure the bvn is a valid UUID
    bvn = actual["attributter"]["brugeregenskaber"][0].pop("brugervendtnoegle")
    assert UUID(bvn)

    assert_registrations_equal(actual, expected)

    expected_employee = {
        "givenname": first_name,
        "surname": last_name,
        "name": f"{first_name} {last_name}",
        "nickname_givenname": "Torkild",
        "nickname_surname": "Sejfyr",
        "nickname": "Torkild Sejfyr",
        "seniority": "2017-01-01",
        "org": {
            "name": "Aarhus Universitet",
            "user_key": "AU",
            "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
        },
        "user_key": bvn,
        "uuid": userid,
        "cpr_no": cpr,
    }

    response = service_client.get(f"/service/e/{userid}/")
    assert response.status_code == 200
    assert response.json() == expected_employee


def _get_expected_response(first_name, last_name, cpr, valid_from):
    expected = {
        "livscykluskode": "Importeret",
        "note": "Oprettet i MO",
        "attributter": {
            "brugeregenskaber": [
                {
                    "virkning": {
                        "to_included": False,
                        "to": "infinity",
                        "from_included": True,
                        "from": valid_from,
                    },
                }
            ],
            "brugerudvidelser": [
                {
                    "fornavn": first_name,
                    "efternavn": last_name,
                    "kaldenavn_fornavn": "Torkild",
                    "kaldenavn_efternavn": "Sejfyr",
                    "seniority": "2017-01-01",
                    "virkning": {
                        "from": valid_from,
                        "from_included": True,
                        "to": "infinity",
                        "to_included": False,
                    },
                }
            ],
        },
        "relationer": {
            "tilhoerer": [
                {
                    "virkning": {
                        "to_included": False,
                        "to": "infinity",
                        "from_included": True,
                        "from": valid_from,
                    },
                    "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
                }
            ],
        },
        "tilstande": {
            "brugergyldighed": [
                {
                    "virkning": {
                        "to_included": False,
                        "to": "infinity",
                        "from_included": True,
                        "from": valid_from,
                    },
                    "gyldighed": "Aktiv",
                }
            ]
        },
    }

    if cpr:
        tilknyttedepersoner = [
            {
                "virkning": {
                    "to_included": False,
                    "to": "infinity",
                    "from_included": True,
                    "from": valid_from,
                },
                "urn": "urn:dk:cpr:person:%s" % cpr,
            }
        ]
        expected["relationer"]["tilknyttedepersoner"] = tilknyttedepersoner

    return expected
