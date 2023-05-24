# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from typing import Any

import freezegun
import pytest
from fastapi.testclient import TestClient

import tests.cases
from mora import lora


@pytest.mark.usefixtures("load_fixture_data_with_reset")
@freezegun.freeze_time("2017-01-01", tz_offset=1)
class AsyncWritingITSystem(tests.cases.AsyncLoRATestCase):
    async def test_create_employee_itsystem(self):
        # Check the POST request
        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")

        userid = "6ee24785-ee9a-4502-81c2-7697009c9053"

        with self.subTest("preconditions"):
            await self.assertRequestResponse(
                f"/service/e/{userid}/details/it?validity=past",
                [],
            )

            await self.assertRequestResponse(
                f"/service/e/{userid}/details/it",
                [],
            )

            await self.assertRequestResponse(
                f"/service/e/{userid}/details/it?validity=future",
                [],
            )

        assert (
            list(
                await c.organisationfunktion.get_all(
                    funktionsnavn="IT-system", tilknyttedebrugere=userid
                )
            )
            == []
        )

        (funcid,) = await self.assertRequest(
            "/service/details/create",
            json=[
                {
                    "type": "it",
                    "user_key": "goofy-moofy",
                    "person": {
                        "uuid": userid,
                    },
                    "engagement": {"uuid": "b6c268d2-4671-4609-8441-6029077d8efc"},
                    "itsystem": {"uuid": "0872fb72-926d-4c5c-a063-ff800b8ee697"},
                    "validity": {"from": "2018-09-01", "to": None},
                },
            ],
            amqp_topics={"employee.it.create": 1},
        )

        await self.assertRequestResponse(
            f"/service/e/{userid}/details/it?validity=past",
            [],
            amqp_topics={"employee.it.create": 1},
        )

        await self.assertRequestResponse(
            f"/service/e/{userid}/details/it",
            [],
            amqp_topics={"employee.it.create": 1},
        )

        await self.assertRequestResponse(
            "/service/e/{}/details/it?validity=future&only_primary_uuid=1".format(
                userid
            ),
            [
                {
                    "itsystem": {
                        "uuid": "0872fb72-926d-4c5c-a063-ff800b8ee697",
                    },
                    "org_unit": None,
                    "person": {"uuid": "6ee24785-ee9a-4502-81c2-7697009c9053"},
                    "engagement": None,
                    "user_key": "goofy-moofy",
                    "uuid": funcid,
                    "validity": {"from": "2018-09-01", "to": None},
                    "primary": None,
                }
            ],
            amqp_topics={"employee.it.create": 1},
        )

    async def test_create_unit_itsystem(self):
        # Check the POST request
        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")

        unitid = "b688513d-11f7-4efc-b679-ab082a2055d0"

        with self.subTest("preconditions"):
            await self.assertRequestResponse(
                f"/service/ou/{unitid}/details/it?validity=past",
                [],
            )

            await self.assertRequestResponse(
                f"/service/ou/{unitid}/details/it",
                [],
            )

            await self.assertRequestResponse(
                f"/service/ou/{unitid}/details/it?validity=future",
                [],
            )

        assert (
            list(
                await c.organisationfunktion.get_all(
                    funktionsnavn="IT-system", tilknyttedebrugere=unitid
                )
            )
            == []
        )

        (funcid,) = await self.assertRequest(
            "/service/details/create",
            json=[
                {
                    "type": "it",
                    "user_key": "root",
                    "org_unit": {
                        "uuid": unitid,
                    },
                    "itsystem": {"uuid": "0872fb72-926d-4c5c-a063-ff800b8ee697"},
                    "validity": {"from": "2018-09-01", "to": None},
                },
            ],
            amqp_topics={"org_unit.it.create": 1},
        )

        await self.assertRequestResponse(
            f"/service/ou/{unitid}/details/it?validity=past",
            [],
            amqp_topics={"org_unit.it.create": 1},
        )

        await self.assertRequestResponse(
            f"/service/ou/{unitid}/details/it",
            [],
            amqp_topics={"org_unit.it.create": 1},
        )

        await self.assertRequestResponse(
            f"/service/ou/{unitid}/details/it?validity=future",
            [
                {
                    "itsystem": {
                        "name": "Lokal Rammearkitektur",
                        "reference": None,
                        "system_type": None,
                        "user_key": "LoRa",
                        "uuid": "0872fb72-926d-4c5c-a063-ff800b8ee697",
                        "validity": {"from": "2010-01-01", "to": None},
                    },
                    "org_unit": {
                        "name": "Samfundsvidenskabelige fakultet",
                        "user_key": "samf",
                        "uuid": "b688513d-11f7-4efc-b679-ab082a2055d0",
                        "validity": {"from": "2017-01-01", "to": None},
                    },
                    "person": None,
                    "engagement": None,
                    "user_key": "root",
                    "uuid": funcid,
                    "validity": {"from": "2018-09-01", "to": None},
                    "primary": None,
                }
            ],
            amqp_topics={"org_unit.it.create": 1},
        )

    @freezegun.freeze_time("2017-06-22", tz_offset=2)
    async def test_edit_itsystem(self):
        it_func_id = "cd4dcccb-5bf7-4c6b-9e1a-f6ebb193e276"

        old_unit_id = "04c78fc2-72d2-4d02-b55f-807af19eac48"
        new_unit_id = "0eb323ac-8513-4b18-80fd-b1dfa7fd9a02"

        old_it_system_id = "0872fb72-926d-4c5c-a063-ff800b8ee697"
        new_it_system_id = "7e7c4f54-a85c-41fa-bae4-74e410215320"

        await self.assertRequestResponse(
            "/service/details/edit",
            [it_func_id],
            json=[
                {
                    "type": "it",
                    "uuid": it_func_id,
                    "data": {
                        "itsystem": {
                            "uuid": new_it_system_id,
                        },
                        "org_unit": {
                            "uuid": new_unit_id,
                        },
                        "validity": {
                            "from": "2017-06-22",
                            "to": "2018-06-01",
                        },
                    },
                }
            ],
            amqp_topics={"org_unit.it.update": 1},
        )

        expected_it_func = {
            "attributter": {
                "organisationfunktionegenskaber": [
                    {
                        "brugervendtnoegle": "fwaf",
                        "funktionsnavn": "IT-system",
                        "virkning": {
                            "from": "2017-01-01 " "00:00:00+01",
                            "from_included": True,
                            "to": "2018-06-02 " "00:00:00+02",
                            "to_included": False,
                        },
                    }
                ]
            },
            "livscykluskode": "Rettet",
            "note": "Rediger IT-system",
            "relationer": {
                "tilknyttedeenheder": [
                    {
                        "uuid": old_unit_id,
                        "virkning": {
                            "from": "2017-01-01 " "00:00:00+01",
                            "from_included": True,
                            "to": "2017-06-22 " "00:00:00+02",
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": new_unit_id,
                        "virkning": {
                            "from": "2017-06-22 " "00:00:00+02",
                            "from_included": True,
                            "to": "2018-06-02 " "00:00:00+02",
                            "to_included": False,
                        },
                    },
                ],
                "tilknyttedeitsystemer": [
                    {
                        "uuid": old_it_system_id,
                        "virkning": {
                            "from": "2017-01-01 " "00:00:00+01",
                            "from_included": True,
                            "to": "2017-06-22 " "00:00:00+02",
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": new_it_system_id,
                        "virkning": {
                            "from": "2017-06-22 " "00:00:00+02",
                            "from_included": True,
                            "to": "2018-06-02 " "00:00:00+02",
                            "to_included": False,
                        },
                    },
                ],
                "tilknyttedeorganisationer": [
                    {
                        "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
                        "virkning": {
                            "from": "2017-01-01 " "00:00:00+01",
                            "from_included": True,
                            "to": "2018-06-02 " "00:00:00+02",
                            "to_included": False,
                        },
                    }
                ],
            },
            "tilstande": {
                "organisationfunktiongyldighed": [
                    {
                        "gyldighed": "Aktiv",
                        "virkning": {
                            "from": "2017-01-01 " "00:00:00+01",
                            "from_included": True,
                            "to": "2018-06-02 " "00:00:00+02",
                            "to_included": False,
                        },
                    }
                ]
            },
        }

        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")
        actual_it_func = await c.organisationfunktion.get(it_func_id)

        self.assertRegistrationsEqual(expected_it_func, actual_it_func)


@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
@freezegun.freeze_time("2017-01-01", tz_offset=1)
@pytest.mark.parametrize(
    "operation,expected,payload,status_code",
    [
        (
            "create",
            {
                "description": "Missing itsystem",
                "error": True,
                "error_key": "V_MISSING_REQUIRED_VALUE",
                "key": "itsystem",
                "obj": {
                    "itsystem": None,
                    "type": "it",
                    "validity": {"from": "2017-12-01", "to": None},
                },
                "status": 400,
            },
            [
                {
                    "type": "it",
                    "itsystem": None,
                    "validity": {
                        "from": "2017-12-01",
                        "to": None,
                    },
                },
            ],
            400,
        ),
        (
            "create",
            {
                "error": True,
                "error_key": "E_NOT_FOUND",
                "description": "Not found.",
                "status": 404,
            },
            [
                {
                    "type": "it",
                    "itsystem": {
                        "uuid": "00000000-0000-0000-0000-000000000000",
                    },
                    "validity": {
                        "from": "2017-12-01",
                        "to": None,
                    },
                },
            ],
            404,
        ),
        (
            "create",
            {
                "description": "Missing itsystem",
                "error": True,
                "error_key": "V_MISSING_REQUIRED_VALUE",
                "key": "itsystem",
                "obj": {
                    "itsystem": None,
                    "type": "it",
                    "validity": {"from": "2017-12-01", "to": None},
                },
                "status": 400,
            },
            [
                {
                    "type": "it",
                    "itsystem": None,
                    "validity": {
                        "from": "2017-12-01",
                        "to": None,
                    },
                },
            ],
            400,
        ),
        (
            "create",
            {
                "error": True,
                "error_key": "V_MISSING_START_DATE",
                "description": "Missing start date.",
                "status": 400,
                "obj": {
                    "itsystem": {"uuid": "59c135c9-2b15-41cc-97c8-b5dff7180beb"},
                    "type": "it",
                    "validity": {"from": None, "to": None},
                },
            },
            [
                {
                    "type": "it",
                    "itsystem": {
                        "uuid": "59c135c9-2b15-41cc-97c8-b5dff7180beb",
                    },
                    "validity": {
                        "from": None,
                        "to": None,
                    },
                },
            ],
            400,
        ),
        (
            "create",
            {
                "description": 'invalid input syntax for type uuid: "None"',
                "error": True,
                "error_key": "E_INVALID_INPUT",
                "status": 400,
            },
            [
                {
                    "type": "it",
                    "itsystem": {},
                    "validity": {
                        "from": None,
                        "to": None,
                    },
                },
            ],
            400,
        ),
        (
            "create",
            {
                "error": True,
                "error_key": "E_INVALID_UUID",
                "description": "Invalid uuid for 'uuid': '42'",
                "status": 400,
                "obj": {"uuid": "42"},
            },
            [
                {
                    "type": "it",
                    "itsystem": {
                        "uuid": "42",
                    },
                    "validity": {
                        "from": "2017-12-01",
                        "to": None,
                    },
                },
            ],
            400,
        ),
        (
            "edit",
            {
                "description": "Not found.",
                "error": True,
                "error_key": "E_NOT_FOUND",
                "status": 404,
            },
            [
                {
                    "type": "it",
                    # WRONG:
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "original": {
                        "name": "Active Directory",
                        "reference": None,
                        "system_type": None,
                        "user_key": "AD",
                        "uuid": "59c135c9-2b15-41cc-97c8-b5dff7180beb",
                        "validity": {
                            "from": "1932-05-12",
                            "to": None,
                        },
                    },
                    "data": {
                        "validity": {
                            "to": "2019-12-31",
                        },
                    },
                },
            ],
            404,
        ),
        (
            "edit",
            {
                "description": "Missing uuid",
                "error": True,
                "error_key": "V_MISSING_REQUIRED_VALUE",
                "key": "uuid",
                "obj": {
                    "type": "it",
                    "data": {"uuid": None},
                    "original": {
                        "name": "Active Directory",
                        "reference": None,
                        "system_type": None,
                        "user_key": "AD",
                        "uuid": "59c135c9-2b15-41cc-97c8-b5dff7180beb",
                        "validity": {"from": "1932-05-12", "to": None},
                    },
                },
                "status": 400,
            },
            [
                {
                    "type": "it",
                    "original": {
                        "name": "Active Directory",
                        "reference": None,
                        "system_type": None,
                        "user_key": "AD",
                        "uuid": "59c135c9-2b15-41cc-97c8-b5dff7180beb",
                        "validity": {
                            "from": "1932-05-12",
                            "to": None,
                        },
                    },
                    "data": {
                        "uuid": None,
                    },
                },
            ],
            400,
        ),
    ],
)
def test_errors(
    service_client: TestClient,
    operation: str,
    expected: list[dict],
    payload: dict,
    status_code: int,
) -> None:
    response = service_client.post(f"/service/details/{operation}", json=payload)
    assert response.status_code == status_code
    assert response.json() == expected


@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
def test_reading_organisation(service_client: TestClient) -> None:
    response = service_client.get(
        "/service/o/456362c4-0ee4-4e5e-a72c-751239745e62/it/",
    )
    assert response.status_code == 200
    assert response.json() == [
        {
            "system_type": None,
            "user_key": "LoRa",
            "uuid": "0872fb72-926d-4c5c-a063-ff800b8ee697",
            "name": "Lokal Rammearkitektur",
        },
        {
            "system_type": None,
            "user_key": "SAP",
            "uuid": "14466fb0-f9de-439c-a6c2-b3262c367da7",
            "name": "SAP",
        },
        {
            "system_type": None,
            "user_key": "AD",
            "uuid": "59c135c9-2b15-41cc-97c8-b5dff7180beb",
            "name": "Active Directory",
        },
    ]


@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
def test_reading_employee(service_client: TestClient) -> None:
    response = service_client.get(
        "/service/e/53181ed2-f1de-4c4a-a8fd-ab358c2c454a/details/it",
        params={"only_primary_uuid": 1},
    )
    assert response.status_code == 200
    assert response.json() == [
        {
            "itsystem": {
                "uuid": "59c135c9-2b15-41cc-97c8-b5dff7180beb",
            },
            "org_unit": None,
            "person": {"uuid": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a"},
            "engagement": None,
            "user_key": "donald",
            "uuid": "aaa8c495-d7d4-4af1-b33a-f4cb27b82c66",
            "validity": {"from": "2017-01-01", "to": None},
            "primary": None,
        },
    ]


@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
@pytest.mark.parametrize(
    "unitid",
    [
        "2874e1dc-85e6-4269-823a-e1125484dfd3",
        "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e",
        "b688513d-11f7-4efc-b679-ab082a2055d0",
        "85715fc7-925d-401b-822d-467eb4b163b6",
        "da77153e-30f3-4dc2-a611-ee912a28d8aa",
    ],
)
@pytest.mark.parametrize("validity", ["past", "present", "future"])
def test_reading_unit_empty(
    service_client: TestClient, unitid: str, validity: str
) -> None:
    response = service_client.get(
        f"/service/ou/{unitid}/details/it", params={"validity": validity}
    )
    assert response.status_code == 200
    assert response.json() == []


reading_unit_result = [
    {
        "itsystem": {
            "name": "Lokal Rammearkitektur",
            "reference": None,
            "system_type": None,
            "user_key": "LoRa",
            "uuid": "0872fb72-926d-4c5c-a063-ff800b8ee697",
            "validity": {"from": "2010-01-01", "to": None},
        },
        "org_unit": {
            "name": "Afdeling for Fortidshistorik",
            "user_key": "frem",
            "uuid": "04c78fc2-72d2-4d02-b55f-807af19eac48",
            "validity": {"from": "2016-01-01", "to": "2018-12-31"},
        },
        "person": None,
        "user_key": "fwaf",
        "engagement": None,
        "uuid": "cd4dcccb-5bf7-4c6b-9e1a-f6ebb193e276",
        "validity": {"from": "2017-01-01", "to": "2017-12-31"},
        "primary": None,
    }
]
reading_unit_result_now = [
    {
        "itsystem": {
            "name": "Lokal Rammearkitektur",
            "reference": None,
            "system_type": None,
            "user_key": "LoRa",
            "uuid": "0872fb72-926d-4c5c-a063-ff800b8ee697",
            "validity": {"from": "2010-01-01", "to": None},
        },
        "org_unit": {
            "name": "Afdeling for Samtidshistorik",
            "user_key": "frem",
            "uuid": "04c78fc2-72d2-4d02-b55f-807af19eac48",
            "validity": {"from": "2016-01-01", "to": "2018-12-31"},
        },
        "person": None,
        "user_key": "fwaf",
        "engagement": None,
        "uuid": "cd4dcccb-5bf7-4c6b-9e1a-f6ebb193e276",
        "validity": {"from": "2017-01-01", "to": "2017-12-31"},
        "primary": None,
    }
]


@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
@pytest.mark.parametrize(
    "params,expected",
    [
        # 2017-01-01 (via freeze_time)
        ({"validity": "past"}, []),
        ({"validity": "present"}, reading_unit_result_now),
        ({}, reading_unit_result_now),
        ({"validity": "future"}, []),
        # 2016-06-01
        ({"at": "2016-06-01", "validity": "past"}, []),
        ({"at": "2016-06-01", "validity": "present"}, []),
        ({"at": "2016-06-01"}, []),
        ({"at": "2016-06-01", "validity": "future"}, reading_unit_result),
        # 2018-06-01
        ({"at": "2018-06-01", "validity": "past"}, reading_unit_result),
        ({"at": "2018-06-01", "validity": "present"}, []),
        ({"at": "2018-06-01"}, []),
        ({"at": "2018-06-01", "validity": "future"}, []),
    ],
)
@freezegun.freeze_time("2017-01-01", tz_offset=1)
def test_reading_unit(
    service_client: TestClient, params: dict[str, Any], expected: list[dict]
) -> None:
    unitid = "04c78fc2-72d2-4d02-b55f-807af19eac48"
    response = service_client.get(f"/service/ou/{unitid}/details/it", params=params)
    assert response.status_code == 200
    assert response.json() == expected
