# SPDX-FileCopyrightText: 2018-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0
import freezegun
import pytest

import tests.cases
from mora import lora
from tests.util import sample_structures_minimal_cls_fixture


@pytest.mark.usefixtures("load_fixture_data_with_reset")
@freezegun.freeze_time("2017-01-01", tz_offset=1)
class AsyncWriting(tests.cases.AsyncLoRATestCase):
    async def test_create_employee_itsystem(self):
        # Check the POST request
        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")

        userid = "6ee24785-ee9a-4502-81c2-7697009c9053"

        with self.subTest("preconditions"):
            await self.assertRequestResponse(
                "/service/e/{}/details/it?validity=past".format(userid),
                [],
            )

            await self.assertRequestResponse(
                "/service/e/{}/details/it".format(userid),
                [],
            )

            await self.assertRequestResponse(
                "/service/e/{}/details/it?validity=future".format(userid),
                [],
            )

        self.assertEqual(
            list(
                await c.organisationfunktion.get_all(
                    funktionsnavn="IT-system",
                    tilknyttedebrugere=userid,
                )
            ),
            [],
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
                    "itsystem": {"uuid": "0872fb72-926d-4c5c-a063-ff800b8ee697"},
                    "validity": {"from": "2018-09-01", "to": None},
                },
            ],
            amqp_topics={"employee.it.create": 1},
        )

        await self.assertRequestResponse(
            "/service/e/{}/details/it?validity=past".format(userid),
            [],
            amqp_topics={"employee.it.create": 1},
        )

        await self.assertRequestResponse(
            "/service/e/{}/details/it".format(userid),
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
                "/service/ou/{}/details/it?validity=past".format(unitid),
                [],
            )

            await self.assertRequestResponse(
                "/service/ou/{}/details/it".format(unitid),
                [],
            )

            await self.assertRequestResponse(
                "/service/ou/{}/details/it?validity=future".format(unitid),
                [],
            )

        self.assertEqual(
            list(
                await c.organisationfunktion.get_all(
                    funktionsnavn="IT-system",
                    tilknyttedebrugere=unitid,
                )
            ),
            [],
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
            "/service/ou/{}/details/it?validity=past".format(unitid),
            [],
            amqp_topics={"org_unit.it.create": 1},
        )

        await self.assertRequestResponse(
            "/service/ou/{}/details/it".format(unitid),
            [],
            amqp_topics={"org_unit.it.create": 1},
        )

        await self.assertRequestResponse(
            "/service/ou/{}/details/it?validity=future".format(unitid),
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


@sample_structures_minimal_cls_fixture
@freezegun.freeze_time("2017-01-01", tz_offset=1)
class WritingMinimal(tests.cases.LoRATestCase):
    maxDiff = None

    @classmethod
    def get_lora_environ(cls):
        # force LoRA to run under a UTC timezone, ensuring that we
        # handle this case correctly for writing
        return {
            "TZ": "UTC",
        }

    def test_errors(self):
        # In Postgres 10.0 the messages mentioning type names was changed. See
        # https://github.com/postgres/postgres/commit/9a34123bc315e55b33038464422ef1cd2b67dab2
        # This test will fail if run against postgres >=10.0. We can ignore it
        # with `pytest -m "not psql_9_dependent"`.
        self.assertRequestResponse(
            "/service/details/create",
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
            json=[
                {
                    "type": "it",
                    "itsystem": None,
                    "validity": {
                        "from": "2017-12-01",
                        "to": None,
                    },
                },
            ],
            status_code=400,
        )

        self.assertRequestResponse(
            "/service/details/create",
            {
                "error": True,
                "error_key": "E_NOT_FOUND",
                "description": "Not found.",
                "status": 404,
            },
            json=[
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
            status_code=404,
        )

        self.assertRequestResponse(
            "/service/details/create",
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
            json=[
                {
                    "type": "it",
                    "itsystem": None,
                    "validity": {
                        "from": "2017-12-01",
                        "to": None,
                    },
                },
            ],
            status_code=400,
        )

        self.assertRequestResponse(
            "/service/details/create",
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
            json=[
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
            status_code=400,
        )

        self.assertRequestResponse(
            "/service/details/create",
            {
                "description": 'invalid input syntax for type uuid: "None"',
                "error": True,
                "error_key": "E_INVALID_INPUT",
                "status": 400,
            },
            json=[
                {
                    "type": "it",
                    "itsystem": {},
                    "validity": {
                        "from": None,
                        "to": None,
                    },
                },
            ],
            status_code=400,
        )

        self.assertRequestResponse(
            "/service/details/create",
            {
                "error": True,
                "error_key": "E_INVALID_UUID",
                "description": "Invalid uuid for 'uuid': '42'",
                "status": 400,
                "obj": {"uuid": "42"},
            },
            json=[
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
            status_code=400,
        )

        self.assertRequestResponse(
            "/service/details/edit",
            {
                "description": "Not found.",
                "error": True,
                "error_key": "E_NOT_FOUND",
                "status": 404,
            },
            json=[
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
            status_code=404,
        )

        self.assertRequestResponse(
            "/service/details/edit",
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
            json=[
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
            status_code=400,
        )


@pytest.mark.usefixtures("load_fixture_data_with_reset")
@freezegun.freeze_time("2017-01-01", tz_offset=1)
class Reading(tests.cases.LoRATestCase):
    def test_reading_organisation(self):
        self.assertRequestResponse(
            "/service/o/456362c4-0ee4-4e5e-a72c-751239745e62/it/",
            [
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
            ],
        )

    def test_reading_employee(self):
        self.assertRequestResponse(
            "/service/e/53181ed2-f1de-4c4a-a8fd-ab358c2c454a/"
            "details/it?only_primary_uuid=1",
            [
                {
                    "itsystem": {
                        "uuid": "59c135c9-2b15-41cc-97c8-b5dff7180beb",
                    },
                    "org_unit": None,
                    "person": {"uuid": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a"},
                    "user_key": "donald",
                    "uuid": "aaa8c495-d7d4-4af1-b33a-f4cb27b82c66",
                    "validity": {"from": "2017-01-01", "to": None},
                    "primary": None,
                },
            ],
        )

    def test_reading_unit(self):
        for unitid in (
            "2874e1dc-85e6-4269-823a-e1125484dfd3",
            "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e",
            "b688513d-11f7-4efc-b679-ab082a2055d0",
            "85715fc7-925d-401b-822d-467eb4b163b6",
            "da77153e-30f3-4dc2-a611-ee912a28d8aa",
        ):
            for validity in ("past", "present", "future"):
                with self.subTest("{} - {}".format(unitid, validity)):
                    self.assertRequestResponse(
                        "/service/ou/{}/details/it?validity={}".format(
                            unitid,
                            validity,
                        ),
                        [],
                    )

        self.assertRequestResponse(
            "/service/ou/04c78fc2-72d2-4d02-b55f-807af19eac48/details/it",
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
                        "name": "Afdeling for Samtidshistorik",
                        "user_key": "frem",
                        "uuid": "04c78fc2-72d2-4d02-b55f-807af19eac48",
                        "validity": {"from": "2016-01-01", "to": "2018-12-31"},
                    },
                    "person": None,
                    "user_key": "fwaf",
                    "uuid": "cd4dcccb-5bf7-4c6b-9e1a-f6ebb193e276",
                    "validity": {"from": "2017-01-01", "to": "2017-12-31"},
                    "primary": None,
                },
            ],
        )

        self.assertRequestResponse(
            "/service/ou/04c78fc2-72d2-4d02-b55f-807af19eac48/details/it"
            "?validity=past",
            [],
        )

        self.assertRequestResponse(
            "/service/ou/04c78fc2-72d2-4d02-b55f-807af19eac48/details/it"
            "?validity=future",
            [],
        )

        self.assertRequestResponse(
            "/service/ou/04c78fc2-72d2-4d02-b55f-807af19eac48/details/it"
            "?at=2016-06-01",
            [],
        )

        self.assertRequestResponse(
            "/service/ou/04c78fc2-72d2-4d02-b55f-807af19eac48/details/it"
            "?at=2016-06-01&validity=future",
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
                        "name": "Afdeling for Fortidshistorik",
                        "user_key": "frem",
                        "uuid": "04c78fc2-72d2-4d02-b55f-807af19eac48",
                        "validity": {"from": "2016-01-01", "to": "2018-12-31"},
                    },
                    "person": None,
                    "user_key": "fwaf",
                    "uuid": "cd4dcccb-5bf7-4c6b-9e1a-f6ebb193e276",
                    "validity": {"from": "2017-01-01", "to": "2017-12-31"},
                    "primary": None,
                },
            ],
        )

        self.assertRequestResponse(
            "/service/ou/04c78fc2-72d2-4d02-b55f-807af19eac48/details/it"
            "?at=2016-06-01&validity=past",
            [],
        )

        self.assertRequestResponse(
            "/service/ou/04c78fc2-72d2-4d02-b55f-807af19eac48/details/it"
            "?at=2018-06-01&validity=present",
            [],
        )

        self.assertRequestResponse(
            "/service/ou/04c78fc2-72d2-4d02-b55f-807af19eac48/details/it"
            "?at=2018-06-01&validity=past",
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
                        "name": "Afdeling for Fortidshistorik",
                        "user_key": "frem",
                        "uuid": "04c78fc2-72d2-4d02-b55f-807af19eac48",
                        "validity": {"from": "2016-01-01", "to": "2018-12-31"},
                    },
                    "person": None,
                    "user_key": "fwaf",
                    "uuid": "cd4dcccb-5bf7-4c6b-9e1a-f6ebb193e276",
                    "validity": {"from": "2017-01-01", "to": "2017-12-31"},
                    "primary": None,
                },
            ],
        )

        self.assertRequestResponse(
            "/service/ou/04c78fc2-72d2-4d02-b55f-807af19eac48/details/it"
            "?at=2018-06-01&validity=future",
            [],
        )
