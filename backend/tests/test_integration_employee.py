# SPDX-FileCopyrightText: 2018-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0

import freezegun
import notsouid

import mora.async_util
import tests.cases
from mora import lora
from . import util


@freezegun.freeze_time("2017-01-01", tz_offset=1)
class Tests(tests.cases.LoRATestCase):
    maxDiff = None

    def test_create_employee(self):
        self.load_sample_structures()

        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")

        mock_uuid = "b6c268d2-4671-4609-8441-6029077d8efc"

        payload = {
            "givenname": "Torkild",
            "surname": "von Testperson",
            "nickname_givenname": "Torkild",
            "nickname_surname": "Sejfyr",
            "seniority": "2017-01-01",
            "cpr_no": "0101501234",
            "org": {"uuid": "456362c4-0ee4-4e5e-a72c-751239745e62"},
        }

        with notsouid.freeze_uuid(mock_uuid):
            r = self.request("/service/e/create", json=payload)
        userid = r.json()

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
                            "from": "1950-01-01 00:00:00+01",
                        },
                        "brugervendtnoegle": mock_uuid,
                        "integrationsdata": "{}",
                    }
                ],
                "brugerudvidelser": [
                    {
                        "fornavn": "Torkild",
                        "efternavn": "von Testperson",
                        "kaldenavn_fornavn": "Torkild",
                        "kaldenavn_efternavn": "Sejfyr",
                        "seniority": "2017-01-01",
                        "virkning": {
                            "from": "1950-01-01 " "00:00:00+01",
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
                            "from": "1950-01-01 00:00:00+01",
                        },
                        "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
                    }
                ],
                "tilknyttedepersoner": [
                    {
                        "virkning": {
                            "to_included": False,
                            "to": "infinity",
                            "from_included": True,
                            "from": "1950-01-01 00:00:00+01",
                        },
                        "urn": "urn:dk:cpr:person:0101501234",
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
                            "from": "1950-01-01 00:00:00+01",
                        },
                        "gyldighed": "Aktiv",
                    }
                ]
            },
        }

        actual = mora.async_util.async_to_sync(c.bruger.get)(userid)

        self.assertRegistrationsEqual(expected, actual)

        self.assertRequestResponse(
            "/service/e/{}/".format(userid),
            {
                "givenname": "Torkild",
                "surname": "von Testperson",
                "name": "Torkild von Testperson",
                "nickname_givenname": "Torkild",
                "nickname_surname": "Sejfyr",
                "nickname": "Torkild Sejfyr",
                "seniority": "2017-01-01",
                "org": {
                    "name": "Aarhus Universitet",
                    "user_key": "AU",
                    "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
                },
                "user_key": mock_uuid,
                "cpr_no": "0101501234",
                "uuid": userid,
            },
            amqp_topics={"employee.employee.create": 1},
        )

    def test_create_employee_like_import(self):
        """Test creating a user that has no CPR number, but does have a
        user_key and a given UUID.

        """
        self.load_sample_structures()

        userid = "ef78f929-2eb4-4d9e-8891-f9e8dcb47533"

        self.assertRequest(
            "/service/e/create",
            json={
                "givenname": "Teodor",
                "surname": "Testfætter",
                "user_key": "testfætter",
                "org": {"uuid": "456362c4-0ee4-4e5e-a72c-751239745e62"},
                "uuid": userid,
            },
        )

    def test_create_employee_fails_on_empty_payload(self):
        self.load_sample_structures()

        payload = {}

        self.assertRequestResponse(
            "/service/e/create",
            {
                "description": "Missing required value.",
                "error": True,
                "error_key": "V_MISSING_REQUIRED_VALUE",
                "name": "Missing name or givenname or surname",
                "status": 400,
            },
            json=payload,
            status_code=400,
        )

    def test_create_employee_fails_on_invalid_cpr(self):
        self.load_sample_structures()
        payload = {
            "name": "Torkild Testperson",
            "cpr_no": "1",
            "org": {"uuid": "456362c4-0ee4-4e5e-a72c-751239745e62"},
        }

        self.assertRequestResponse(
            "/service/e/create",
            {
                "cpr": "1",
                "description": "Not a valid CPR number.",
                "error": True,
                "error_key": "V_CPR_NOT_VALID",
                "status": 400,
            },
            json=payload,
            status_code=400,
        )

    def test_create_employee_existing_cpr_existing_org(self):
        self.load_sample_structures()

        payload = {
            "givenname": "Torkild",
            "surname": "Testperson",
            "cpr_no": "0906340000",
            "org": {"uuid": "456362c4-0ee4-4e5e-a72c-751239745e62"},
        }

        expected = {
            "cpr": "0906340000",
            "description": "Person with CPR number already exists.",
            "error": True,
            "error_key": "V_EXISTING_CPR",
            "status": 409,
        }

        self.assertRequestResponse(
            "/service/e/create",
            expected,
            json=payload,
            status_code=409,
        )

    def test_fail_on_double_naming(self):
        self.load_sample_structures()

        payload = {
            "givenname": "Torkild",
            "surname": "Testperson",
            "name": "Torkild Testperson",
            "cpr_no": "0906340000",
            "org": {"uuid": "456362c4-0ee4-4e5e-a72c-751239745e62"},
        }

        expected = {
            "description": "Invalid input.",
            "error": True,
            "error_key": "E_INVALID_INPUT",
            "name": "Supply either name or given name/surame",
            "status": 400,
        }

        self.assertRequestResponse(
            "/service/e/create",
            expected,
            json=payload,
            status_code=400,
        )

    def test_create_employee_existing_cpr_new_org(self):
        """
        Should not be able to create employee with same CPR no,
        in different organisation, as only one is allowed
        """
        self.load_sample_structures()

        payload = {
            "name": "Torkild Testperson",
            "cpr_no": "0906340000",
            "org": {"uuid": "3dcb1072-482e-491e-a8ad-647991d0bfcf"},
        }
        r = self.request("/service/e/create", json=payload)
        self.assertEqual(
            {
                "description": "Organisation is not allowed",
                "uuid": "3dcb1072-482e-491e-a8ad-647991d0bfcf",
                "status": 400,
                "error_key": "E_ORG_NOT_ALLOWED",
                "error": True,
            },
            r.json(),
        )

    def test_create_employee_with_details(self):
        """Test creating an employee with added details.
        Also add three names to a single name parameter and check
        it will be split on lest space."""
        self.load_sample_structures()

        employee_uuid = "f7bcc7b1-381a-4f0e-a3f5-48a7b6eedf1c"

        payload = {
            "name": "Torkild Von Testperson",
            "cpr_no": "0101501234",
            "org": {"uuid": "456362c4-0ee4-4e5e-a72c-751239745e62"},
            "details": [
                {
                    "type": "engagement",
                    "org_unit": {"uuid": "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e"},
                    "job_function": {"uuid": "3ef81e52-0deb-487d-9d0e-a69bbe0277d8"},
                    "engagement_type": {"uuid": "62ec821f-4179-4758-bfdf-134529d186e9"},
                    "validity": {
                        "from": "2016-12-01",
                        "to": None,
                    },
                }
            ],
            "uuid": employee_uuid,
        }

        self.assertRequestResponse(
            "/service/e/create",
            employee_uuid,
            json=payload,
            amqp_topics={
                "employee.engagement.create": 1,
                "org_unit.engagement.create": 1,
                "employee.employee.create": 1,
            },
        )

        self.assertRequestResponse(
            "/service/e/{}/".format(employee_uuid),
            {
                "surname": "Testperson",
                "givenname": "Torkild Von",
                "name": "Torkild Von Testperson",
                "nickname_surname": "",
                "nickname_givenname": "",
                "seniority": "",
                "nickname": "",
                "org": {
                    "name": "Aarhus Universitet",
                    "user_key": "AU",
                    "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
                },
                "user_key": employee_uuid,
                "cpr_no": "0101501234",
                "uuid": employee_uuid,
            },
            amqp_topics={
                "employee.engagement.create": 1,
                "org_unit.engagement.create": 1,
                "employee.employee.create": 1,
            },
        )

        r = self.request("/service/e/{}/details/engagement".format(employee_uuid))
        self.assertEqual(1, len(r.json()), "One engagement should exist")

    def test_create_employee_with_details_fails_atomically(self):
        """Ensure that we only save data when everything validates correctly"""
        self.load_sample_structures()

        employee_uuid = "d2e1b69e-def1-41b1-b652-e704af02591c"

        payload_broken_engagement = {
            "name": "Torkild Testperson",
            "cpr_no": "0101501234",
            "org": {"uuid": "456362c4-0ee4-4e5e-a72c-751239745e62"},
            "details": [
                {
                    "type": "engagement",
                    "org_unit": {"uuid": "9d07123e-47ac-4a9a-" "88c8-da82e3a4bc9e"},
                    "job_function": {"uuid": "3ef81e52-0deb-487d-9d0e-a69bbe0277d8"},
                    "engagement_type": {"uuid": "62ec821f-4179-4758-bfdf-134529d186e9"},
                    "validity": {
                        "from": "1960-12-01",
                        "to": "2017-12-01",
                    },
                }
            ],
            "uuid": employee_uuid,
        }

        self.assertRequestResponse(
            "/service/e/create",
            {
                "description": "Date range exceeds validity "
                "range of associated org unit.",
                "error": True,
                "error_key": "V_DATE_OUTSIDE_ORG_UNIT_RANGE",
                "org_unit_uuid": "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e",
                "status": 400,
                "valid_from": "2016-01-01",
                "valid_to": None,
                "wanted_valid_from": "1960-12-01",
                "wanted_valid_to": "2017-12-01",
            },
            status_code=400,
            json=payload_broken_engagement,
        )

        payload_broken_employee = {
            "name": "Torkild Testperson",
            "cpr_no": "0101174234",
            "org": {"uuid": "456362c4-0ee4-4e5e-a72c-751239745e62"},
            "details": [
                {
                    "type": "engagement",
                    "org_unit": {"uuid": "9d07123e-47ac-4a9a-" "88c8-da82e3a4bc9e"},
                    "job_function": {"uuid": "3ef81e52-0deb-487d-9d0e-a69bbe0277d8"},
                    "engagement_type": {"uuid": "62ec821f-4179-4758-bfdf-134529d186e9"},
                    "validity": {
                        "from": "2016-12-01",
                        "to": "2017-12-01",
                    },
                }
            ],
            "uuid": employee_uuid,
        }

        self.assertRequestResponse(
            "/service/e/create",
            {
                "description": "Date range exceeds validity "
                "range of associated employee.",
                "error": True,
                "error_key": "V_DATE_OUTSIDE_EMPL_RANGE",
                "status": 400,
                "valid_from": "2017-01-01",
                "valid_to": "9999-12-31",
                "wanted_valid_from": "2016-12-01",
                "wanted_valid_to": "2017-12-02",
            },
            status_code=400,
            json=payload_broken_employee,
        )

        # Assert that nothing has been written

        self.assertRequestResponse(
            "/service/e/{}/".format(employee_uuid),
            {
                "status": 404,
                "error": True,
                "description": "User not found.",
                "error_key": "E_USER_NOT_FOUND",
            },
            status_code=404,
        )

        engagement = self.request(
            "/service/e/{}/details/engagement".format(employee_uuid)
        ).json()
        self.assertEqual([], engagement, "No engagement should have been created")

    def test_cpr_lookup_prod_mode_false(self):
        # Arrange
        cpr = "0101501234"

        expected = {"name": "Merle Mortensen", "cpr_no": cpr}

        # Act
        self.assertRequestResponse("/service/e/cpr_lookup/?q={}".format(cpr), expected)

    def test_cpr_lookup_raises_on_wrong_length(self):
        # Arrange

        # Act
        self.assertRequestResponse(
            "/service/e/cpr_lookup/?q=1234/",
            {
                "cpr": "1234/",
                "description": "Not a valid CPR number.",
                "error": True,
                "error_key": "V_CPR_NOT_VALID",
                "status": 400,
            },
            status_code=400,
        )
        self.assertRequestResponse(
            "/service/e/cpr_lookup/?q=1234",
            {
                "cpr": "1234",
                "description": "Not a valid CPR number.",
                "error": True,
                "error_key": "V_CPR_NOT_VALID",
                "status": 400,
            },
            status_code=400,
        )
        self.assertRequestResponse(
            "/service/e/cpr_lookup/?q=1234567890123",
            {
                "cpr": "1234567890123",
                "description": "Not a valid CPR number.",
                "error": True,
                "error_key": "V_CPR_NOT_VALID",
                "status": 400,
            },
            status_code=400,
        )

    def test_edit_employee_overwrite(self):
        # A generic example of editing an employee

        self.load_sample_structures()

        userid = "6ee24785-ee9a-4502-81c2-7697009c9053"

        req = [
            {
                "type": "employee",
                "original": {
                    "validity": {"from": "2016-01-01 00:00:00+01", "to": None},
                    "cpr_no": "1205320000",
                    "givenname": "Fedtmule",
                    "surname": "Hund",
                    "uuid": userid,
                },
                "data": {
                    "validity": {
                        "from": "2017-01-01",
                    },
                    "cpr_no": "0202020202",
                    "givenname": "Test",
                    "surname": "2 Employee",
                    "nickname_givenname": "Testmand",
                    "nickname_surname": "Whatever",
                    "seniority": "2017-01-01",
                },
            }
        ]

        self.assertRequestResponse(
            "/service/details/edit",
            [userid],
            json=req,
            amqp_topics={"employee.employee.update": 1},
        )

        # there must be a registration of the new name
        expected_brugeregenskaber = [
            {
                "brugervendtnoegle": "fedtmule",
                "virkning": {
                    "from": "1932-05-12 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            }
        ]

        expected_brugerudvidelser = [
            {
                "fornavn": "Fedtmule",
                "efternavn": "Hund",
                "kaldenavn_fornavn": "George",
                "kaldenavn_efternavn": "Geef",
                "virkning": {
                    "from": "1932-05-12 00:00:00+01",
                    "from_included": True,
                    "to": "2017-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "fornavn": "Test",
                "efternavn": "2 Employee",
                "kaldenavn_fornavn": "Testmand",
                "kaldenavn_efternavn": "Whatever",
                "seniority": "2017-01-01",
                "virkning": {
                    "from": "2017-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        expected_tilknyttedepersoner = [
            {
                "urn": "urn:dk:cpr:person:0202020202",
                "virkning": {
                    "from": "2017-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
            {
                "urn": "urn:dk:cpr:person:1205320000",
                "virkning": {
                    "from": "1932-05-12 00:00:00+01",
                    "from_included": True,
                    "to": "2017-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
        ]

        # but looking at the validity of the original that was sent along
        # the period from that fromdate up to the this fromdate has been
        # removed

        expected_brugergyldighed = [
            {
                "gyldighed": "Aktiv",
                "virkning": {
                    "from": "1932-05-12 00:00:00+01",
                    "from_included": True,
                    "to": "2016-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "gyldighed": "Aktiv",
                "virkning": {
                    "from": "2017-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
            {
                "gyldighed": "Inaktiv",
                "virkning": {
                    "from": "2016-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "2017-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
        ]

        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")
        actual = mora.async_util.async_to_sync(c.bruger.get)(userid)

        self.assertEqual(
            expected_brugeregenskaber, actual["attributter"]["brugeregenskaber"]
        )
        self.assertEqual(
            expected_brugerudvidelser, actual["attributter"]["brugerudvidelser"]
        )
        self.assertEqual(
            expected_brugergyldighed, actual["tilstande"]["brugergyldighed"]
        )
        self.assertEqual(
            expected_tilknyttedepersoner, actual["relationer"]["tilknyttedepersoner"]
        )

    def test_edit_employee(self):
        # A generic example of editing an employee

        self.load_sample_structures()

        userid = "6ee24785-ee9a-4502-81c2-7697009c9053"

        req = [
            {
                "type": "employee",
                "original": None,
                "data": {
                    "validity": {
                        "from": "2017-02-02",
                    },
                    "user_key": "regnbøfssalat",
                    "cpr_no": "0101010101",
                    "givenname": "Martin L",
                    "surname": "Gore",
                    "nickname_givenname": "John",
                    "nickname_surname": "Morfar",
                    "seniority": "2017-01-01",
                },
                "uuid": userid,
            }
        ]

        self.assertRequestResponse(
            "/service/details/edit",
            [userid],
            json=req,
            amqp_topics={"employee.employee.update": 1},
        )

        # there must be a registration of the new name
        expected_brugeregenskaber = [
            {
                "brugervendtnoegle": "fedtmule",
                "virkning": {
                    "from": "1932-05-12 00:00:00+01",
                    "from_included": True,
                    "to": "2017-02-02 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "brugervendtnoegle": "regnbøfssalat",
                "virkning": {
                    "from": "2017-02-02 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        expected_brugerudvidelser = [
            {
                "fornavn": "Fedtmule",
                "efternavn": "Hund",
                "kaldenavn_fornavn": "George",
                "kaldenavn_efternavn": "Geef",
                "virkning": {
                    "from": "1932-05-12 00:00:00+01",
                    "from_included": True,
                    "to": "2017-02-02 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "fornavn": "Martin L",
                "efternavn": "Gore",
                "kaldenavn_fornavn": "John",
                "kaldenavn_efternavn": "Morfar",
                "seniority": "2017-01-01",
                "virkning": {
                    "from": "2017-02-02 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        # but looking at the validity of the original that was sent along
        # the period from that fromdate up to the this fromdate has been
        # removed

        expected_brugergyldighed = [
            {
                "gyldighed": "Aktiv",
                "virkning": {
                    "from": "1932-05-12 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            }
        ]

        expected_tilknyttedepersoner = [
            {
                "urn": "urn:dk:cpr:person:0101010101",
                "virkning": {
                    "from": "2017-02-02 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
            {
                "urn": "urn:dk:cpr:person:1205320000",
                "virkning": {
                    "from": "1932-05-12 00:00:00+01",
                    "from_included": True,
                    "to": "2017-02-02 00:00:00+01",
                    "to_included": False,
                },
            },
        ]

        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")
        actual = mora.async_util.async_to_sync(c.bruger.get)(userid)

        self.assertEqual(
            expected_brugeregenskaber, actual["attributter"]["brugeregenskaber"]
        )
        self.assertEqual(
            expected_brugerudvidelser, actual["attributter"]["brugerudvidelser"]
        )
        self.assertEqual(
            expected_brugergyldighed, actual["tilstande"]["brugergyldighed"]
        )
        self.assertEqual(
            expected_tilknyttedepersoner, actual["relationer"]["tilknyttedepersoner"]
        )

    def test_edit_remove_seniority(self):
        # A generic example of editing an employee

        self.load_sample_structures()

        userid = "6ee24785-ee9a-4502-81c2-7697009c9053"

        req = [
            {
                "type": "employee",
                "original": None,
                "data": {
                    "validity": {
                        "from": "2017-02-02",
                    },
                    "user_key": "regnbøfssalat",
                    "seniority": "2017-01-01",
                },
                "uuid": userid,
            }
        ]

        self.assertRequestResponse(
            "/service/details/edit",
            [userid],
            json=req,
            amqp_topics={"employee.employee.update": 1},
        )

        expected_seniorities = ["2017-01-01", None]

        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")
        actual = mora.async_util.async_to_sync(c.bruger.get)(userid)
        self.assertEqual(
            expected_seniorities,
            list(
                map(
                    lambda x: x.get("seniority", None),
                    actual["attributter"]["brugerudvidelser"],
                )
            ),
        )

        req = [
            {
                "type": "employee",
                "original": None,
                "data": {
                    "validity": {
                        "from": "2017-02-03",
                    },
                    "seniority": None,
                },
                "uuid": userid,
            }
        ]

        self.assertRequestResponse(
            "/service/details/edit",
            [userid],
            json=req,
            amqp_topics={"employee.employee.update": 2},
        )

        expected_seniorities = [None, None, "2017-01-01"]

        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")
        actual = mora.async_util.async_to_sync(c.bruger.get)(userid)

        self.assertEqual(
            expected_seniorities,
            sorted(
                map(
                    lambda x: x.get("seniority", None),
                    actual["attributter"]["brugerudvidelser"],
                ),
                key=lambda x: "" if x is None else x,
            ),
        )

    @freezegun.freeze_time("2016-01-01", tz_offset=2)
    def test_get_integration_data(self):
        self.load_sample_structures()
        employee_uuid = "df55a3ad-b996-4ae0-b6ea-a3241c4cbb24"
        mora.async_util.async_to_sync(util.load_fixture)(
            "organisation/bruger", "create_bruger_andersine.json", employee_uuid
        )

        self.assertRequestResponse(
            "/service/e/{}/integration-data".format(employee_uuid),
            {
                "integration_data": {"von-and-løn-id": "2468"},
                "surname": "And",
                "givenname": "Andersine",
                "name": "Andersine And",
                "nickname": "Daisy Duck",
                "nickname_givenname": "Daisy",
                "nickname_surname": "Duck",
                "seniority": "",
                "uuid": "df55a3ad-b996-4ae0-b6ea-a3241c4cbb24",
            },
        )

    @freezegun.freeze_time("2016-01-01", tz_offset=2)
    def test_edit_integration_data(self):
        self.load_sample_structures()
        employee_uuid = "df55a3ad-b996-4ae0-b6ea-a3241c4cbb24"
        mora.async_util.async_to_sync(util.load_fixture)(
            "organisation/bruger", "create_bruger_andersine.json", employee_uuid
        )

        req = {
            "type": "employee",
            "data": {
                "uuid": employee_uuid,
                "integration_data": {
                    "von-and-løn-id": "2468",
                    "bjørnebanden-hjælper-id": "sorte-slyngel",
                },
                "validity": {
                    "from": "2016-01-01",
                    "to": "2016-01-02",
                },
            },
        }

        self.assertRequestResponse(
            "/service/details/edit",
            employee_uuid,
            json=req,
            amqp_topics={"employee.employee.update": 1},
        )

        self.assertRequestResponse(
            "/service/e/" + employee_uuid + "/integration-data?at=2016-01-01",
            {
                "integration_data": {
                    "bjørnebanden-hjælper-id": "sorte-slyngel",
                    "von-and-løn-id": "2468",
                },
                "surname": "And",
                "givenname": "Andersine",
                "name": "Andersine And",
                "nickname": "Daisy Duck",
                "nickname_givenname": "Daisy",
                "nickname_surname": "Duck",
                "seniority": "",
                "uuid": employee_uuid,
            },
            amqp_topics={"employee.employee.update": 1},
        )
