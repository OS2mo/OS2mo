# SPDX-FileCopyrightText: 2018-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0
import re
import freezegun
import pytest

import tests.cases
from mora import lora
from mora.util import get_effect_from
from tests import util

ean_class = {
    "example": "5712345000014",
    "name": "EAN",
    "scope": "EAN",
    "user_key": "EAN",
    "uuid": "e34d4426-9845-4c72-b31e-709be85d6fa2",
}

phone_class = {
    "example": "20304060",
    "name": "Telefon",
    "scope": "PHONE",
    "user_key": "Telefon",
    "uuid": "1d1d3711-5af4-4084-99b3-df2b8752fdec",
}

address_type_facet = {
    "description": "",
    "user_key": "org_unit_address_type",
    "uuid": "3c44e5d2-7fef-4448-9bf6-449bf414ec49",
}


@pytest.mark.usefixtures("sample_structures")
@freezegun.freeze_time("2017-01-01", tz_offset=1)
class AsyncWriting(tests.cases.AsyncLoRATestCase):
    maxDiff = None

    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=True)
    async def test_add_org_unit_address(self, mock):
        unitid = "2874e1dc-85e6-4269-823a-e1125484dfd3"

        (addr_id,) = await self.assertRequest(
            "/service/details/create",
            json=[
                {
                    "type": "address",
                    "address_type": {
                        "uuid": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                    },
                    "value": "root@example.com",
                    "org_unit": {"uuid": unitid},
                    "validity": {
                        "from": "2017-01-02",
                    },
                },
            ],
            amqp_topics={"org_unit.address.create": 1},
        )

        expected = {
            "attributter": {
                "organisationfunktionegenskaber": [
                    {
                        "brugervendtnoegle": "root@example.com",
                        "funktionsnavn": "Adresse",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ]
            },
            "livscykluskode": "Importeret",
            "note": "Oprettet i MO",
            "relationer": {
                "adresser": [
                    {
                        "objekttype": "EMAIL",
                        "urn": "urn:mailto:root@example.com",
                        "virkning": {
                            "from": "2017-01-02 00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "organisatoriskfunktionstype": [
                    {
                        "uuid": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "tilknyttedeenheder": [
                    {
                        "uuid": "2874e1dc-85e6-4269-823a-e1125484dfd3",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "tilknyttedeorganisationer": [
                    {
                        "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
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
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ]
            },
        }
        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")

        self.assertRegistrationsEqual(
            expected, await c.organisationfunktion.get(addr_id)
        )

    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=True)
    async def test_add_org_unit_address_contact_open_hours(self, mock):
        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")

        unitid = "2874e1dc-85e6-4269-823a-e1125484dfd3"  # root org

        # matches 'org_unit_contactopenhours'
        addr_type_id = "e8ea1a09-d3d4-4203-bfe9-d9a2da100f3b"

        # Example "Træffetid", original and encoded as URN
        addr_value = "Åbningstider:\nMan-tors: 09:00-15:30\nFre: 09:00-13:00"
        addr_value_as_urn = "urn:text:%c3%85bningstider%3a%0a%4dan%2dtors%3a%2009%3a00%2d15%3a30%0a%46re%3a%2009%3a00%2d13%3a00"  # noqa: E501

        (addr_id,) = await self.assertRequest(
            "/service/details/create",
            json=[
                {
                    "type": "address",
                    "address_type": {
                        "uuid": addr_type_id,
                    },
                    "value": addr_value,
                    "org_unit": {"uuid": unitid},
                    "validity": {
                        "from": "2017-01-02",
                    },
                },
            ],
            amqp_topics={"org_unit.address.create": 1},
        )

        expected = {
            "attributter": {
                "organisationfunktionegenskaber": [
                    {
                        "brugervendtnoegle": addr_value,
                        "funktionsnavn": "Adresse",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ]
            },
            "livscykluskode": "Importeret",
            "note": "Oprettet i MO",
            "relationer": {
                "adresser": [
                    {
                        "objekttype": "TEXT",
                        "urn": addr_value_as_urn,
                        "virkning": {
                            "from": "2017-01-02 00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "organisatoriskfunktionstype": [
                    {
                        "uuid": addr_type_id,
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "tilknyttedeenheder": [
                    {
                        "uuid": "2874e1dc-85e6-4269-823a-e1125484dfd3",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "tilknyttedeorganisationer": [
                    {
                        "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
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
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ]
            },
        }

        self.assertRegistrationsEqual(
            expected, await c.organisationfunktion.get(addr_id)
        )

    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=True)
    async def test_add_employee_address(self, mock):
        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")

        employee_id = "53181ed2-f1de-4c4a-a8fd-ab358c2c454a"

        (addr_id,) = await self.assertRequest(
            "/service/details/create",
            json=[
                {
                    "type": "address",
                    "address_type": {
                        "uuid": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                    },
                    "value": "root@example.com",
                    "person": {"uuid": employee_id},
                    "validity": {
                        "from": "2017-01-02",
                    },
                },
            ],
            amqp_topics={"employee.address.create": 1},
        )

        expected = {
            "attributter": {
                "organisationfunktionegenskaber": [
                    {
                        "brugervendtnoegle": "root@example.com",
                        "funktionsnavn": "Adresse",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ]
            },
            "livscykluskode": "Importeret",
            "note": "Oprettet i MO",
            "relationer": {
                "adresser": [
                    {
                        "objekttype": "EMAIL",
                        "urn": "urn:mailto:root@example.com",
                        "virkning": {
                            "from": "2017-01-02 00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "organisatoriskfunktionstype": [
                    {
                        "uuid": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "tilknyttedebrugere": [
                    {
                        "uuid": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "tilknyttedeorganisationer": [
                    {
                        "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
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
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ]
            },
        }

        with self.subTest("LoRA"):
            self.assertRegistrationsEqual(
                expected,
                await c.organisationfunktion.get(addr_id),
            )

        with self.subTest("result"):
            await self.assertRequestResponse(
                "/service/e/{}/details/address?"
                "validity=future&only_primary_uuid=1".format(employee_id),
                [
                    {
                        "address_type": {
                            "uuid": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                        },
                        "href": "mailto:root@example.com",
                        "name": "root@example.com",
                        "person": {
                            "uuid": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
                        },
                        "user_key": "root@example.com",
                        "uuid": addr_id,
                        "validity": {
                            "from": "2017-01-02",
                            "to": None,
                        },
                        "value": "root@example.com",
                        "value2": None,
                    },
                ],
                amqp_topics={"employee.address.create": 1},
            )

    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=True)
    async def test_create_employee_with_address(self, mock):
        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")

        user_id = await self.assertRequest(
            "/service/e/create",
            json={
                "name": "Torkild Testperson",
                "cpr_no": "0101501234",
                "details": [
                    {
                        "type": "address",
                        "address_type": {
                            "uuid": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                        },
                        "value": "root@example.com",
                        "validity": {
                            "from": "2017-01-02",
                        },
                    },
                ],
            },
            amqp_topics={
                "employee.address.create": 1,
                "employee.employee.create": 1,
            },
        )

        expected = {
            "attributter": {
                "organisationfunktionegenskaber": [
                    {
                        "brugervendtnoegle": "root@example.com",
                        "funktionsnavn": "Adresse",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ]
            },
            "livscykluskode": "Importeret",
            "note": "Oprettet i MO",
            "relationer": {
                "adresser": [
                    {
                        "objekttype": "EMAIL",
                        "urn": "urn:mailto:root@example.com",
                        "virkning": {
                            "from": "2017-01-02 00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "organisatoriskfunktionstype": [
                    {
                        "uuid": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "tilknyttedebrugere": [
                    {
                        "uuid": user_id,
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "tilknyttedeorganisationer": [
                    {
                        "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
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
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ]
            },
        }

        addr_id = await c.organisationfunktion.fetch(tilknyttedebrugere=user_id)

        assert len(addr_id) == 1
        addr_id = addr_id[0]

        self.assertRegistrationsEqual(
            expected, await c.organisationfunktion.get(addr_id)
        )

    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=True)
    async def test_create_engagement_with_address(self, mock):
        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")

        userid = "6ee24785-ee9a-4502-81c2-7697009c9053"
        payload = [
            {
                "type": "engagement",
                "person": {"uuid": userid},
                "primary": {"uuid": "d60d1fd6-e561-463c-9a43-2fa99d27c7a3"},
                "org_unit": {"uuid": "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e"},
                "job_function": {"uuid": "3ef81e52-0deb-487d-9d0e-a69bbe0277d8"},
                "engagement_type": {"uuid": "62ec821f-4179-4758-bfdf-134529d186e9"},
                "user_key": "1234",
                "validity": {
                    "from": "2017-12-01",
                    "to": "2017-12-01",
                },
                "address": [
                    {
                        "type": "address",
                        "address_type": {
                            "uuid": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                        },
                        "value": "root@example.com",
                        "validity": {
                            "from": "2017-01-02",
                        },
                    }
                ],
            }
        ]

        (func_id,) = await self.assertRequest(
            "/service/details/create",
            json=payload,
            amqp_topics={
                "employee.engagement.create": 1,
                "org_unit.engagement.create": 1,
            },
        )
        expected_tilknyttedefunktioner = [
            {
                "uuid": func_id,
                "objekttype": "engagement",
                "virkning": {
                    "from": "2017-01-02 " "00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            }
        ]

        addr_id = await c.organisationfunktion.fetch(tilknyttedefunktioner=func_id)
        assert len(addr_id) == 1
        addr_id = addr_id[0]

        actual = (await c.organisationfunktion.get(addr_id))["relationer"][
            "tilknyttedefunktioner"
        ]

        self.assertEqual(expected_tilknyttedefunktioner, actual)

    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=True)
    async def test_create_org_unit_with_address(self, mock):
        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")

        unit_id = await self.assertRequest(
            "/service/ou/create",
            json={
                "name": "Fake Corp",
                "integration_data": {"fakekey": 42},
                "parent": {"uuid": "2874e1dc-85e6-4269-823a-e1125484dfd3"},
                "org_unit_type": {"uuid": "ca76a441-6226-404f-88a9-31e02e420e52"},
                "validity": {
                    "from": "2016-02-04",
                },
                "details": [
                    {
                        "type": "address",
                        "address_type": {
                            "uuid": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                        },
                        "value": "root@example.com",
                        "validity": {
                            "from": "2017-01-02",
                        },
                    },
                ],
            },
            amqp_topics={
                "org_unit.address.create": 1,
                "org_unit.org_unit.create": 1,
            },
        )

        expected = {
            "attributter": {
                "organisationfunktionegenskaber": [
                    {
                        "brugervendtnoegle": "root@example.com",
                        "funktionsnavn": "Adresse",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ]
            },
            "livscykluskode": "Importeret",
            "note": "Oprettet i MO",
            "relationer": {
                "adresser": [
                    {
                        "objekttype": "EMAIL",
                        "urn": "urn:mailto:root@example.com",
                        "virkning": {
                            "from": "2017-01-02 00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "organisatoriskfunktionstype": [
                    {
                        "uuid": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "tilknyttedeenheder": [
                    {
                        "uuid": unit_id,
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "tilknyttedeorganisationer": [
                    {
                        "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
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
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ]
            },
        }

        addr_id = await c.organisationfunktion.fetch(tilknyttedeenheder=unit_id)
        assert len(addr_id) == 1
        addr_id = addr_id[0]

        self.assertRegistrationsEqual(
            expected, await c.organisationfunktion.get(addr_id)
        )

    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=True)
    async def test_edit_address(self, mock):
        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")

        addr_id = "414044e0-fe5f-4f82-be20-1e107ad50e80"

        await self.assertRequest(
            "/service/details/edit",
            json=[
                {
                    "type": "address",
                    "uuid": addr_id,
                    "data": {
                        "address_type": {
                            "uuid": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                        },
                        "value": "root@example.com",
                        "validity": {
                            "from": "2017-01-02",
                        },
                    },
                }
            ],
            amqp_topics={"org_unit.address.update": 1},
        )

        expected = {
            "attributter": {
                "organisationfunktionegenskaber": [
                    {
                        "brugervendtnoegle": "Nordre "
                        "Ringgade "
                        "1, "
                        "8000 "
                        "Aarhus "
                        "C",
                        "funktionsnavn": "Adresse",
                        "virkning": {
                            "from": "2016-01-01 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ]
            },
            "livscykluskode": "Rettet",
            "note": "Rediger Adresse",
            "relationer": {
                "adresser": [
                    {
                        "objekttype": "DAR",
                        "urn": "urn:dar:b1f1817d-5f02-4331-b8b3-97330a5d3197",
                        "virkning": {
                            "from": "2016-01-01 00:00:00+01",
                            "from_included": True,
                            "to": "2017-01-02 00:00:00+01",
                            "to_included": False,
                        },
                    },
                    {
                        "objekttype": "EMAIL",
                        "urn": "urn:mailto:root@example.com",
                        "virkning": {
                            "from": "2017-01-02 00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    },
                ],
                "organisatoriskfunktionstype": [
                    {
                        "uuid": "28d71012-2919-4b67-a2f0-7b59ed52561e",
                        "virkning": {
                            "from": "2016-01-01 " "00:00:00+01",
                            "from_included": True,
                            "to": "2017-01-02 " "00:00:00+01",
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                        "virkning": {
                            "from": "2017-01-02 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    },
                ],
                "tilknyttedeenheder": [
                    {
                        "uuid": "2874e1dc-85e6-4269-823a-e1125484dfd3",
                        "virkning": {
                            "from": "2016-01-01 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "tilknyttedeorganisationer": [
                    {
                        "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
                        "virkning": {
                            "from": "2016-01-01 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
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
                            "from": "2016-01-01 " "00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ]
            },
        }

        actual = await c.organisationfunktion.get(addr_id)

        self.assertRegistrationsEqual(expected, actual)

    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=True)
    async def test_edit_address_user_key(self, mock):
        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")

        addr_id = "414044e0-fe5f-4f82-be20-1e107ad50e80"

        await self.assertRequest(
            "/service/details/edit",
            json=[
                {
                    "type": "address",
                    "uuid": addr_id,
                    "data": {
                        "user_key": "gedebukkebensoverogundergeneralkrigs"
                        "kommandørsergenten",
                        "validity": {"from": "2018-01-01", "to": "2019-12-31"},
                    },
                }
            ],
            amqp_topics={"org_unit.address.update": 1},
        )

        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")

        actual_reg = await c.organisationfunktion.get(addr_id)
        actual = sorted(
            actual_reg["attributter"]["organisationfunktionegenskaber"],
            key=get_effect_from,
        )

        expected = [
            {
                "brugervendtnoegle": "Nordre Ringgade 1, 8000 Aarhus C",
                "funktionsnavn": "Adresse",
                "virkning": {
                    "from": "2016-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "2018-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "brugervendtnoegle": (
                    "gedebukkebensoverogundergeneralkrigskommandørsergenten"
                ),
                "funktionsnavn": "Adresse",
                "virkning": {
                    "from": "2018-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "2020-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "brugervendtnoegle": "Nordre Ringgade 1, 8000 Aarhus C",
                "funktionsnavn": "Adresse",
                "virkning": {
                    "from": "2020-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        self.assertEqual(actual, expected)

    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=True)
    async def test_create_address_related_to_engagement(self, mock):
        engagement_uuid = "d000591f-8705-4324-897a-075e3623f37b"

        req = [
            {
                "type": "address",
                "address_type": {
                    "uuid": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                },
                "value": "root@example.com",
                "validity": {
                    "from": "2017-01-02",
                },
                "engagement": {"uuid": engagement_uuid},
            }
        ]

        created = await self.assertRequest(
            "/service/details/create",
            json=req,
        )
        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")
        actual_response = await c.organisationfunktion.get(uuid=created[0])
        actual = actual_response["relationer"]["tilknyttedefunktioner"]
        expected = [
            {
                "objekttype": "engagement",
                "uuid": engagement_uuid,
                "virkning": {
                    "from": "2017-01-02 " "00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            }
        ]
        self.assertEqual(actual, expected)


@pytest.mark.usefixtures("sample_structures")
@freezegun.freeze_time("2017-01-01", tz_offset=1)
class Writing(tests.cases.LoRATestCase):
    maxDiff = None

    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=True)
    def test_create_errors(self, mock):
        userid = "53181ed2-f1de-4c4a-a8fd-ab358c2c454a"
        unitid = "04c78fc2-72d2-4d02-b55f-807af19eac48"

        nothingid = "00000000-0000-0000-0000-000000000000"

        with self.subTest("neither failing"):
            req = [
                {
                    "type": "address",
                    "address_type": ean_class,
                    "value": "1234567890",
                    "validity": {
                        "from": "2013-01-01",
                        "to": None,
                    },
                },
            ]

            self.assertRequestResponse(
                "/service/details/create",
                {
                    "description": "Must supply exactly one org_unit UUID, "
                    "person UUID or engagement UUID",
                    "error": True,
                    "error_key": "E_INVALID_INPUT",
                    "obj": req[0],
                    "status": 400,
                },
                json=req,
                status_code=400,
            )

        with self.subTest("both failing"):
            req = [
                {
                    "type": "address",
                    "address_type": ean_class,
                    "value": "1234567890",
                    "person": {
                        "uuid": userid,
                    },
                    "org_unit": {
                        "uuid": unitid,
                    },
                    "validity": {
                        "from": "2013-01-01",
                        "to": None,
                    },
                },
            ]

            self.assertRequestResponse(
                "/service/details/create",
                {
                    "description": "Must supply exactly one org_unit UUID, "
                    "person UUID or engagement UUID",
                    "error": True,
                    "error_key": "E_INVALID_INPUT",
                    "obj": req[0],
                    "status": 400,
                },
                json=req,
                status_code=400,
            )

        with self.subTest("no address"):
            req = [
                {
                    "type": "address",
                    "address_type": {
                        "example": "test@example.com",
                        "name": "Email",
                        "scope": "EMAIL",
                        "user_key": "BrugerEmail",
                        "uuid": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                    },
                    "org_unit": {"uuid": unitid},
                    # NB: no value
                    "validity": {
                        "from": "2017-01-01",
                        "to": None,
                    },
                },
            ]

            self.assertRequestResponse(
                "/service/details/create",
                {
                    "error": True,
                    "error_key": "V_MISSING_REQUIRED_VALUE",
                    "description": "Missing value",
                    "key": "value",
                    "status": 400,
                    "obj": req[0],
                },
                status_code=400,
                json=req,
            )

        with self.subTest("no type"):
            req = [
                {
                    "type": "address",
                    # NB: no type!
                    "address_type": None,
                    "value": "hallo@exmaple.com",
                    "org_unit": {"uuid": unitid},
                    "validity": {
                        "from": "2013-01-01",
                        "to": None,
                    },
                },
            ]

            self.assertRequestResponse(
                "/service/details/create",
                {
                    "description": "Missing address_type",
                    "error": True,
                    "error_key": "V_MISSING_REQUIRED_VALUE",
                    "key": "address_type",
                    "status": 400,
                    "obj": req[0],
                },
                status_code=400,
                json=req,
            )

        with self.subTest("unit not found"):
            req = [
                {
                    "type": "address",
                    "address_type": {
                        "example": "<UUID>",
                        "name": "Postadresse",
                        "scope": "DAR",
                        "user_key": "OrgEnhedPostadresse",
                        "uuid": "28d71012-2919-4b67-a2f0-7b59ed52561e",
                    },
                    "value": "b1f1817d-5f02-4331-b8b3-97330a5d3197",
                    "org_unit": {"uuid": nothingid},
                    "validity": {
                        "from": "2013-01-01",
                        "to": None,
                    },
                }
            ]

            self.assertRequestResponse(
                "/service/details/create",
                {
                    "description": "Org unit not found.",
                    "error": True,
                    "error_key": "E_ORG_UNIT_NOT_FOUND",
                    "status": 404,
                    "org_unit_uuid": nothingid,
                },
                status_code=404,
                json=req,
            )

        with self.subTest("employee not found"):
            req = [
                {
                    "type": "address",
                    "address_type": {
                        "example": "<UUID>",
                        "name": "Postadresse",
                        "scope": "DAR",
                        "user_key": "BrugerPostadresse",
                        "uuid": "4e337d8e-1fd2-4449-8110-e0c8a22958ed",
                    },
                    "value": "b1f1817d-5f02-4331-b8b3-97330a5d3197",
                    "person": {"uuid": nothingid},
                    "validity": {
                        "from": "2013-01-01",
                        "to": None,
                    },
                }
            ]

            self.assertRequestResponse(
                "/service/details/create",
                {
                    "description": "User not found.",
                    "error": True,
                    "error_key": "E_USER_NOT_FOUND",
                    "status": 404,
                    "employee_uuid": nothingid,
                },
                status_code=404,
                json=req,
            )

    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=True)
    def test_create_dar_address_fails_correctly(self, mock):
        """Ensure that we fail when creating a DAR address when lookup fails"""
        expected_msg = {
            "description": "Invalid address",
            "error": True,
            "error_key": "V_INVALID_ADDRESS_DAR",
            "status": 400,
            "value": "4dbf94f1-350f-4f52-bf0f-050b6b1072c0",
        }

        msg = self.assertRequest(
            "/service/details/create",
            status_code=400,
            json=[
                {
                    "type": "address",
                    "address_type": {
                        # Unknown DAR UUID
                        "uuid": "4e337d8e-1fd2-4449-8110-e0c8a22958ed"
                    },
                    "value": "4dbf94f1-350f-4f52-bf0f-050b6b1072c0",
                    "person": {"uuid": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a"},
                    "validity": {
                        "from": "2017-01-02",
                    },
                }
            ],
        )

        self.assertEqual(expected_msg, msg)

    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=True)
    def test_edit_errors(self, mock):
        userid = "53181ed2-f1de-4c4a-a8fd-ab358c2c454a"
        unitid = "04c78fc2-72d2-4d02-b55f-807af19eac48"

        with self.subTest("both failing"):
            req = [
                {
                    "type": "address",
                    "data": {
                        "person": {"uuid": userid},
                        "org_unit": {"uuid": unitid},
                        "address_type": phone_class,
                        "value": "11223344",
                        "validity": {
                            "from": "2017-01-01",
                            "to": "2018-12-31",
                        },
                    },
                    "uuid": "fba61e38-b553-47cc-94bf-8c7c3c2a6887",
                },
            ]

            self.assertRequestResponse(
                "/service/details/edit",
                {
                    "description": "Must supply at most one of org_unit UUID, "
                    "person UUID and engagement UUID",
                    "error": True,
                    "error_key": "E_INVALID_INPUT",
                    "obj": req[0],
                    "status": 400,
                },
                status_code=400,
                json=req,
            )


@pytest.mark.usefixtures("sample_structures_minimal")
@freezegun.freeze_time("2017-01-01", tz_offset=1)
class AsyncReadingMinimal(tests.cases.AsyncLoRATestCase):
    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=True)
    async def test_missing_class(self, mock):
        # The relevant address_type klasse is not present in the minimal dataset
        await util.load_fixture(
            "organisation/organisationfunktion",
            "create_organisationfunktion_email_andersand.json",
        )

        with pytest.raises(ValueError, match="NoneType"):
            await self.assertRequest(
                "/service/e/53181ed2-f1de-4c4a-a8fd-ab358c2c454a" "/details/address",
            )


@pytest.mark.usefixtures("sample_structures")
@freezegun.freeze_time("2017-01-01", tz_offset=1)
class AsyncReading(tests.cases.AsyncLoRATestCase):
    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=False)
    async def test_missing_address(self, mock):
        unitid = "2874e1dc-85e6-4269-823a-e1125484dfd3"
        addrid = "bd7e5317-4a9e-437b-8923-11156406b117"
        functionid = "414044e0-fe5f-4f82-be20-1e107ad50e80"

        for t in (
            "adresser",
            "adgangsadresser",
            "historik/adresser",
            "historik/adgangsadresser",
        ):
            pattern = re.compile(r"^https://api.dataforsyningen.dk/" + t + ".*$")
            mock.get(pattern, json=[])

        await lora.Connector().organisationfunktion.update(
            {
                "relationer": {
                    "adresser": [
                        {
                            "objekttype": "DAR",
                            "urn": "urn:dar:{}".format(addrid),
                            "virkning": {
                                "from": "2016-01-01",
                                "to": "2020-01-01",
                            },
                        },
                    ],
                },
            },
            functionid,
        )

        await self.assertRequestResponse(
            "/service/ou/{}/details/address".format(unitid),
            [
                {
                    "address_type": {
                        "example": "<UUID>",
                        "facet": address_type_facet,
                        "name": "Postadresse",
                        "owner": None,
                        "scope": "DAR",
                        "top_level_facet": address_type_facet,
                        "user_key": "OrgEnhedPostadresse",
                        "uuid": "28d71012-2919-4b67-a2f0-7b59ed52561e",
                    },
                    "user_key": "Nordre Ringgade 1, 8000 Aarhus C",
                    "href": None,
                    "name": "Ukendt",
                    "org_unit": {
                        "name": "Overordnet Enhed",
                        "user_key": "root",
                        "uuid": "2874e1dc-85e6-4269-823a-e1125484dfd3",
                        "validity": {"from": "2016-01-01", "to": None},
                    },
                    "uuid": "414044e0-fe5f-4f82-be20-1e107ad50e80",
                    "validity": {"from": "2016-01-01", "to": "2019-12-31"},
                    "value": "bd7e5317-4a9e-437b-8923-11156406b117",
                    "value2": None,
                }
            ],
        )

    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=False)
    async def test_missing_error(self, mock):
        unitid = "2874e1dc-85e6-4269-823a-e1125484dfd3"
        addrid = "bd7e5317-4a9e-437b-8923-11156406b117"
        functionid = "414044e0-fe5f-4f82-be20-1e107ad50e80"

        mock.get(
            re.compile(r"^https://api.dataforsyningen.dk/adresser.*$"),
            json={
                "type": "ResourceNotFoundError",
                "title": "The resource was not found",
                "details": {
                    "id": addrid,
                },
            },
            status=500,
        )

        await lora.Connector().organisationfunktion.update(
            {
                "relationer": {
                    "adresser": [
                        {
                            "objekttype": "DAR",
                            "urn": "urn:dar:{}".format(addrid),
                            "virkning": {
                                "from": "2016-01-01",
                                "to": "2020-01-01",
                            },
                        },
                    ],
                },
            },
            functionid,
        )

        await self.assertRequestResponse(
            "/service/ou/{}/details/address".format(unitid),
            [
                {
                    "address_type": {
                        "example": "<UUID>",
                        "facet": address_type_facet,
                        "name": "Postadresse",
                        "owner": None,
                        "scope": "DAR",
                        "top_level_facet": address_type_facet,
                        "user_key": "OrgEnhedPostadresse",
                        "uuid": "28d71012-2919-4b67-a2f0-7b59ed52561e",
                    },
                    "href": None,
                    "name": "Ukendt",
                    "user_key": "Nordre Ringgade 1, 8000 Aarhus C",
                    "org_unit": {
                        "name": "Overordnet Enhed",
                        "user_key": "root",
                        "uuid": "2874e1dc-85e6-4269-823a-e1125484dfd3",
                        "validity": {"from": "2016-01-01", "to": None},
                    },
                    "uuid": "414044e0-fe5f-4f82-be20-1e107ad50e80",
                    "validity": {"from": "2016-01-01", "to": "2019-12-31"},
                    "value": addrid,
                    "value2": None,
                }
            ],
        )


@pytest.mark.usefixtures("sample_structures")
@freezegun.freeze_time("2017-01-01", tz_offset=1)
class Reading(tests.cases.LoRATestCase):
    @util.darmock("dawa-addresses.json", allow_mox=True, real_http=True)
    def test_reading(self, mock):
        with self.subTest("Addresses present"):
            self.assertRequestResponse(
                "/service/e/6ee24785-ee9a-4502-81c2-7697009c9053"
                "/details/address?validity=present&only_primary_uuid=1",
                [
                    {
                        "uuid": "64ea02e2-8469-4c54-a523-3d46729e86a7",
                        "address_type": {
                            "uuid": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                        },
                        "href": "mailto:goofy@example.com",
                        "name": "goofy@example.com",
                        "value": "goofy@example.com",
                        "value2": None,
                        "user_key": "bruger@example.comw",
                        "person": {
                            "uuid": "6ee24785-ee9a-4502-81c2-7697009c9053",
                        },
                        "validity": {
                            "from": "1932-05-12",
                            "to": None,
                        },
                    },
                    {
                        "uuid": "cd6008bc-1ad2-4272-bc1c-d349ef733f52",
                        "address_type": {
                            "uuid": "4e337d8e-1fd2-4449-8110-e0c8a22958ed",
                        },
                        "href": "https://www.openstreetmap.org/?mlon="
                        "10.19938084&mlat=56.17102843&zoom=16",
                        "name": "Nordre Ringgade 1, 8000 Aarhus C",
                        "value": "b1f1817d-5f02-4331-b8b3-97330a5d3197",
                        "value2": None,
                        "user_key": "Christiansborg Slotsplads 1, " "1218 København K",
                        "person": {
                            "uuid": "6ee24785-ee9a-4502-81c2-7697009c9053",
                        },
                        "validity": {
                            "from": "1932-05-12",
                            "to": None,
                        },
                    },
                ],
            )

        with self.subTest("No addresses"):
            self.assertRequestResponse(
                "/service/ou/b688513d-11f7-4efc-b679-ab082a2055d0"
                "/details/address?validity=present",
                [],
            )
