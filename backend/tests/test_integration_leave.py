#
# Copyright (c) Magenta ApS
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
from unittest.mock import patch

import freezegun

from mora import lora
from tests import util

mock_uuid = '1eb680cd-d8ec-4fd2-8ca0-dce2d03f59a5'


@freezegun.freeze_time('2016-01-01', tz_offset=1)
@patch('uuid.uuid4', new=lambda: mock_uuid)
class Tests(util.LoRATestCase):
    maxDiff = None

    def test_create_leave(self):
        self.load_sample_structures()

        # Check the POST request
        c = lora.Connector(virkningfra='-infinity', virkningtil='infinity')

        userid = "53181ed2-f1de-4c4a-a8fd-ab358c2c454a"
        leave_type = "62ec821f-4179-4758-bfdf-134529d186e9"
        org_uuid = "2a7b1686-d697-489d-9f02-96d16e1e224b"

        payload = [
            {
                "type": "leave",
                "person": {
                    "uuid": userid,
                },
                "leave_type": {
                    'uuid': leave_type},
                "user_key": "1234",
                "org": {
                    "uuid": org_uuid
                },
                "validity": {
                    "from": "2017-12-01",
                    "to": "2017-12-01",
                },
            }
        ]

        leaveid, = self.assertRequest(
            '/service/details/create',
            json=payload,
            amqp_topics={'employee.leave.create': 1},
        )

        expected = {
            "livscykluskode": "Importeret",
            "tilstande": {
                "organisationfunktiongyldighed": [
                    {
                        "virkning": {
                            "to_included": False,
                            "to": "2017-12-02 00:00:00+01",
                            "from_included": True,
                            "from": "2017-12-01 00:00:00+01"
                        },
                        "gyldighed": "Aktiv"
                    }
                ]
            },
            "note": "Oprettet i MO",
            "relationer": {
                "tilknyttedeorganisationer": [
                    {
                        "virkning": {
                            "to_included": False,
                            "to": "2017-12-02 00:00:00+01",
                            "from_included": True,
                            "from": "2017-12-01 00:00:00+01"
                        },
                        "uuid": org_uuid
                    }
                ],
                "tilknyttedebrugere": [
                    {
                        "virkning": {
                            "to_included": False,
                            "to": "2017-12-02 00:00:00+01",
                            "from_included": True,
                            "from": "2017-12-01 00:00:00+01"
                        },
                        "uuid": userid
                    }
                ],
                "organisatoriskfunktionstype": [
                    {
                        "virkning": {
                            "to_included": False,
                            "to": "2017-12-02 00:00:00+01",
                            "from_included": True,
                            "from": "2017-12-01 00:00:00+01"
                        },
                        "uuid": leave_type
                    }
                ],
            },
            "attributter": {
                "organisationfunktionegenskaber": [
                    {
                        "virkning": {
                            "to_included": False,
                            "to": "2017-12-02 00:00:00+01",
                            "from_included": True,
                            "from": "2017-12-01 00:00:00+01"
                        },
                        "brugervendtnoegle": "1234",
                        "funktionsnavn": "Orlov"
                    }
                ]
            }
        }

        actual_leave = c.organisationfunktion.get(leaveid)

        self.assertRegistrationsEqual(actual_leave, expected)

    def test_create_leave_no_valid_to(self):
        self.load_sample_structures()

        # Check the POST request
        c = lora.Connector(virkningfra='-infinity', virkningtil='infinity')

        userid = "53181ed2-f1de-4c4a-a8fd-ab358c2c454a"
        leave_type = "62ec821f-4179-4758-bfdf-134529d186e9"

        payload = [
            {
                "type": "leave",
                "person": {
                    "uuid": userid,
                },
                "leave_type": {
                    'uuid': leave_type
                },
                "validity": {
                    "from": "2017-12-01",
                },
            }
        ]

        leaveid, = self.assertRequest(
            '/service/details/create',
            json=payload,
            amqp_topics={'employee.leave.create': 1},
        )

        expected = {
            "livscykluskode": "Importeret",
            "tilstande": {
                "organisationfunktiongyldighed": [
                    {
                        "virkning": {
                            "to_included": False,
                            "to": "infinity",
                            "from_included": True,
                            "from": "2017-12-01 00:00:00+01"
                        },
                        "gyldighed": "Aktiv"
                    }
                ]
            },
            "note": "Oprettet i MO",
            "relationer": {
                "tilknyttedeorganisationer": [
                    {
                        "virkning": {
                            "to_included": False,
                            "to": "infinity",
                            "from_included": True,
                            "from": "2017-12-01 00:00:00+01"
                        },
                        "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62"
                    }
                ],
                "tilknyttedebrugere": [
                    {
                        "virkning": {
                            "to_included": False,
                            "to": "infinity",
                            "from_included": True,
                            "from": "2017-12-01 00:00:00+01"
                        },
                        "uuid": userid
                    }
                ],
                "organisatoriskfunktionstype": [
                    {
                        "virkning": {
                            "to_included": False,
                            "to": "infinity",
                            "from_included": True,
                            "from": "2017-12-01 00:00:00+01"
                        },
                        "uuid": leave_type
                    }
                ],
            },
            "attributter": {
                "organisationfunktionegenskaber": [
                    {
                        "virkning": {
                            "to_included": False,
                            "to": "infinity",
                            "from_included": True,
                            "from": "2017-12-01 00:00:00+01"
                        },
                        "brugervendtnoegle": mock_uuid,
                        "funktionsnavn": "Orlov"
                    }
                ]
            }
        }

        actual_leave = c.organisationfunktion.get(leaveid)

        # drop lora-generated timestamps & users
        del actual_leave['fratidspunkt'], actual_leave[
            'tiltidspunkt'], actual_leave[
            'brugerref']

        self.assertEqual(actual_leave, expected)

    def test_create_leave_fails_on_empty_payload(self):
        self.load_sample_structures()

        payload = [
            {
                "type": "leave",
            }
        ]

        self.assertRequestResponse(
            '/service/details/create',
            {
                'description': 'Missing person',
                'error': True,
                'error_key': 'V_MISSING_REQUIRED_VALUE',
                'key': 'person',
                'obj': payload[0],
                'status': 400,
            },
            json=payload,
            status_code=400,
        )

    def test_create_leave_fails_when_no_active_engagement(self):
        """Should fail on validation when the employee has no
        active engagements"""
        self.load_sample_structures()

        # Check the POST request
        userid = "6ee24785-ee9a-4502-81c2-7697009c9053"
        leave_type = "62ec821f-4179-4758-bfdf-134529d186e9"

        payload = [
            {
                "type": "leave",
                "person": {
                    "uuid": userid,
                },
                "leave_type": {
                    'uuid': leave_type},
                "validity": {
                    "from": "2017-12-01",
                    "to": "2017-12-01",
                },
            }
        ]

        self.assertRequestResponse(
            '/service/details/create',
            {
                'description': 'Employee must have an active engagement.',
                'employee': '6ee24785-ee9a-4502-81c2-7697009c9053',
                'error': True,
                'error_key': 'V_NO_ACTIVE_ENGAGEMENT',
                'status': 400
            },
            json=payload,
            status_code=400
        )

    def test_edit_leave_no_overwrite(self):
        self.load_sample_structures()

        leave_uuid = 'b807628c-030c-4f5f-a438-de41c1f26ba5'

        req = [{
            "type": "leave",
            "uuid": leave_uuid,
            "data": {
                "user_key": "koflagerske",
                "leave_type": {
                    'uuid': "bcd05828-cc10-48b1-bc48-2f0d204859b2"
                },
                "validity": {
                    "from": "2018-04-01",
                },
            },
        }]

        self.assertRequestResponse(
            '/service/details/edit',
            [leave_uuid],
            json=req,
            amqp_topics={'employee.leave.update': 1},
        )

        expected_leave = {
            "note": "Rediger orlov",
            "relationer": {
                "organisatoriskfunktionstype": [
                    {
                        "uuid": "32547559-cfc1-4d97-94c6-70b192eff825",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "2018-04-01 00:00:00+02"
                        }
                    },
                    {
                        "uuid": "bcd05828-cc10-48b1-bc48-2f0d204859b2",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2018-04-01 00:00:00+02",
                            "to": "infinity"
                        }
                    },
                ],
                "tilknyttedeorganisationer": [
                    {
                        "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "infinity"
                        }
                    }
                ],
                "tilknyttedebrugere": [
                    {
                        "uuid": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "infinity"
                        }
                    }
                ]
            },
            "livscykluskode": "Rettet",
            "tilstande": {
                "organisationfunktiongyldighed": [
                    {
                        "gyldighed": "Aktiv",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "2018-04-01 00:00:00+02"
                        }
                    },
                    {
                        "gyldighed": "Aktiv",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2018-04-01 00:00:00+02",
                            "to": "infinity"
                        }
                    }
                ]
            },
            "attributter": {
                "organisationfunktionegenskaber": [
                    {
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "2018-04-01 00:00:00+02",
                        },
                        "brugervendtnoegle": "bvn",
                        "funktionsnavn": "Orlov"
                    },
                    {
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2018-04-01 00:00:00+02",
                            "to": "infinity"
                        },
                        "brugervendtnoegle": "koflagerske",
                        "funktionsnavn": "Orlov"
                    }
                ]
            },
        }

        c = lora.Connector(virkningfra='-infinity', virkningtil='infinity')
        actual_leave = c.organisationfunktion.get(leave_uuid)

        # drop lora-generated timestamps & users
        del actual_leave['fratidspunkt'], actual_leave[
            'tiltidspunkt'], actual_leave[
            'brugerref']

        self.assertEqual(expected_leave, actual_leave)

    def test_edit_leave_minimal(self):
        self.load_sample_structures()

        leave_uuid = 'b807628c-030c-4f5f-a438-de41c1f26ba5'

        req = [{
            "type": "leave",
            "uuid": leave_uuid,
            "data": {
                "validity": {
                    "from": "2018-04-01",
                },
            },
        }]

        self.assertRequestResponse(
            '/service/details/edit',
            [leave_uuid],
            json=req,
            amqp_topics={'employee.leave.update': 1},
        )

        expected_leave = {
            "note": "Rediger orlov",
            "relationer": {
                "organisatoriskfunktionstype": [
                    {
                        "uuid": "32547559-cfc1-4d97-94c6-70b192eff825",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "infinity"
                        }
                    }
                ],
                "tilknyttedeorganisationer": [
                    {
                        "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "infinity"
                        }
                    }
                ],
                "tilknyttedebrugere": [
                    {
                        "uuid": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "infinity"
                        }
                    }
                ]
            },
            "livscykluskode": "Rettet",
            "tilstande": {
                "organisationfunktiongyldighed": [
                    {
                        "gyldighed": "Aktiv",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "2018-04-01 00:00:00+02"
                        }
                    },
                    {
                        "gyldighed": "Aktiv",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2018-04-01 00:00:00+02",
                            "to": "infinity"
                        }
                    }
                ]
            },
            "attributter": {
                "organisationfunktionegenskaber": [
                    {
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "infinity"
                        },
                        "brugervendtnoegle": "bvn",
                        "funktionsnavn": "Orlov"
                    }
                ]
            },
        }

        c = lora.Connector(virkningfra='-infinity', virkningtil='infinity')
        actual_leave = c.organisationfunktion.get(leave_uuid)

        # drop lora-generated timestamps & users
        del actual_leave['fratidspunkt'], actual_leave[
            'tiltidspunkt'], actual_leave[
            'brugerref']

        self.assertEqual(expected_leave, actual_leave)

    def test_edit_leave_overwrite(self):
        self.load_sample_structures()

        leave_uuid = 'b807628c-030c-4f5f-a438-de41c1f26ba5'

        req = [{
            "type": "leave",
            "uuid": leave_uuid,
            "original": {
                "validity": {
                    "from": "2017-01-01",
                    "to": None
                },
                "leave_type": {
                    'uuid': "32547559-cfc1-4d97-94c6-70b192eff825"},
            },
            "data": {
                "leave_type": {
                    'uuid': "bcd05828-cc10-48b1-bc48-2f0d204859b2"
                },
                "validity": {
                    "from": "2018-04-01",
                },
            },
        }]

        self.assertRequestResponse(
            '/service/details/edit',
            [leave_uuid],
            json=req,
            amqp_topics={'employee.leave.update': 1},
        )

        expected_leave = {
            "note": "Rediger orlov",
            "relationer": {
                "organisatoriskfunktionstype": [
                    {
                        "uuid": "32547559-cfc1-4d97-94c6-70b192eff825",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "2018-04-01 00:00:00+02"
                        }
                    },
                    {
                        "uuid": "bcd05828-cc10-48b1-bc48-2f0d204859b2",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2018-04-01 00:00:00+02",
                            "to": "infinity"
                        }
                    },
                ],
                "tilknyttedeorganisationer": [
                    {
                        "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "infinity"
                        }
                    }
                ],
                "tilknyttedebrugere": [
                    {
                        "uuid": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "infinity"
                        }
                    }
                ]
            },
            "livscykluskode": "Rettet",
            "tilstande": {
                "organisationfunktiongyldighed": [
                    {
                        "gyldighed": "Aktiv",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2018-04-01 00:00:00+02",
                            "to": "infinity"
                        }
                    },
                    {
                        "gyldighed": "Inaktiv",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "2018-04-01 00:00:00+02"
                        }
                    }
                ]
            },
            "attributter": {
                "organisationfunktionegenskaber": [
                    {
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "infinity"
                        },
                        "brugervendtnoegle": "bvn",
                        "funktionsnavn": "Orlov"
                    }
                ]
            },
        }

        c = lora.Connector(virkningfra='-infinity', virkningtil='infinity')
        actual_leave = c.organisationfunktion.get(leave_uuid)

        # drop lora-generated timestamps & users
        del actual_leave['fratidspunkt'], actual_leave[
            'tiltidspunkt'], actual_leave[
            'brugerref']

        self.assertEqual(expected_leave, actual_leave)

    def test_edit_leave_fails_when_no_active_engagement(self):
        self.load_sample_structures()

        leave_uuid = 'b807628c-030c-4f5f-a438-de41c1f26ba5'

        req = [{
            "type": "leave",
            "uuid": leave_uuid,
            "data": {
                "leave_type": {
                    'uuid': "bcd05828-cc10-48b1-bc48-2f0d204859b2"
                },
                "validity": {
                    "from": "2016-04-01",
                    "to": "2016-04-01",
                },
            },
        }]

        self.assertRequestResponse(
            '/service/details/edit',
            {
                'description': 'Employee must have an active engagement.',
                'employee': '53181ed2-f1de-4c4a-a8fd-ab358c2c454a',
                'error': True,
                'error_key': 'V_NO_ACTIVE_ENGAGEMENT',
                'status': 400
            },
            json=req,
            status_code=400
        )

    @freezegun.freeze_time('2020-01-01')
    def test_edit_leave_in_the_past_fails(self):
        """It shouldn't be possible to perform an edit in the past"""
        self.load_sample_structures()

        leave_uuid = 'b807628c-030c-4f5f-a438-de41c1f26ba5'

        req = [{
            "type": "leave",
            "uuid": leave_uuid,
            "data": {
                "leave_type": {
                    'uuid': "bcd05828-cc10-48b1-bc48-2f0d204859b2"
                },
                "validity": {
                    "from": "2018-01-01",
                },
            },
        }]

        self.assertRequestResponse(
            '/service/details/edit',
            {
                'description': 'Cannot perform changes before current date',
                'error': True,
                'error_key': 'V_CHANGING_THE_PAST',
                'date': '2018-01-01T00:00:00+01:00',
                'status': 400
            },
            json=req,
            status_code=400)

    def test_terminate_leave(self):
        self.load_sample_structures()

        # Check the POST request
        c = lora.Connector(virkningfra='-infinity', virkningtil='infinity')

        userid = "53181ed2-f1de-4c4a-a8fd-ab358c2c454a"

        payload = {
            "validity": {
                "to": "2017-11-30"
            }
        }

        self.assertRequestResponse(
            '/service/e/{}/terminate'.format(userid),
            userid,
            json=payload,
            amqp_topics={
                'employee.address.delete': 1,
                'employee.association.delete': 1,
                'employee.engagement.delete': 1,
                'employee.it.delete': 1,
                'employee.leave.delete': 1,
                'employee.manager.delete': 1,
                'employee.role.delete': 1,
                'org_unit.association.delete': 1,
                'org_unit.engagement.delete': 1,
                'org_unit.manager.delete': 1,
                'org_unit.role.delete': 1,
            },
        )

        expected = {
            "note": "Afsluttet",
            "relationer": {
                "organisatoriskfunktionstype": [
                    {
                        "uuid": "32547559-cfc1-4d97-94c6-70b192eff825",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "infinity"
                        }
                    }
                ],
                "tilknyttedeorganisationer": [
                    {
                        "uuid": "456362c4-0ee4-4e5e-a72c-751239745e62",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "infinity"
                        }
                    }
                ],
                "tilknyttedebrugere": [
                    {
                        "uuid": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "infinity"
                        }
                    }
                ],
            },
            "livscykluskode": "Rettet",
            "tilstande": {
                "organisationfunktiongyldighed": [
                    {
                        "gyldighed": "Aktiv",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "2017-12-01 00:00:00+01"
                        }
                    },
                    {
                        "gyldighed": "Inaktiv",
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-12-01 00:00:00+01",
                            "to": "infinity"
                        }
                    },
                ]
            },
            "attributter": {
                "organisationfunktionegenskaber": [
                    {
                        "virkning": {
                            "from_included": True,
                            "to_included": False,
                            "from": "2017-01-01 00:00:00+01",
                            "to": "infinity"
                        },
                        "brugervendtnoegle": "bvn",
                        "funktionsnavn": "Orlov"
                    }
                ]
            },
        }

        leave_uuid = 'b807628c-030c-4f5f-a438-de41c1f26ba5'

        actual_leave = c.organisationfunktion.get(leave_uuid)

        # drop lora-generated timestamps & users
        del actual_leave['fratidspunkt'], actual_leave[
            'tiltidspunkt'], actual_leave[
            'brugerref']

        self.assertEqual(expected, actual_leave)

    def test_create_leave_missing_user(self):
        self.load_sample_structures()

        # Check the POST request
        unitid = "da77153e-30f3-4dc2-a611-ee912a28d8aa"
        userid = "00000000-0000-0000-0000-000000000000"

        payload = [
            {
                "type": "leave",
                "person": {'uuid': userid},
                "org_unit": {'uuid': unitid},
                "leave_type": {
                    'uuid': "62ec821f-4179-4758-bfdf-134529d186e9"},
                "validity": {
                    "from": "2017-12-01",
                    "to": "2017-12-01",
                },
            }
        ]

        self.assertRequestResponse(
            '/service/details/create',
            {
                'description': 'User not found.',
                'employee_uuid': '00000000-0000-0000-0000-000000000000',
                'error': True,
                'error_key': 'E_USER_NOT_FOUND',
                'status': 404,
            },
            json=payload,
            status_code=404,
        )

    def test_edit_leave_person(self):
        self.load_sample_structures()

        leave_uuid = self.assertRequest(
            '/service/details/create',
            json={
                "type": "leave",
                "uuid": "3be0c325-83db-48cc-9d60-12d80993a3c8",
                "person": {
                    "uuid": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
                },
                "leave_type": {
                    'uuid': "62ec821f-4179-4758-bfdf-134529d186e9",
                },
                "user_key": "1234",
                "validity": {
                    "from": "2017-01-01",
                },
            },
            amqp_topics={'employee.leave.create': 1},
        )

        with self.subTest('failing without any'):
            self.assertRequestFails(
                '/service/details/edit',
                400,
                json={
                    "type": "leave",
                    "uuid": leave_uuid,
                    "data": {
                        "person": {
                            "uuid": "6ee24785-ee9a-4502-81c2-7697009c9053",
                        },
                        "validity": {
                            "from": "2018-01-01",
                        },
                    },
                },
                amqp_topics={'employee.leave.create': 1},
            )

        # first, create an engagement for the other user
        self.assertRequest(
            '/service/details/create',
            json={
                "type": "engagement",
                "uuid": "f1383b2d-d706-4c49-9249-20fa9ef7b55a",
                "person": {'uuid': "6ee24785-ee9a-4502-81c2-7697009c9053"},
                "org_unit": {'uuid': "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e"},
                "job_function": {
                    'uuid': "3ef81e52-0deb-487d-9d0e-a69bbe0277d8"},
                "engagement_type": {
                    'uuid': "62ec821f-4179-4758-bfdf-134529d186e9"},
                "user_key": "1234",
                "validity": {
                    "from": "2018-01-01",
                }
            },
            amqp_topics={
                'employee.leave.create': 1,
                'employee.engagement.create': 1,
                'org_unit.engagement.create': 1,
            },
        )

        with self.subTest('failing too soon'):
            self.assertRequestFails(
                '/service/details/edit',
                400,
                json={
                    "type": "leave",
                    "uuid": leave_uuid,
                    "data": {
                        "person": {
                            "uuid": "6ee24785-ee9a-4502-81c2-7697009c9053",
                        },
                        "validity": {
                            "from": "2017-06-01",
                        },
                    },
                },
                amqp_topics={
                    'employee.leave.create': 1,
                    'employee.engagement.create': 1,
                    'org_unit.engagement.create': 1,
                },
            )

        self.assertRequestResponse(
            '/service/details/edit',
            leave_uuid,
            json={
                "type": "leave",
                "uuid": leave_uuid,
                "data": {
                    "person": {
                        "uuid": "6ee24785-ee9a-4502-81c2-7697009c9053",
                    },
                    "validity": {
                        "from": "2018-06-01",
                    },
                },
            },
            amqp_topics={
                'employee.leave.create': 1,
                'employee.engagement.create': 1,
                'org_unit.engagement.create': 1,
                'employee.leave.update': 1,
            },
        )

        expected_users = [
            {
                "uuid": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
                "virkning": {
                    "from_included": True,
                    "to_included": False,
                    "from": "2017-01-01 00:00:00+01",
                    "to": "2018-06-01 00:00:00+02",
                }
            },
            {
                "uuid": "6ee24785-ee9a-4502-81c2-7697009c9053",
                "virkning": {
                    "from_included": True,
                    "to_included": False,
                    "from": "2018-06-01 00:00:00+02",
                    "to": "infinity"
                }
            }
        ]

        c = lora.Connector(virkningfra='-infinity', virkningtil='infinity')
        actual_leave = c.organisationfunktion.get(leave_uuid)

        self.assertEqual(
            expected_users,
            actual_leave['relationer']['tilknyttedebrugere'],
        )
