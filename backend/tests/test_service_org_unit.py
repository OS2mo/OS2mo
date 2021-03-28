# SPDX-FileCopyrightText: 2018-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0

import freezegun
from mock import call, patch
from os2mo_http_trigger_protocol import MOTriggerRegister
from starlette.datastructures import ImmutableMultiDict

import tests.cases
from mora import lora, mapping
from mora.async_util import async_to_sync
from mora.exceptions import HTTPException
from mora.handler.impl.association import AssociationReader
from mora.request_scoped.query_args import current_query
from mora.service.orgunit import UnitDetails, _get_count_related, get_one_orgunit
from mora.service.orgunit import (
    get_children, get_orgunit, get_unit_ancestor_tree,
)
from mora.triggers import Trigger
from mora.triggers.internal.http_trigger import HTTPTriggerException, register
from tests import util


class TestAddressLookup(tests.cases.TestCase):
    @freezegun.freeze_time("2018-03-15")
    @util.MockAioresponses()
    def test_unit_past(self, mock):
        unitid = "ef04b6ba-8ba7-4a25-95e3-774f38e5d9bc"

        reg = {
            "attributter": {
                "organisationenhedegenskaber": [
                    {
                        "brugervendtnoegle": "IDR\u00c6TSPARK",
                        "enhedsnavn": "Ballerup Idr\u00e6tspark",
                        "virkning": {
                            "from": "1993-01-01 00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ]
            },
            "brugerref": "42c432e8-9c4a-11e6-9f62-873cf34a735f",
            "fratidspunkt": {
                "graenseindikator": True,
                "tidsstempeldatotid": "2018-03-09T14:38:45.310653+01:00",
            },
            "livscykluskode": "Rettet",
            "relationer": {
                "adresser": [
                    {
                        "objekttype": "a8c8fe66-2ab1-46ed-ba99-ed05e855d65f",
                        "uuid": "9ab45e95-a42a-47c0-b284-e5d2377fc429",
                        "virkning": {
                            "from": "1993-01-01 00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    },
                    {
                        "objekttype": "80764a2f-6a7b-492c-92d9-96d24ac845ea",
                        "urn": "urn:mailto:tbri@balk.dk",
                        "virkning": {
                            "from": "1993-01-01 00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    },
                ],
                "enhedstype": [
                    {
                        "uuid": "547e6946-abdb-4dc2-ad99-b6042e05a7e4",
                        "virkning": {
                            "from": "1993-01-01 00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "overordnet": [
                    {
                        "uuid": "9f42976b-93be-4e0b-9a25-0dcb8af2f6b4",
                        "virkning": {
                            "from": "1993-01-01 00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "tilhoerer": [
                    {
                        "uuid": "3a87187c-f25a-40a1-8d42-312b2e2b43bd",
                        "virkning": {
                            "from": "1993-01-01 00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    }
                ],
                "tilknyttedeenheder": [
                    {
                        "virkning": {
                            "from": "1993-01-01 00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        }
                    }
                ],
            },
            "tilstande": {
                "organisationenhedgyldighed": [
                    {
                        "gyldighed": "Aktiv",
                        "virkning": {
                            "from": "1993-01-01 00:00:00+01",
                            "from_included": True,
                            "to": "infinity",
                            "to_included": False,
                        },
                    },
                    {
                        "gyldighed": "Inaktiv",
                        "virkning": {
                            "from": "-infinity",
                            "from_included": True,
                            "to": "1993-01-01 00:00:00+01",
                            "to_included": False,
                        },
                    },
                ]
            },
            "tiltidspunkt": {"tidsstempeldatotid": "infinity"},
        }

        mock.get(
            "http://mox/organisation/organisationenhed"
            "?uuid=" + unitid + "&virkningtil=2018-03-15T00%3A00%3A00%2B01%3A00"
                                "&virkningfra=-infinity"
                                "&konsolider=True",
            payload={
                "results": [
                    [
                        {
                            "id": "ef04b6ba-8ba7-4a25-95e3-774f38e5d9bc",
                            "registreringer": [
                                reg,
                            ],
                        }
                    ]
                ]
            },
        )

        self.assertRequestResponse(
            "/service/ou/" + unitid + "/details/org_unit?validity=past",
            [],
        )


class TestTriggerExternalIntegration(tests.cases.TestCase):
    @patch("mora.service.orgunit.get_one_orgunit")
    def test_returns_404_on_unknown_unit(self, mock):
        mock.return_value = {}

        r = self.assertRequest(
            "/service/ou/44c86c7a-cfe0-447e-9706-33821b5721a4/refresh", status_code=404
        )
        self.assertIn("NOT_FOUND", r.get("error_key"))

    @util.override_config(
        {
            "triggers": {
                "http_trigger": {
                    "enabled": True,
                    "http_endpoints": ["http://whatever"],
                }
            }
        }
    )
    @patch("mora.triggers.internal.http_trigger.fetch_endpoint_trigger")
    @patch("mora.triggers.internal.http_trigger.http_sender")
    @patch("mora.service.orgunit.get_one_orgunit")
    def test_returns_integration_error_on_wrong_status(
        self, mock, t_sender_mock, t_fetch_mock
    ):
        t_fetch_mock.return_value = [
            MOTriggerRegister(
                **{
                    "event_type": mapping.EventType.ON_BEFORE,
                    "request_type": mapping.RequestType.REFRESH,
                    "role_type": "org_unit",
                    "url": "/triggers/ou/refresh",
                }
            )
        ]
        Trigger.registry = {}
        register(None)
        t_fetch_mock.assert_called()

        error_msg = "Something horrible happened"

        def side_effect(trigger_url, trigger_dict, timeout):
            raise HTTPTriggerException(error_msg)

        t_sender_mock.side_effect = side_effect

        mock.return_value = {"whatever": 123}
        r = self.assertRequest(
            "/service/ou/44c86c7a-cfe0-447e-9706-33821b5721a4/refresh", status_code=400
        )
        self.assertIn("INTEGRATION_ERROR", r.get("error_key"))
        self.assertIn(error_msg, r.get("description"))

        t_sender_mock.assert_called_with(
            "http://whatever/triggers/ou/refresh",
            {
                "request_type": mapping.RequestType.REFRESH,
                "request": {"uuid": "44c86c7a-cfe0-447e-9706-33821b5721a4"},
                "role_type": "org_unit",
                "event_type": mapping.EventType.ON_BEFORE,
                "org_unit_uuid": "44c86c7a-cfe0-447e-9706-33821b5721a4",
                "uuid": "44c86c7a-cfe0-447e-9706-33821b5721a4",
            },
            timeout=5,
        )

    @util.override_config(
        {
            "triggers": {
                "http_trigger": {
                    "enabled": True,
                    "http_endpoints": ["http://whatever"],
                }
            }
        }
    )
    @patch("mora.triggers.internal.http_trigger.fetch_endpoint_trigger")
    @patch(
        "mora.triggers.internal.http_trigger.http_sender", new_callable=util.CopyingMock
    )
    @patch("mora.service.orgunit.get_one_orgunit")
    def test_returns_message_on_success(self, mock, t_sender_mock, t_fetch_mock):
        t_fetch_mock.return_value = [
            MOTriggerRegister(
                **{
                    "event_type": mapping.EventType.ON_BEFORE,
                    "request_type": mapping.RequestType.REFRESH,
                    "role_type": "org_unit",
                    "url": "/triggers/ou/refresh",
                }
            )
        ]
        Trigger.registry = {}
        register(None)
        t_fetch_mock.assert_called()
        response_msg = "Something good happened"
        t_sender_mock.return_value = response_msg

        mock.return_value = {"whatever": 123}
        r = self.assertRequest(
            "/service/ou/44c86c7a-cfe0-447e-9706-33821b5721a4/refresh"
        )
        self.assertEqual(response_msg, r["message"])

        t_sender_mock.assert_has_calls(
            [
                call(
                    "http://whatever/triggers/ou/refresh",
                    {
                        "request_type": mapping.RequestType.REFRESH,
                        "request": {"uuid": "44c86c7a-cfe0-447e-9706-33821b5721a4"},
                        "role_type": "org_unit",
                        "event_type": mapping.EventType.ON_BEFORE,  # WHAT THE FUCK
                        "org_unit_uuid": "44c86c7a-cfe0-447e-9706-33821b5721a4",
                        "uuid": "44c86c7a-cfe0-447e-9706-33821b5721a4",
                    },
                    timeout=5,
                )
            ]
        )


class TestGetOneOrgUnit(tests.cases.LoRATestCase):
    def setUp(self):
        self.load_sample_structures(minimal=True)
        self._connector = lora.Connector(
            virkningfra="-infinity", virkningtil="infinity"
        )
        self._orgunit_uuid = "2874e1dc-85e6-4269-823a-e1125484dfd3"

    def test_details_nchildren(self):
        self._assert_orgunit_keys(
            {"uuid", "name", "user_key", "validity", "child_count"},
            details=UnitDetails.NCHILDREN,
        )

    def test_details_path(self):
        self._assert_orgunit_keys(
            {"uuid", "name", "user_key", "validity", "location"},
            details=UnitDetails.PATH,
        )

    def test_get_one_orgunit_with_association_count(self):
        result = async_to_sync(get_one_orgunit)(
            self._connector,
            self._orgunit_uuid,
            count_related={"association": AssociationReader},
        )
        self.assertIn("association_count", result)

    def _assert_orgunit_keys(self, expected_keys, **kwargs):
        orgunit = async_to_sync(get_one_orgunit)(
            self._connector, self._orgunit_uuid, **kwargs
        )
        self.assertSetEqual(set(orgunit.keys()), expected_keys)


class TestGetCountRelated(tests.cases.TestCase):
    def setUp(self):
        super().setUp()
        self._simple = {"association"}
        self._multiple = {"association", "engagement"}

    def test_valid_name(self):
        with current_query.temporary_args(ImmutableMultiDict({'count': 'association'})):
            self.assertSetEqual(self._simple, _get_count_related())

    def test_valid_name_repeated(self):
        with current_query.temporary_args(
            ImmutableMultiDict([('count', 'association'), ('count', 'association')])
        ):
            self.assertSetEqual(self._simple, _get_count_related())

    def test_multiple_valid_names(self):
        with current_query.temporary_args(
            ImmutableMultiDict([('count', 'association'), ('count', 'engagement')])
        ):
            self.assertSetEqual(self._multiple, _get_count_related())

    def test_invalid_name(self):
        with current_query.temporary_args(
            ImmutableMultiDict([('count', 'association'), ('count', 'foobar')])
        ):
            with self.assertRaises(HTTPException):
                _get_count_related()


class TestGetOrgUnit(util.ConfigTestCase):
    def setUp(self):
        super().setUp()
        self.load_sample_structures()
        # The OU "Humanistisk Fakultet" has 3 engagements and 1 association.
        self._orgunit_uuid = "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e"

    def test_count_association(self):
        with self.app.test_request_context("?count=association"):
            result = get_orgunit(self._orgunit_uuid)
            self.assertEqual(result.json["association_count"], 1)

    def test_count_engagement(self):
        with self.app.test_request_context("?count=engagement"):
            result = get_orgunit(self._orgunit_uuid)
            self.assertEqual(result.json["engagement_count"], 3)


class TestGetChildren(util.ConfigTestCase):
    def setUp(self):
        super().setUp()
        self.load_sample_structures()
        self._connector = lora.Connector(
            virkningfra="-infinity", virkningtil="infinity"
        )
        # The OU "Humanistisk Fakultet" has 3 engagements and 1 association.
        # We need the UUID of a *parent* OU to test `get_children`.
        # Below is the UUID of "Overordnet Enhed".
        self._orgunit_uuid = "2874e1dc-85e6-4269-823a-e1125484dfd3"

    def test_count_association(self):
        with self.app.test_request_context("?count=association"):
            result = get_children("ou", self._orgunit_uuid)
            self._assert_matching_ou_has(
                result.json,
                user_key="hum",
                association_count=1,
            )

    def test_count_engagement(self):
        with self.app.test_request_context("?count=engagement"):
            result = get_children("ou", self._orgunit_uuid)
            self._assert_matching_ou_has(
                result.json,
                user_key="hum",
                engagement_count=3,
            )

    def _assert_matching_ou_has(self, doc, user_key=None, **attrs):
        for node in doc:
            if node.get("user_key") == user_key:
                for attr_name, attr_value in attrs.items():
                    self.assertEqual(node.get(attr_name), attr_value)


class TestGetUnitAncestorTree(util.ConfigTestCase):
    def setUp(self):
        super().setUp()
        self.load_sample_structures()
        self._connector = lora.Connector(
            virkningfra="-infinity", virkningtil="infinity"
        )
        # The OU "Humanistisk Fakultet" has 3 engagements and 1 association.
        # We need the UUID of a *child* OU to test `get_unit_ancestor_tree`.
        # Below is the UUID of "Filosofisk Institut".
        self._orgunit_uuid = "85715fc7-925d-401b-822d-467eb4b163b6"

    def test_count_association(self):
        query = f"?uuid={self._orgunit_uuid}&count=association"
        with self.app.test_request_context(query):
            result = get_unit_ancestor_tree()
            self._assert_matching_ou_has(
                result.json,
                user_key="hum",
                association_count=1,
            )

    def test_count_engagement(self):
        query = f"?uuid={self._orgunit_uuid}&count=engagement"
        with self.app.test_request_context(query):
            result = get_unit_ancestor_tree()
            self._assert_matching_ou_has(
                result.json,
                user_key="hum",
                engagement_count=3,
            )

    def _assert_matching_ou_has(self, doc, user_key=None, **attrs):
        # Recurse into `doc` until we find a dictionary whose `user_key` equals
        # `user_key`. Then, assert that each key-value pair in `attrs` is
        # present in the matching dict, and has the expected value.
        def visit(node):
            if isinstance(node, list):
                for ou in node:
                    visit(ou)
            elif isinstance(node, dict):
                if "children" in node:
                    for ou in node["children"]:
                        visit(ou)
                if node.get("user_key") == user_key:
                    for attr_name, attr_value in attrs.items():
                        self.assertEqual(node.get(attr_name), attr_value)

        visit(doc)
