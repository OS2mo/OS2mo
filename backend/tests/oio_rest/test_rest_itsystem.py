# SPDX-FileCopyrightText: 2018-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0
from oio_rest.utils import is_uuid
from tests.oio_rest import util
from tests.oio_rest.util import DBTestCase


class TestItSystem(DBTestCase):
    def test_it_system(self):
        result = self.client.post(
            "organisation/itsystem",
            data={
                "json": util.get_fixture("itsystem_opret.json", as_text=False),
            },
        )
        self.assertEqual(result.status_code, 201)
        uuid_ = result.json()["uuid"]
        self.assertTrue(is_uuid(uuid_))
