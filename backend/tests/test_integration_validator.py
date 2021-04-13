# SPDX-FileCopyrightText: 2017-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0

import datetime

from mock import patch

import mora.async_util
import tests.cases
from mora import exceptions
from mora import mapping
from mora import util as mora_util
from mora.service.validation import validator


class TestHelper(tests.cases.LoRATestCase):
    maxDiff = None
    ORG = '456362c4-0ee4-4e5e-a72c-751239745e62'
    SAMF_UNIT = 'b688513d-11f7-4efc-b679-ab082a2055d0'
    HIST_UNIT = 'da77153e-30f3-4dc2-a611-ee912a28d8aa'
    PARENT = SAMF_UNIT

    def setUp(self):
        super().setUp()
        self.load_sample_structures()

    def expire_org_unit(self, org_unit):
        # Expire the parent from 2018-01-01
        payload = {
            'validity': {
                'to': "2018-01-01"
            }
        }

        self.assertRequestResponse(
            '/service/ou/{}/terminate'.format(org_unit),
            org_unit,
            json=payload,
            amqp_topics={'org_unit.org_unit.delete': 1},
        )


class TestValidator(TestHelper):
    def test_should_return_true_when_interval_contained(self):
        """
        [------ super ------)
           [--- sub ---)
        """
        self.expire_org_unit(self.PARENT)

        startdate = '01-02-2017'
        enddate = '01-06-2017'

        mora.async_util.async_to_sync(validator.is_date_range_in_org_unit_range)(
            {
                'uuid': self.PARENT
            },
            mora_util.parsedatetime(startdate),
            mora_util.parsedatetime(enddate)
        )

    def test_should_return_true_when_interval_contained2(self):
        """
        [------ super ------)
        [------ sub ---)
        """
        self.expire_org_unit(self.PARENT)

        startdate = '01-01-2017'
        enddate = '01-06-2017'

        mora.async_util.async_to_sync(validator.is_date_range_in_org_unit_range)(
            {
                'uuid': self.PARENT
            },
            mora_util.parsedatetime(startdate),
            mora_util.parsedatetime(enddate)
        )

    def test_should_return_true_when_interval_contained3(self):
        """
        [------ super ------)
          [------ sub ------)
        """
        self.expire_org_unit(self.PARENT)

        startdate = '01-02-2017'
        enddate = '01-01-2018'

        mora.async_util.async_to_sync(validator.is_date_range_in_org_unit_range)(
            {
                'uuid': self.PARENT
            },
            mora_util.parsedatetime(startdate),
            mora_util.parsedatetime(enddate)
        )

    def test_should_false_true_when_interval_not_contained1(self):
        """
          [---- super ------)
        [------ sub ---)
        """
        self.expire_org_unit(self.PARENT)

        startdate = '01-01-2016'
        enddate = '01-06-2017'

        with self.assertRaises(exceptions.HTTPException):
            mora.async_util.async_to_sync(validator.is_date_range_in_org_unit_range)(
                {
                    'uuid': self.PARENT
                },
                mora_util.parsedatetime(startdate),
                mora_util.parsedatetime(enddate)
            )

    def test_should_return_false_when_interval_not_contained2(self):
        """
        [------ super ------)
          [---- sub -----------)
        """
        self.expire_org_unit(self.PARENT)

        startdate = '01-02-2017'
        enddate = '01-06-2019'

        with self.assertRaises(exceptions.HTTPException):
            mora.async_util.async_to_sync(validator.is_date_range_in_org_unit_range)(
                {
                    'uuid': self.PARENT
                },
                mora_util.parsedatetime(startdate),
                mora_util.parsedatetime(enddate)
            )

    def test_should_return_false_when_interval_not_contained3(self):
        """
                                   [------ super ------)
        [---- sub -----------)
        """
        self.expire_org_unit(self.PARENT)

        startdate = '01-02-2010'
        enddate = '01-06-2015'

        with self.assertRaises(exceptions.HTTPException):
            mora.async_util.async_to_sync(validator.is_date_range_in_org_unit_range)(
                {
                    'uuid': self.PARENT
                },
                mora_util.parsedatetime(startdate),
                mora_util.parsedatetime(enddate)
            )

    def test_is_date_range_in_employee_valid_raises_outside_range(self):
        """Assert that a validation error is raised when the range exceeds
        employee range """

        # Arrange
        self.load_sample_structures()
        employee_uuid = '53181ed2-f1de-4c4a-a8fd-ab358c2c454a'  # Anders And
        valid_from = mora_util.parsedatetime("1910-01-01")
        valid_to = mora_util.parsedatetime("2040-01-01")
        employee = {
            'uuid': employee_uuid
        }

        # Act & Assert
        with self.assertRaises(exceptions.HTTPException):
            mora.async_util.async_to_sync(validator.is_date_range_in_employee_range)(
                employee, valid_from, valid_to)

    def test_is_date_range_in_employee_valid_inside_range(self):
        """Assert that a validation error is not raised when the range is
        inside employee range"""

        # Arrange
        self.load_sample_structures()
        employee_uuid = '53181ed2-f1de-4c4a-a8fd-ab358c2c454a'  # Anders And
        valid_from = mora_util.parsedatetime("2020-01-01")
        valid_to = mora_util.parsedatetime("2040-01-01")
        employee = {
            'uuid': employee_uuid
        }

        # Act & Assert
        # Should be callable without raising exception
        mora.async_util.async_to_sync(validator.is_date_range_in_employee_range)(
            employee,
            valid_from, valid_to)

    def test_is_distinct_responsibility_with_duplicate(self):
        with self.assertRaises(exceptions.HTTPException) as ctxt:
            validator.is_distinct_responsibility([
                (
                    mapping.RESPONSIBILITY_FIELD,
                    {
                        'objekttype': 'lederansvar',
                        'uuid': '00000000-0000-0000-0000-000000000000',
                    },
                ),
                (
                    mapping.RESPONSIBILITY_FIELD,
                    {
                        'objekttype': 'lederansvar',
                        'uuid': '00000000-0000-0000-0000-000000000000',
                    },
                ),
                (
                    mapping.RESPONSIBILITY_FIELD,
                    {
                        'objekttype': 'lederansvar',
                        'uuid': '00000000-0000-0000-0000-000000000001',
                    },
                ),
            ])

        self.assertEqual(
            ctxt.exception.detail,
            {
                'description': 'Manager has the same responsibility more than '
                               'once.',
                'duplicates': [
                    '00000000-0000-0000-0000-000000000000',
                ],
                'error': True,
                'error_key': 'V_DUPLICATED_RESPONSIBILITY',
                'status': 400,
            },
        )

    def test_is_distinct_responsibility_no_duplicate(self):
        validator.is_distinct_responsibility([
            (
                mapping.RESPONSIBILITY_FIELD,
                {
                    'objekttype': 'lederansvar',
                    'uuid': '00000000-0000-0000-0000-000000000000',
                },
            ),
            (
                mapping.RESPONSIBILITY_FIELD,
                {
                    'objekttype': 'lederansvar',
                    'uuid': '00000000-0000-0000-0000-000000000001',
                },
            ),
            (
                mapping.MANAGER_LEVEL_FIELD,
                {
                    'objekttype': 'hestefest',
                    'uuid': '00000000-0000-0000-0000-000000000001',
                },
            ),
        ])

    @patch(
        "mora.conf_db.get_configuration",
        return_value={"substitute_roles": 'bcd05828-cc10-48b1-bc48-2f0d204859b2'}
    )
    def test_is_substitute_allowed(self, mock):
        # This should pass
        validator.is_substitute_allowed("bcd05828-cc10-48b1-bc48-2f0d204859b2")

        # This shouldn't
        with self.assertRaises(exceptions.HTTPException):
            validator.is_substitute_allowed("8b073375-4196-4d90-9af9-0eb6ef8b6d0d")

    def test_is_substitute_self(self):
        # This should pass
        validator.is_substitute_self(
            "32eba675-1edb-4c08-8d1a-82caf948aae6",
            "962f70a7-4cb0-47f8-b949-ec249c595936"
        )

        # This shouldn't
        with self.assertRaises(exceptions.HTTPException):
            validator.is_substitute_self(
                "8b073375-4196-4d90-9af9-0eb6ef8b6d0d",
                "8b073375-4196-4d90-9af9-0eb6ef8b6d0d"
            )


class TestIntegrationMoveOrgUnitValidator(TestHelper):
    UNIT_TO_MOVE = '9d07123e-47ac-4a9a-88c8-da82e3a4bc9e'  # Hum

    def setUp(self):
        super().setUp()

    def test_cannot_move_unit_to_own_subtree(self):
        candidate_parent = '04c78fc2-72d2-4d02-b55f-807af19eac48'  # Frem

        move_date = '01-02-2017'
        new_org_uuid = candidate_parent

        with self.assertRaises(exceptions.HTTPException):
            mora.async_util.async_to_sync(validator.is_candidate_parent_valid)(
                self.UNIT_TO_MOVE, new_org_uuid, move_date
            )

    def test_should_allow_move_unit_to_valid_orgtree_location(self):
        candidate_parent = 'b688513d-11f7-4efc-b679-ab082a2055d0'  # Samf

        move_date = '01-02-2017'
        new_org_uuid = candidate_parent

        # Should not raise
        mora.async_util.async_to_sync(validator.is_candidate_parent_valid)(
            self.UNIT_TO_MOVE, new_org_uuid, move_date
        )

    def test_should_not_move_root_org_unit(self):
        root_org_unit = '2874e1dc-85e6-4269-823a-e1125484dfd3'
        candidate_parent = 'b688513d-11f7-4efc-b679-ab082a2055d0'  # Samf

        move_date = '01-02-2017'
        new_org_uuid = candidate_parent

        with self.assertRaises(exceptions.HTTPException):
            mora.async_util.async_to_sync(validator.is_candidate_parent_valid)(
                root_org_unit, new_org_uuid, move_date
            )

    def test_should_not_move_org_unit_to_child(self):
        candidate_parent = '85715fc7-925d-401b-822d-467eb4b163b6'  # Fil

        move_date = '01-02-2017'
        new_org_uuid = candidate_parent

        with self.assertRaises(exceptions.HTTPException):
            mora.async_util.async_to_sync(validator.is_candidate_parent_valid)(
                self.UNIT_TO_MOVE, new_org_uuid, move_date
            )

    def test_should_not_move_org_unit_to_itself(self):
        move_date = '01-02-2017'

        with self.assertRaises(exceptions.HTTPException):
            mora.async_util.async_to_sync(validator.is_candidate_parent_valid)(
                self.UNIT_TO_MOVE, self.UNIT_TO_MOVE, move_date
            )

    def test_should_return_false_when_candidate_parent_is_inactive(self):
        move_date = '01-01-2019'
        new_org_uuid = self.PARENT

        self.expire_org_unit(self.PARENT)

        with self.assertRaises(exceptions.HTTPException):
            mora.async_util.async_to_sync(validator.is_candidate_parent_valid)(
                self.UNIT_TO_MOVE, new_org_uuid, move_date
            )


class TestIsContainedInRange(TestHelper):

    def test_raises_when_outside_range_upper(self):
        empl_from = datetime.date(2010, 1, 1)
        empl_to = datetime.date(2018, 1, 1)

        valid_from = datetime.date(2012, 1, 1)
        valid_to = datetime.date(2020, 1, 1)

        with self.assertRaises(exceptions.HTTPException):
            validator.is_contained_in_range(
                empl_from, empl_to,
                valid_from, valid_to,
                exceptions.ErrorCodes.V_DATE_OUTSIDE_EMPL_RANGE)

    def test_raises_when_outside_range_lower(self):
        empl_from = datetime.date(2010, 1, 1)
        empl_to = datetime.date(2018, 1, 1)

        valid_from = datetime.date(2008, 1, 1)
        valid_to = datetime.date(2016, 1, 1)

        with self.assertRaises(exceptions.HTTPException):
            validator.is_contained_in_range(
                empl_from, empl_to,
                valid_from, valid_to,
                exceptions.ErrorCodes.V_DATE_OUTSIDE_EMPL_RANGE)

    def test_passes_when_inside_range(self):
        empl_from = datetime.date(2010, 1, 1)
        empl_to = datetime.date(2018, 1, 1)

        valid_from = datetime.date(2010, 1, 1)
        valid_to = datetime.date(2018, 1, 1)

        # Should not raise an exception
        validator.is_contained_in_range(
            empl_from, empl_to,
            valid_from, valid_to,
            exceptions.ErrorCodes.V_DATE_OUTSIDE_EMPL_RANGE)
