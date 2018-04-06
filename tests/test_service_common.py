#
# Copyright (c) 2017-2018, Magenta ApS
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

import datetime

from unittest import TestCase

import dateutil

from mora import util
from mora.service import common


class TestClass(TestCase):
    maxDiff = None

    def test_get_obj_path(self):
        # Arrange
        obj = {
            'whatever': 'no',
            'test1': {
                'garbage': 'there is some stuff here already',
                'test2': ['something']
            }
        }

        path = ('test1', 'test2')

        expected_props = ['something']

        # Act
        actual_props = common.get_obj_value(obj, path)

        # Assert
        self.assertEqual(expected_props, actual_props)

    def test_get_obj_path_missing(self):
        # Arrange
        obj = {
            'whatever': 'no',
            'test1': None,
        }

        path = ('test1', 'test2')

        expected_props = None

        # Act
        actual_props = common.get_obj_value(obj, path)

        # Assert
        self.assertEqual(expected_props, actual_props)

    def test_update_payload_complex(self):
        # Arrange
        fields = [
            (
                common.FieldTuple(
                    ('test1', 'prop1'),
                    common.FieldTypes.ADAPTED_ZERO_TO_MANY,
                    lambda x: True,
                ),
                {
                    'uuid': '8525d022-e939-4d16-8378-2e46101a3a47',
                }
            ),
            (
                common.FieldTuple(
                    ('test1', 'prop2'),
                    common.FieldTypes.ZERO_TO_MANY,
                    lambda x: True,
                ),
                {
                    'uuid': '6995b5db-5e66-4479-82d8-67045663eb79',
                }
            ),
            (
                common.FieldTuple(
                    ('test2', 'prop3'),
                    common.FieldTypes.ZERO_TO_ONE,
                    lambda x: True,
                ),
                {
                    'uuid': '3251f325-a36f-4879-a150-2775cdc1b0fb',
                }
            )
        ]

        original = {
            'test1': {
                'prop1': [
                    {
                        'uuid': '1ebd2f10-df7b-42ca-93d9-3078a174c3f6',
                        'virkning': {
                            'from': '2016-01-01T00:00:00+00:00',
                            'to': '2018-01-01T00:00:00+00:00'
                        }
                    },
                    {
                        'uuid': '6563c93d-48da-4375-a106-b05343f97915',
                        'virkning': {
                            'from': '2018-01-01T00:00:00+00:00',
                            'to': '2020-01-01T00:00:00+00:00'
                        }
                    },
                ],
                'prop2': [
                    {
                        'uuid': 'eb936cf5-e72b-4aa9-9bd2-f773c462fa50',
                        'virkning': {
                            'from': '2016-01-01T00:00:00+00:00',
                            'to': '2020-01-01T00:00:00+00:00'
                        }
                    }
                ]
            },
            'test2': {
                'prop3': [
                    {
                        'uuid': 'ab9c5351-6448-4b6e-be02-eb3c16960884',
                        'virkning': {
                            'from': '2016-01-01T00:00:00+00:00',
                            'to': '2020-01-01T00:00:00+00:00'
                        }
                    }
                ]
            },
            'test3': {
                'prop4': [
                    {
                        'uuid': 'ab9c5351-6448-4b6e-be02-eb3c16960884',
                        'virkning': {
                            'from': '2016-01-01T00:00:00+00:00',
                            'to': '2020-01-01T00:00:00+00:00'
                        }
                    }
                ]
            }
        }

        expected_payload = {
            'test1': {
                'prop1': [
                    {
                        'uuid': '1ebd2f10-df7b-42ca-93d9-3078a174c3f6',
                        'virkning': {
                            'from': '2016-01-01T00:00:00+00:00',
                            'to': '2017-01-01T00:00:00+00:00'
                        }
                    },
                    {
                        'uuid': '8525d022-e939-4d16-8378-2e46101a3a47',
                        'virkning': {
                            'from': '2017-01-01T00:00:00+00:00',
                            'to': '2021-01-01T00:00:00+00:00'
                        }
                    }
                ],
                'prop2': [
                    {
                        'uuid': 'eb936cf5-e72b-4aa9-9bd2-f773c462fa50',
                        'virkning': {
                            'from': '2016-01-01T00:00:00+00:00',
                            'to': '2020-01-01T00:00:00+00:00'
                        }
                    },
                    {
                        'uuid': '6995b5db-5e66-4479-82d8-67045663eb79',
                        'virkning': {
                            'from': '2017-01-01T00:00:00+00:00',
                            'to': '2021-01-01T00:00:00+00:00'
                        }
                    }
                ]
            },
            'test2': {
                'prop3': [
                    {
                        'uuid': '3251f325-a36f-4879-a150-2775cdc1b0fb',
                        'virkning': {
                            'from': '2017-01-01T00:00:00+00:00',
                            'to': '2021-01-01T00:00:00+00:00'
                        }
                    }
                ]
            }
        }

        # Act
        actual_payload = common.update_payload(
            '2017-01-01T00:00:00+00:00',
            '2021-01-01T00:00:00+00:00',
            fields,
            original,
            {}
        )

        # Assert
        self.assertEqual(expected_payload, actual_payload)

    def test_inactivates_correctly_when_diminishing_bounds(self):
        # Arrange
        old_from = '2013-01-01T00:00:00+00:00'
        old_to = '2016-01-01T00:00:00+00:00'
        new_from = '2014-01-01T00:00:00+00:00'
        new_to = '2015-01-01T00:00:00+00:00'
        payload = {
            'whatever': ['Should remain untouched'],
            'note': 'NOTE'
        }
        path = ('hest', 'hestgyldighed')

        expected_result = {
            'whatever': ['Should remain untouched'],
            'hest': {
                'hestgyldighed': [
                    {
                        'gyldighed': 'Inaktiv',
                        'virkning': {
                            'from': '2013-01-01T00:00:00+00:00',
                            'to': '2014-01-01T00:00:00+00:00',
                        }
                    },
                    {
                        'gyldighed': 'Inaktiv',
                        'virkning': {
                            'from': '2015-01-01T00:00:00+00:00',
                            'to': '2016-01-01T00:00:00+00:00',
                        }
                    }
                ]
            },
            'note': 'NOTE'
        }

        # Act
        actual_result = common.inactivate_old_interval(
            old_from, old_to, new_from, new_to, payload, path,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_does_not_inactivate_when_expanding_bounds(self):
        # Arrange
        old_from = '2014-01-01T00:00:00+00:00'
        old_to = '2015-01-01T00:00:00+00:00'
        new_from = '2013-01-01T00:00:00+00:00'
        new_to = '2016-01-01T00:00:00+00:00'
        payload = {
            'whatever': ['Should remain untouched'],
            'note': 'NOTE'
        }
        path = ('hest', 'hestgyldighed')

        expected_result = {
            'whatever': ['Should remain untouched'],
            'note': 'NOTE'
        }

        # Act
        actual_result = common.inactivate_old_interval(
            old_from, old_to, new_from, new_to, payload, path,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_does_not_inactivate_when_bounds_do_not_move(self):
        # Arrange
        old_from = '2014-01-01T00:00:00+00:00'
        old_to = '2015-01-01T00:00:00+00:00'
        new_from = '2014-01-01T00:00:00+00:00'
        new_to = '2015-01-01T00:00:00+00:00'
        payload = {
            'whatever': ['Should remain untouched'],
            'note': 'NOTE'
        }
        path = ('hest', 'hestgyldighed')

        expected_result = {
            'whatever': ['Should remain untouched'],
            'note': 'NOTE'
        }

        # Act
        actual_result = common.inactivate_old_interval(
            old_from, old_to, new_from, new_to, payload, path,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_aztm_times_are_inside_bounds(self):
        # Arrange
        new_from = util.parsedatetime('2013-01-01T00:00:00+00:00')
        new_to = util.parsedatetime('2015-01-01T00:00:00+00:00')

        original = {
            'test1': {
                'test2': [
                    {
                        'uuid': 'HEJ2',
                        'virkning': {
                            'from': '2013-01-01T00:00:00+00:00',
                            'to': '2014-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ1',
                        'virkning': {
                            'from': '2012-01-01T00:00:00+00:00',
                            'to': '2013-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ3',
                        'virkning': {
                            'from': '2014-01-01T00:00:00+00:00',
                            'to': '2015-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                ]
            }
        }

        payload = {
            'whatever': ['I should remain untouched, please'],
            'test1': {
                'no': ['Me too']
            },
            'note': 'NOTE'
        }
        paths = [
            common.FieldTuple(
                ('test1', 'test2'),
                common.FieldTypes.ADAPTED_ZERO_TO_MANY,
                lambda x: x
            )
        ]

        expected_result = {
            'whatever': ['I should remain untouched, please'],
            'test1': {
                'no': ['Me too']
            },
            'note': 'NOTE'
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from, new_to, paths, original,
            payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_aztm_expanding_from_time(self):
        # Arrange
        new_from = util.parsedatetime('2010-01-01T00:00:00+00:00')
        new_to = util.parsedatetime('2014-01-01T00:00:00+00:00')

        original = {
            'test1': {
                'test2': [
                    {
                        'uuid': 'HEJ2',
                        'virkning': {
                            'from': '2013-01-01T00:00:00+00:00',
                            'to': '2014-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ1',
                        'virkning': {
                            'from': '2012-01-01T00:00:00+00:00',
                            'to': '2013-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ3',
                        'virkning': {
                            'from': '2014-01-01T00:00:00+00:00',
                            'to': '2015-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                ]
            }
        }

        payload = {
            'whatever': ['I should remain untouched, please'],
            'test1': {
                'no': ['Me too']
            },
            'note': 'NOTE'
        }

        paths = [
            common.FieldTuple(
                ('test1', 'test2'),
                common.FieldTypes.ADAPTED_ZERO_TO_MANY,
                lambda x: x
            )
        ]

        expected_result = {
            'note': 'NOTE',
            'test1': {'no': ['Me too'],
                      'test2': [{'uuid': 'HEJ1',
                                 'virkning': {
                                     'from': '2010-01-01T00:00:00+00:00',
                                     'from_included': True,
                                     'to': '2013-01-01T00:00:00+00:00',
                                     'to_included': False}},
                                {'uuid': 'HEJ2',
                                 'virkning': {
                                     'from': '2013-01-01T00:00:00+00:00',
                                     'from_included': True,
                                     'to': '2014-01-01T00:00:00+00:00',
                                     'to_included': False}},
                                {'uuid': 'HEJ3',
                                 'virkning': {
                                     'from': '2014-01-01T00:00:00+00:00',
                                     'from_included': True,
                                     'to': '2015-01-01T00:00:00+00:00',
                                     'to_included': False}}]},
            'whatever': ['I should remain untouched, please']}

        # Act
        actual_result = common.ensure_bounds(
            new_from, new_to, paths, original, payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_aztm_diminishing_from_time(self):
        # Arrange
        new_from = util.parsedatetime('2012-07-01T00:00:00+00:00')
        new_to = util.parsedatetime('2015-01-01T00:00:00+00:00')

        original = {
            'test1': {
                'test2': [
                    {
                        'uuid': 'HEJ2',
                        'virkning': {
                            'from': '2013-01-01T00:00:00+00:00',
                            'to': '2014-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ1',
                        'virkning': {
                            'from': '2012-01-01T00:00:00+00:00',
                            'to': '2013-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ3',
                        'virkning': {
                            'from': '2014-01-01T00:00:00+00:00',
                            'to': '2015-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                ]
            }
        }

        payload = {
            'whatever': ['I should remain untouched, please'],
            'test1': {
                'no': ['Me too']
            },
            'note': 'NOTE'
        }

        paths = [
            common.FieldTuple(
                ('test1', 'test2'),
                common.FieldTypes.ADAPTED_ZERO_TO_MANY,
                lambda x: x
            )
        ]

        expected_result = {
            'whatever': ['I should remain untouched, please'],
            'note': 'NOTE',
            'test1': {
                'no': [
                    'Me too'
                ]
            }
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from, new_to, paths, original,
            payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_aztm_expanding_to_time(self):
        # Arrange
        new_from = util.parsedatetime('2012-01-01T00:00:00+00:00')
        new_to = util.parsedatetime('2017-01-01T00:00:00+00:00')

        original = {
            'test1': {
                'test2': [
                    {
                        'uuid': 'HEJ2',
                        'virkning': {
                            'from': '2013-01-01T00:00:00+00:00',
                            'to': '2014-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ1',
                        'virkning': {
                            'from': '2012-01-01T00:00:00+00:00',
                            'to': '2013-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ3',
                        'virkning': {
                            'from': '2014-01-01T00:00:00+00:00',
                            'to': '2015-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                ]
            }
        }

        payload = {
            'whatever': ['I should remain untouched, please'],
            'test1': {
                'no': ['Me too']
            },
            'note': 'NOTE'
        }

        paths = [
            common.FieldTuple(
                ('test1', 'test2'),
                common.FieldTypes.ADAPTED_ZERO_TO_MANY,
                lambda x: x
            )
        ]

        expected_result = {
            'note': 'NOTE',
            'test1': {'no': ['Me too'],
                      'test2': [{'uuid': 'HEJ1',
                                 'virkning': {
                                     'from': '2012-01-01T00:00:00+00:00',
                                     'from_included': True,
                                     'to': '2013-01-01T00:00:00+00:00',
                                     'to_included': False}},
                                {'uuid': 'HEJ2',
                                 'virkning': {
                                     'from': '2013-01-01T00:00:00+00:00',
                                     'from_included': True,
                                     'to': '2014-01-01T00:00:00+00:00',
                                     'to_included': False}},
                                {'uuid': 'HEJ3',
                                 'virkning': {
                                     'from': '2014-01-01T00:00:00+00:00',
                                     'from_included': True,
                                     'to': '2017-01-01T00:00:00+00:00',
                                     'to_included': False}}]},
            'whatever': ['I should remain untouched, please']}

        # Act
        actual_result = common.ensure_bounds(
            new_from, new_to, paths, original, payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_aztm_diminishing_to_time(self):
        # Arrange
        new_from = util.parsedatetime('2012-01-01T00:00:00+00:00')
        new_to = util.parsedatetime('2014-07-01T00:00:00+00:00')

        original = {
            'test1': {
                'test2': [
                    {
                        'uuid': 'HEJ2',
                        'virkning': {
                            'from': '2013-01-01T00:00:00+00:00',
                            'to': '2014-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ1',
                        'virkning': {
                            'from': '2012-01-01T00:00:00+00:00',
                            'to': '2013-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ3',
                        'virkning': {
                            'from': '2014-01-01T00:00:00+00:00',
                            'to': '2015-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                ]
            }
        }

        payload = {
            'whatever': ['I should remain untouched, please'],
            'test1': {
                'no': ['Me too']
            },
            'note': 'NOTE'
        }

        paths = [
            common.FieldTuple(
                ('test1', 'test2'),
                common.FieldTypes.ADAPTED_ZERO_TO_MANY,
                lambda x: x
            )
        ]

        expected_result = {
            'whatever': ['I should remain untouched, please'],
            'note': 'NOTE',
            'test1': {
                'no': [
                    'Me too'
                ]
            }
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from, new_to, paths, original,
            payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_ztm(self):
        # Arrange
        new_from = util.parsedatetime('2000-01-01T00:00:00+00:00')
        new_to = util.parsedatetime('2020-07-01T00:00:00+00:00')

        original = {
            'test1': {
                'test2': [
                    {
                        'uuid': 'HEJ2',
                        'virkning': {
                            'from': '2013-01-01T00:00:00+00:00',
                            'to': '2014-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ1',
                        'virkning': {
                            'from': '2012-01-01T00:00:00+00:00',
                            'to': '2013-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ3',
                        'virkning': {
                            'from': '2014-01-01T00:00:00+00:00',
                            'to': '2015-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                ]
            }
        }

        payload = {
            'whatever': ['I should remain untouched, please'],
            'test1': {
                'no': ['Me too'],
            },
            'note': 'NOTE'
        }

        paths = [
            common.FieldTuple(
                ('test1', 'test2'),
                common.FieldTypes.ZERO_TO_MANY,
                lambda x: x
            )
        ]

        expected_result = {
            'whatever': ['I should remain untouched, please'],
            'note': 'NOTE',
            'test1': {
                'no': [
                    'Me too'
                ],
                'test2': [
                    {
                        'uuid': 'HEJ2',
                        'virkning': {
                            'from': '2013-01-01T00:00:00+00:00',
                            'to': '2014-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ1',
                        'virkning': {
                            'from': '2012-01-01T00:00:00+00:00',
                            'to': '2013-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ3',
                        'virkning': {
                            'from': '2014-01-01T00:00:00+00:00',
                            'to': '2015-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                ]
            }
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from, new_to, paths, original, payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_zto_expanding_to_time(self):
        # Arrange
        new_from = util.parsedatetime('2012-01-01T00:00:00+00:00')
        new_to = util.parsedatetime('2016-07-01T00:00:00+00:00')

        original = {
            'test1': {
                'test2': [
                    {
                        'uuid': 'HEJ2',
                        'virkning': {
                            'from': '2013-01-01T00:00:00+00:00',
                            'to': '2014-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ1',
                        'virkning': {
                            'from': '2012-01-01T00:00:00+00:00',
                            'to': '2013-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ3',
                        'virkning': {
                            'from': '2014-01-01T00:00:00+00:00',
                            'to': '2015-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                ]
            }
        }

        payload = {
            'whatever': ['I should remain untouched, please'],
            'test1': {
                'no': ['Me too']
            },
            'note': 'NOTE'
        }

        paths = [
            common.FieldTuple(
                ('test1', 'test2'),
                common.FieldTypes.ZERO_TO_ONE,
                lambda x: x
            )
        ]

        expected_result = {
            'whatever': ['I should remain untouched, please'],
            'note': 'NOTE',
            'test1': {
                'no': [
                    'Me too'
                ],
                'test2': [
                    {
                        'uuid': 'HEJ3',
                        'virkning': {
                            'from': '2014-01-01T00:00:00+00:00',
                            'to': '2016-07-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                ]
            }
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from, new_to, paths, original, payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_zto_expanding_from_time(self):
        # Arrange
        new_from = util.parsedatetime('2010-01-01T00:00:00+00:00')
        new_to = util.parsedatetime('2015-01-01T00:00:00+00:00')

        original = {
            'test1': {
                'test2': [
                    {
                        'uuid': 'HEJ2',
                        'virkning': {
                            'from': '2013-01-01T00:00:00+00:00',
                            'to': '2014-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ1',
                        'virkning': {
                            'from': '2012-01-01T00:00:00+00:00',
                            'to': '2013-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ3',
                        'virkning': {
                            'from': '2014-01-01T00:00:00+00:00',
                            'to': '2015-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                ]
            }
        }

        payload = {
            'whatever': ['I should remain untouched, please'],
            'test1': {
                'no': ['Me too']
            },
            'note': 'NOTE'
        }

        paths = [
            common.FieldTuple(
                ('test1', 'test2'),

                common.FieldTypes.ZERO_TO_ONE,
                lambda x: x
            )
        ]

        expected_result = {
            'whatever': ['I should remain untouched, please'],
            'note': 'NOTE',
            'test1': {
                'no': [
                    'Me too'
                ],
                'test2': [
                    {
                        'uuid': 'HEJ1',
                        'virkning': {
                            'from': '2010-01-01T00:00:00+00:00',
                            'to': '2013-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                ]
            }
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from, new_to, paths, original, payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_zto_inside_bounds(self):
        # Arrange
        new_from = util.parsedatetime('2012-01-01T00:00:00+00:00')
        new_to = util.parsedatetime('2015-01-01T00:00:00+00:00')

        original = {
            'test1': {
                'test2': [
                    {
                        'uuid': 'HEJ2',
                        'virkning': {
                            'from': '2013-01-01T00:00:00+00:00',
                            'to': '2014-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ1',
                        'virkning': {
                            'from': '2012-01-01T00:00:00+00:00',
                            'to': '2013-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ3',
                        'virkning': {
                            'from': '2014-01-01T00:00:00+00:00',
                            'to': '2015-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                ]
            }
        }

        payload = {
            'whatever': ['I should remain untouched, please'],
            'test1': {
                'no': ['Me too']
            },
            'note': 'NOTE'
        }

        paths = [
            common.FieldTuple(
                ('test1', 'test2'),

                common.FieldTypes.ZERO_TO_ONE,
                lambda x: x
            )
        ]

        expected_result = {
            'whatever': ['I should remain untouched, please'],
            'note': 'NOTE',
            'test1': {
                'no': [
                    'Me too'
                ]
            }
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from, new_to, paths, original, payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_zto_extending_both_ends(self):
        # Arrange
        new_from = util.parsedatetime('2010-01-01T00:00:00+00:00')
        new_to = util.parsedatetime('2020-01-01T00:00:00+00:00')

        original = {
            'test1': {
                'test2': [
                    {
                        'uuid': 'HEJ2',
                        'virkning': {
                            'from': '2013-01-01T00:00:00+00:00',
                            'to': '2014-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ1',
                        'virkning': {
                            'from': '2012-01-01T00:00:00+00:00',
                            'to': '2013-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ3',
                        'virkning': {
                            'from': '2014-01-01T00:00:00+00:00',
                            'to': '2015-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                ]
            }
        }

        payload = {
            'whatever': ['I should remain untouched, please'],
            'test1': {
                'no': ['Me too']
            },
            'note': 'NOTE'
        }

        paths = [
            common.FieldTuple(
                ('test1', 'test2'),

                common.FieldTypes.ZERO_TO_ONE,
                lambda x: x
            )
        ]

        expected_result = {
            'whatever': ['I should remain untouched, please'],
            'note': 'NOTE',
            'test1': {
                'no': [
                    'Me too'
                ],
                'test2': [
                    {
                        'uuid': 'HEJ1',
                        'virkning': {
                            'from': '2010-01-01T00:00:00+00:00',
                            'to': '2013-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                    {
                        'uuid': 'HEJ3',
                        'virkning': {
                            'from': '2014-01-01T00:00:00+00:00',
                            'to': '2020-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    },
                ]
            }
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from, new_to, paths, original, payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_zto_extending_both_ends_single_effect(self):
        # Arrange
        new_from = util.parsedatetime('2010-01-01T00:00:00+00:00')
        new_to = util.parsedatetime('2020-01-01T00:00:00+00:00')

        original = {
            'test1': {
                'test2': [
                    {
                        'uuid': 'HEJ1',
                        'virkning': {
                            'from': '2012-01-01T00:00:00+00:00',
                            'to': '2013-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    }
                ]
            }
        }

        payload = {
            'whatever': ['I should remain untouched, please'],
            'test1': {
                'no': ['Me too']
            },
            'note': 'NOTE'
        }

        paths = [
            common.FieldTuple(
                ('test1', 'test2'),

                common.FieldTypes.ZERO_TO_ONE,
                lambda x: x
            )
        ]

        expected_result = {
            'whatever': ['I should remain untouched, please'],
            'note': 'NOTE',
            'test1': {
                'no': [
                    'Me too'
                ],
                'test2': [
                    {
                        'uuid': 'HEJ1',
                        'virkning': {
                            'from': '2010-01-01T00:00:00+00:00',
                            'to': '2020-01-01T00:00:00+00:00',
                            'from_included': True,
                            'to_included': False,
                        }
                    }
                ]
            }
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from, new_to, paths, original, payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_handles_unknown_fields(self):
        # Arrange
        new_from = util.parsedatetime('2010-01-01T00:00:00+00:00')
        new_to = util.parsedatetime('2020-01-01T00:00:00+00:00')

        original = {
            'unknown': {
            }
        }

        payload = {
            'whatever': ['I should remain untouched, please'],
            'test1': {
                'no': ['Me too']
            },
            'note': 'NOTE'
        }

        paths = [
            common.FieldTuple(
                ('test1', 'test2'),

                common.FieldTypes.ZERO_TO_ONE,
                lambda x: x
            )
        ]

        expected_result = {
            'whatever': ['I should remain untouched, please'],
            'note': 'NOTE',
            'test1': {
                'no': [
                    'Me too'
                ]
            }
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from, new_to, paths, original, payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_merge_obj_1(self):
        # New obj overlaps beginning and ending of originals
        # Arrange
        orig_objs = [
            {
                'uuid': 'whatever1',
                'virkning': {
                    'from': '2015-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2017-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            },
            {
                'uuid': 'whatever2',
                'virkning': {
                    'from': '2017-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2019-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            }
        ]

        new = {
            'uuid': 'whatever3',
            'virkning': {
                'from': '2016-01-01T00:00:00+01:00',
                'from_included': True,
                'to': '2018-01-01T00:00:00+01:00',
                'to_included': False,
            }
        }

        expected_result = [
            {
                'uuid': 'whatever1',
                'virkning': {
                    'from': '2015-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2016-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            },
            {
                'uuid': 'whatever3',
                'virkning': {
                    'from': '2016-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2018-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            },
            {
                'uuid': 'whatever2',
                'virkning': {
                    'from': '2018-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2019-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            }
        ]

        # Act
        actual_result = common._merge_obj_effects(orig_objs, new)

        actual_result = sorted(actual_result,
                               key=lambda x: x.get('virkning').get('from'))

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_merge_obj_2(self):
        # Original timespan completely contains new timespan
        # Arrange
        orig_objs = [
            {
                'uuid': 'whatever1',
                'virkning': {
                    'from': '2015-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2020-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            }
        ]

        new = {
            'uuid': 'whatever3',
            'virkning': {
                'from': '2016-01-01T00:00:00+01:00',
                'from_included': True,
                'to': '2018-01-01T00:00:00+01:00',
                'to_included': False,
            }
        }

        expected_result = [
            {
                'uuid': 'whatever1',
                'virkning': {
                    'from': '2015-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2016-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            },
            {
                'uuid': 'whatever3',
                'virkning': {
                    'from': '2016-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2018-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            },
            {
                'uuid': 'whatever1',
                'virkning': {
                    'from': '2018-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2020-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            }
        ]

        # Act
        actual_result = common._merge_obj_effects(orig_objs, new)

        actual_result = sorted(actual_result,
                               key=lambda x: x.get('virkning').get('from'))

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_merge_obj_3(self):
        # New doesn't overlap with originals
        # Arrange
        orig_objs = [
            {
                'uuid': 'whatever1',
                'virkning': {
                    'from': '2015-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2016-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            },
            {
                'uuid': 'whatever2',
                'virkning': {
                    'from': '2018-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2019-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            }
        ]

        new = {
            'uuid': 'whatever3',
            'virkning': {
                'from': '2016-01-01T00:00:00+01:00',
                'from_included': True,
                'to': '2018-01-01T00:00:00+01:00',
                'to_included': False,
            }
        }

        expected_result = [
            {
                'uuid': 'whatever1',
                'virkning': {
                    'from': '2015-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2016-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            },
            {
                'uuid': 'whatever3',
                'virkning': {
                    'from': '2016-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2018-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            },
            {
                'uuid': 'whatever2',
                'virkning': {
                    'from': '2018-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2019-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            }
        ]

        # Act
        actual_result = common._merge_obj_effects(orig_objs, new)

        actual_result = sorted(actual_result,
                               key=lambda x: x.get('virkning').get('from'))

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_merge_obj_4(self):
        # New completely overlaps with old
        # Arrange
        orig_objs = [
            {
                'uuid': 'whatever1',
                'virkning': {
                    'from': '2015-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2016-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            },
            {
                'uuid': 'whatever2',
                'virkning': {
                    'from': '2018-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2019-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            }
        ]

        new = {
            'uuid': 'whatever3',
            'virkning': {
                'from': '2010-01-01T00:00:00+01:00',
                'from_included': True,
                'to': '2020-01-01T00:00:00+01:00',
                'to_included': False,
            }
        }

        expected_result = [
            {
                'uuid': 'whatever3',
                'virkning': {
                    'from': '2010-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2020-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            }
        ]

        # Act
        actual_result = common._merge_obj_effects(orig_objs, new)

        actual_result = sorted(actual_result,
                               key=lambda x: x.get('virkning').get('from'))

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_merge_obj_5(self):
        # Handle infinity
        # Arrange
        orig_objs = [
            {
                'uuid': 'whatever1',
                'virkning': {
                    'from': '2014-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': 'infinity',
                    'to_included': False,
                }
            }
        ]

        new = {
            'uuid': 'whatever2',
            'virkning': {
                'from': '2016-01-01T00:00:00+01:00',
                'from_included': True,
                'to': 'infinity',
                'to_included': False,
            }
        }

        expected_result = [
            {
                'uuid': 'whatever1',
                'virkning': {
                    'from': '2014-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': '2016-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            },
            {
                'uuid': 'whatever2',
                'virkning': {
                    'from': '2016-01-01T00:00:00+01:00',
                    'from_included': True,
                    'to': 'infinity',
                    'to_included': False,
                }
            }
        ]

        # Act
        actual_result = common._merge_obj_effects(orig_objs, new)

        actual_result = sorted(actual_result,
                               key=lambda x: x.get('virkning').get('from'))

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_merge_obj_6(self):
        # Handle -infinity
        # Arrange
        orig_objs = [
            {
                'uuid': 'whatever1',
                'virkning': {
                    'from': '-infinity',
                    'from_included': False,
                    'to': '2016-01-01T00:00:00+01:00',
                    'to_included': False,
                }
            }
        ]

        new = {
            'uuid': 'whatever2',
            'virkning': {
                'from': '-infinity',
                'from_included': False,
                'to': 'infinity',
                'to_included': False,
            }
        }

        expected_result = [
            {
                'uuid': 'whatever2',
                'virkning': {
                    'from': '-infinity',
                    'from_included': False,
                    'to': 'infinity',
                    'to_included': False,
                }
            }
        ]

        # Act
        actual_result = common._merge_obj_effects(orig_objs, new)

        actual_result = sorted(actual_result,
                               key=lambda x: x.get('virkning').get('from'))

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_set_object_value_existing_path(self):
        # Arrange
        obj = {'test1': {'test2': [{'key1': 'val1'}]}}
        path = ('test1', 'test2')

        val = [{'key2': 'val2'}]

        expected_result = {
            'test1': {
                'test2': [
                    {'key1': 'val1'},
                    {'key2': 'val2'},
                ]
            }
        }

        # Act
        actual_result = common.set_object_value(obj, path, val)

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_set_object_value_new_path(self):
        # Arrange
        obj = {}
        path = ('test1', 'test2')

        val = [{'key2': 'val2'}]

        expected_result = {
            'test1': {
                'test2': [
                    {'key2': 'val2'},
                ]
            }
        }

        # Act
        actual_result = common.set_object_value(obj, path, val)

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_get_valid_from(self):
        ts = '2018-03-21T00:00:00+01:00'
        dt = datetime.datetime(2018, 3, 21,
                               tzinfo=dateutil.tz.tzoffset(None, 3600))

        self.assertEqual(dt, common.get_valid_from(
            {
                'validity': {
                    'from': ts,
                }
            },
        ))

        self.assertEqual(dt, common.get_valid_from(
            {
                'validity': {
                },
            },
            {
                'validity': {
                    'from': ts,
                }
            }
        ))

        self.assertRaises(
            ValueError, common.get_valid_from,
            {},
        )

        self.assertRaises(
            ValueError, common.get_valid_from,
            {
                'validity': {},
            },
        )

        self.assertRaises(
            ValueError, common.get_valid_from,
            {},
            {
                'validity': {
                }
            },
        )

        self.assertRaises(
            ValueError, common.get_valid_from,
            {

            },
            {
                'validity': {
                }
            },
        )

        self.assertRaises(
            ValueError, common.get_valid_from,
            {

            },
            {
                'validity': {
                    'from': None,
                }
            },
        )

    def test_get_valid_to(self):
        ts = '2018-03-21T00:00:00+01:00'
        dt = datetime.datetime(2018, 3, 21,
                               tzinfo=dateutil.tz.tzoffset(None, 3600))

        self.assertEqual(dt, common.get_valid_to(
            {
                'validity': {
                    'to': ts,
                }
            },
        ))

        self.assertEqual(dt, common.get_valid_to(
            {
                'validity': {
                },
            },
            {
                'validity': {
                    'to': ts,
                }
            }
        ))

        self.assertEqual(
            util.positive_infinity,
            common.get_valid_to({}),
        )

        self.assertEqual(
            common.get_valid_to({
                'validity': {},
            }),
            util.positive_infinity,
        )

        self.assertEqual(
            util.positive_infinity,
            common.get_valid_to(
                {},
                {
                    'validity': {
                    }
                },
            ),
        )

        self.assertEqual(
            util.positive_infinity,
            common.get_valid_to(
                {
                    'validity': {
                        'to': None,
                    }
                },
            ),
        )

        self.assertEqual(
            util.positive_infinity,
            common.get_valid_to(
                {},
                {
                    'validity': {
                        'to': None,
                    }
                },
            ),
        )

    def test_get_validities(self):
        # start time required
        self.assertRaises(
            ValueError,
            common.get_valid_from, {}, {},
        )

        self.assertRaises(
            ValueError,
            common.get_valid_from, {}, {
                'validity': None,
            },
        )

        self.assertRaises(
            ValueError,
            common.get_valid_from, {}, {
                'validity': {
                    'from': None,
                },
            },
        )

        # still nothing
        self.assertEqual(
            common.get_valid_to({}, {}),
            util.positive_infinity,
        )

        self.assertEqual(
            common.get_valid_to({}, {
                'validity': None,
            }),
            util.positive_infinity,
        )

        self.assertEqual(
            util.positive_infinity,
            common.get_valid_to({}, {
                'validity': {
                    'to': None,
                },
            }),
        )

        # actually set
        self.assertEqual(
            datetime.datetime(2018, 3, 5, tzinfo=util.default_timezone),
            common.get_valid_from({
                'validity': {
                    'from': '2018-03-05',
                },
            }),
        )

        self.assertEqual(
            datetime.datetime(2018, 3, 5, tzinfo=util.default_timezone),
            common.get_valid_to({
                'validity': {
                    'to': '2018-03-05',
                },
            }),
        )

        # actually set in the fallback
        self.assertEqual(
            datetime.datetime(2018, 3, 5, tzinfo=util.default_timezone),
            common.get_valid_from({}, {
                'validity': {
                    'from': '2018-03-05',
                },
            }),
        )

        self.assertEqual(
            datetime.datetime(2018, 3, 5, tzinfo=util.default_timezone),
            common.get_valid_to({}, {
                'validity': {
                    'to': '2018-03-05',
                },
            }),
        )

    def test_get_uuid(self):
        testid = '00000000-0000-0000-0000-000000000000'

        self.assertEqual(
            testid,
            common.get_uuid({
                'uuid': testid,
            }),
        )

        self.assertEqual(
            testid,
            common.get_uuid(
                {},
                {
                    'uuid': testid,
                },
            ),
        )

        self.assertRaises(
            ValueError,
            common.get_uuid,
            {
                'uuid': 42,
            },
        )

    def test_checked_get(self):
        mapping = {
            'list': [1337],
            'dict': {1337: 1337},
            'string': '1337',
            'int': 1337,
        }

        # when it's there
        self.assertIs(
            common.checked_get(mapping, 'list', []),
            mapping['list'],
        )

        self.assertIs(
            common.checked_get(mapping, 'dict', {}),
            mapping['dict'],
        )

        self.assertIs(
            common.checked_get(mapping, 'string', ''),
            mapping['string'],
        )

        self.assertIs(
            common.checked_get(mapping, 'int', 1337),
            mapping['int'],
        )

        # when it's not there
        self.assertEqual(
            common.checked_get(mapping, 'nonexistent', [], required=False),
            [],
        )

        self.assertEqual(
            common.checked_get(mapping, 'nonexistent', {}, required=False),
            {},
        )

        with self.assertRaisesRegex(ValueError, "missing 'nonexistent'"):
            common.checked_get(mapping, 'nonexistent', [])

        with self.assertRaisesRegex(ValueError, "missing 'nonexistent'"):
            common.checked_get(mapping, 'nonexistent', {})

        # bad value
        with self.assertRaisesRegex(
                ValueError,
                'invalid \'dict\', expected list, got: {"1337": 1337}',
        ):
            common.checked_get(mapping, 'dict', [])

        with self.assertRaisesRegex(
                ValueError,
                r"invalid 'list', expected dict, got: \[1337\]",
        ):
            common.checked_get(mapping, 'list', {})
