# SPDX-FileCopyrightText: 2018-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0
import freezegun
import mora.async_util
import tests.cases
from mora import common
from mora import exceptions
from mora import lora
from mora import mapping
from mora import util as mora_util
from more_itertools import one
from yarl import URL

from . import util


class TestClass(tests.cases.TestCase):
    maxDiff = None

    def test_update_payload_complex(self):
        # Arrange
        fields = [
            (
                mapping.FieldTuple(
                    ("test1", "prop1"),
                    mapping.FieldTypes.ADAPTED_ZERO_TO_MANY,
                    lambda x: True,
                ),
                {
                    "uuid": "8525d022-e939-4d16-8378-2e46101a3a47",
                },
            ),
            (
                mapping.FieldTuple(
                    ("test1", "prop2"),
                    mapping.FieldTypes.ZERO_TO_MANY,
                    lambda x: True,
                ),
                {
                    "uuid": "6995b5db-5e66-4479-82d8-67045663eb79",
                },
            ),
            (
                mapping.FieldTuple(
                    ("test2", "prop3"),
                    mapping.FieldTypes.ZERO_TO_ONE,
                    lambda x: True,
                ),
                {
                    "uuid": "3251f325-a36f-4879-a150-2775cdc1b0fb",
                },
            ),
        ]

        original = {
            "test1": {
                "prop1": [
                    {
                        "uuid": "1ebd2f10-df7b-42ca-93d9-3078a174c3f6",
                        "virkning": {
                            "from": "2016-01-01T00:00:00+01:00",
                            "to": "2018-01-01T00:00:00+01:00",
                        },
                    },
                    {
                        "uuid": "6563c93d-48da-4375-a106-b05343f97915",
                        "virkning": {
                            "from": "2018-01-01T00:00:00+01:00",
                            "to": "2020-01-01T00:00:00+01:00",
                        },
                    },
                ],
                "prop2": [
                    {
                        "uuid": "eb936cf5-e72b-4aa9-9bd2-f773c462fa50",
                        "virkning": {
                            "from": "2016-01-01T00:00:00+01:00",
                            "to": "2020-01-01T00:00:00+01:00",
                        },
                    }
                ],
            },
            "test2": {
                "prop3": [
                    {
                        "uuid": "ab9c5351-6448-4b6e-be02-eb3c16960884",
                        "virkning": {
                            "from": "2016-01-01T00:00:00+01:00",
                            "to": "2020-01-01T00:00:00+01:00",
                        },
                    }
                ]
            },
            "test3": {
                "prop4": [
                    {
                        "uuid": "ab9c5351-6448-4b6e-be02-eb3c16960884",
                        "virkning": {
                            "from": "2016-01-01T00:00:00+01:00",
                            "to": "2020-01-01T00:00:00+01:00",
                        },
                    }
                ]
            },
        }

        expected_payload = {
            "test1": {
                "prop1": [
                    {
                        "uuid": "1ebd2f10-df7b-42ca-93d9-3078a174c3f6",
                        "virkning": {
                            "from": "2016-01-01T00:00:00+01:00",
                            "to": "2017-01-01T00:00:00+01:00",
                        },
                    },
                    {
                        "uuid": "8525d022-e939-4d16-8378-2e46101a3a47",
                        "virkning": {
                            "from": "2017-01-01T00:00:00+01:00",
                            "to": "2021-01-01T00:00:00+01:00",
                        },
                    },
                ],
                "prop2": [
                    {
                        "uuid": "6995b5db-5e66-4479-82d8-67045663eb79",
                        "virkning": {
                            "from": "2017-01-01T00:00:00+01:00",
                            "to": "2021-01-01T00:00:00+01:00",
                        },
                    }
                ],
            },
            "test2": {
                "prop3": [
                    {
                        "uuid": "3251f325-a36f-4879-a150-2775cdc1b0fb",
                        "virkning": {
                            "from": "2017-01-01T00:00:00+01:00",
                            "to": "2021-01-01T00:00:00+01:00",
                        },
                    }
                ]
            },
        }

        # Act
        actual_payload = common.update_payload(
            "2017-01-01T00:00:00+01:00",
            "2021-01-01T00:00:00+01:00",
            fields,
            original,
            {},
        )

        # Assert
        self.assertEqual(expected_payload, actual_payload)

    def test_inactivates_correctly_when_diminishing_bounds(self):
        # Arrange
        old_from = "2013-01-01T00:00:00+01:00"
        old_to = "2016-01-01T00:00:00+01:00"
        new_from = "2014-01-01T00:00:00+01:00"
        new_to = "2015-01-01T00:00:00+01:00"
        payload = {"whatever": ["Should remain untouched"], "note": "NOTE"}
        path = ("hest", "hestgyldighed")

        expected_result = {
            "whatever": ["Should remain untouched"],
            "hest": {
                "hestgyldighed": [
                    {
                        "gyldighed": "Inaktiv",
                        "virkning": {
                            "from": "2013-01-01T00:00:00+01:00",
                            "to": "2014-01-01T00:00:00+01:00",
                        },
                    },
                    {
                        "gyldighed": "Inaktiv",
                        "virkning": {
                            "from": "2015-01-01T00:00:00+01:00",
                            "to": "2016-01-01T00:00:00+01:00",
                        },
                    },
                ]
            },
            "note": "NOTE",
        }

        # Act
        actual_result = common.inactivate_old_interval(
            old_from,
            old_to,
            new_from,
            new_to,
            payload,
            path,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_does_not_inactivate_when_expanding_bounds(self):
        # Arrange
        old_from = "2014-01-01T00:00:00+01:00"
        old_to = "2015-01-01T00:00:00+01:00"
        new_from = "2013-01-01T00:00:00+01:00"
        new_to = "2016-01-01T00:00:00+01:00"
        payload = {"whatever": ["Should remain untouched"], "note": "NOTE"}
        path = ("hest", "hestgyldighed")

        expected_result = {"whatever": ["Should remain untouched"], "note": "NOTE"}

        # Act
        actual_result = common.inactivate_old_interval(
            old_from,
            old_to,
            new_from,
            new_to,
            payload,
            path,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_does_not_inactivate_when_bounds_do_not_move(self):
        # Arrange
        old_from = "2014-01-01T00:00:00+01:00"
        old_to = "2015-01-01T00:00:00+01:00"
        new_from = "2014-01-01T00:00:00+01:00"
        new_to = "2015-01-01T00:00:00+01:00"
        payload = {"whatever": ["Should remain untouched"], "note": "NOTE"}
        path = ("hest", "hestgyldighed")

        expected_result = {"whatever": ["Should remain untouched"], "note": "NOTE"}

        # Act
        actual_result = common.inactivate_old_interval(
            old_from,
            old_to,
            new_from,
            new_to,
            payload,
            path,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_aztm_times_are_inside_bounds(self):
        # Arrange
        new_from = mora_util.parsedatetime("2013-01-01T00:00:00+01:00")
        new_to = mora_util.parsedatetime("2015-01-01T00:00:00+01:00")

        original = {
            "test1": {
                "test2": [
                    {
                        "uuid": "HEJ2",
                        "virkning": {
                            "from": "2013-01-01T00:00:00+01:00",
                            "to": "2014-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2012-01-01T00:00:00+01:00",
                            "to": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ3",
                        "virkning": {
                            "from": "2014-01-01T00:00:00+01:00",
                            "to": "2015-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                ]
            }
        }

        payload = {
            "whatever": ["I should remain untouched, please"],
            "test1": {"no": ["Me too"]},
            "note": "NOTE",
        }
        paths = [
            mapping.FieldTuple(
                ("test1", "test2"), mapping.FieldTypes.ADAPTED_ZERO_TO_MANY, lambda x: x
            )
        ]

        expected_result = {
            "whatever": ["I should remain untouched, please"],
            "test1": {"no": ["Me too"]},
            "note": "NOTE",
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from,
            new_to,
            paths,
            original,
            payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_aztm_expanding_from_time(self):
        # Arrange
        new_from = mora_util.parsedatetime("2010-01-01T00:00:00+01:00")
        new_to = mora_util.parsedatetime("2014-01-01T00:00:00+01:00")

        original = {
            "test1": {
                "test2": [
                    {
                        "uuid": "HEJ2",
                        "virkning": {
                            "from": "2013-01-01T00:00:00+01:00",
                            "to": "2014-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2012-01-01T00:00:00+01:00",
                            "to": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ3",
                        "virkning": {
                            "from": "2014-01-01T00:00:00+01:00",
                            "to": "2015-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                ]
            }
        }

        payload = {
            "whatever": ["I should remain untouched, please"],
            "test1": {"no": ["Me too"]},
            "note": "NOTE",
        }

        paths = [
            mapping.FieldTuple(
                ("test1", "test2"), mapping.FieldTypes.ADAPTED_ZERO_TO_MANY, lambda x: x
            )
        ]

        expected_result = {
            "note": "NOTE",
            "test1": {
                "no": ["Me too"],
                "test2": [
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2010-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to": "2013-01-01T00:00:00+01:00",
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ2",
                        "virkning": {
                            "from": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to": "2014-01-01T00:00:00+01:00",
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ3",
                        "virkning": {
                            "from": "2014-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to": "2015-01-01T00:00:00+01:00",
                            "to_included": False,
                        },
                    },
                ],
            },
            "whatever": ["I should remain untouched, please"],
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from,
            new_to,
            paths,
            original,
            payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_aztm_diminishing_from_time(self):
        # Arrange
        new_from = mora_util.parsedatetime("2012-07-01T00:00:00+01:00")
        new_to = mora_util.parsedatetime("2015-01-01T00:00:00+01:00")

        original = {
            "test1": {
                "test2": [
                    {
                        "uuid": "HEJ2",
                        "virkning": {
                            "from": "2013-01-01T00:00:00+01:00",
                            "to": "2014-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2012-01-01T00:00:00+01:00",
                            "to": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ3",
                        "virkning": {
                            "from": "2014-01-01T00:00:00+01:00",
                            "to": "2015-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                ]
            }
        }

        payload = {
            "whatever": ["I should remain untouched, please"],
            "test1": {"no": ["Me too"]},
            "note": "NOTE",
        }

        paths = [
            mapping.FieldTuple(
                ("test1", "test2"), mapping.FieldTypes.ADAPTED_ZERO_TO_MANY, lambda x: x
            )
        ]

        expected_result = {
            "whatever": ["I should remain untouched, please"],
            "note": "NOTE",
            "test1": {"no": ["Me too"]},
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from,
            new_to,
            paths,
            original,
            payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_aztm_expanding_to_time(self):
        # Arrange
        new_from = mora_util.parsedatetime("2012-01-01T00:00:00+01:00")
        new_to = mora_util.parsedatetime("2017-01-01T00:00:00+01:00")

        original = {
            "test1": {
                "test2": [
                    {
                        "uuid": "HEJ2",
                        "virkning": {
                            "from": "2013-01-01T00:00:00+01:00",
                            "to": "2014-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2012-01-01T00:00:00+01:00",
                            "to": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ3",
                        "virkning": {
                            "from": "2014-01-01T00:00:00+01:00",
                            "to": "2015-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                ]
            }
        }

        payload = {
            "whatever": ["I should remain untouched, please"],
            "test1": {"no": ["Me too"]},
            "note": "NOTE",
        }

        paths = [
            mapping.FieldTuple(
                ("test1", "test2"), mapping.FieldTypes.ADAPTED_ZERO_TO_MANY, lambda x: x
            )
        ]

        expected_result = {
            "note": "NOTE",
            "test1": {
                "no": ["Me too"],
                "test2": [
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2012-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to": "2013-01-01T00:00:00+01:00",
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ2",
                        "virkning": {
                            "from": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to": "2014-01-01T00:00:00+01:00",
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ3",
                        "virkning": {
                            "from": "2014-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to": "2017-01-01T00:00:00+01:00",
                            "to_included": False,
                        },
                    },
                ],
            },
            "whatever": ["I should remain untouched, please"],
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from,
            new_to,
            paths,
            original,
            payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_aztm_diminishing_to_time(self):
        # Arrange
        new_from = mora_util.parsedatetime("2012-01-01T00:00:00+01:00")
        new_to = mora_util.parsedatetime("2014-07-01T00:00:00+02:00")

        original = {
            "test1": {
                "test2": [
                    {
                        "uuid": "HEJ2",
                        "virkning": {
                            "from": "2013-01-01T00:00:00+01:00",
                            "to": "2014-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2012-01-01T00:00:00+01:00",
                            "to": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ3",
                        "virkning": {
                            "from": "2014-01-01T00:00:00+01:00",
                            "to": "2015-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                ]
            }
        }

        payload = {
            "whatever": ["I should remain untouched, please"],
            "test1": {"no": ["Me too"]},
            "note": "NOTE",
        }

        paths = [
            mapping.FieldTuple(
                ("test1", "test2"), mapping.FieldTypes.ADAPTED_ZERO_TO_MANY, lambda x: x
            )
        ]

        expected_result = {
            "whatever": ["I should remain untouched, please"],
            "note": "NOTE",
            "test1": {"no": ["Me too"]},
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from,
            new_to,
            paths,
            original,
            payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_ztm(self):
        # Arrange
        new_from = mora_util.parsedatetime("2000-01-01T00:00:00+01:00")
        new_to = mora_util.parsedatetime("2020-07-01T00:00:00+02:00")

        original = {
            "test1": {
                "test2": [
                    {
                        "uuid": "HEJ2",
                        "virkning": {
                            "from": "2013-01-01T00:00:00+01:00",
                            "to": "2014-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2012-01-01T00:00:00+01:00",
                            "to": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ3",
                        "virkning": {
                            "from": "2014-01-01T00:00:00+01:00",
                            "to": "2015-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                ]
            }
        }

        payload = {
            "whatever": ["I should remain untouched, please"],
            "test1": {
                "no": ["Me too"],
            },
            "note": "NOTE",
        }

        paths = [
            mapping.FieldTuple(("test1", "test2"), mapping.FieldTypes.ZERO_TO_MANY, lambda x: x)
        ]

        expected_result = {
            "whatever": ["I should remain untouched, please"],
            "note": "NOTE",
            "test1": {
                "no": ["Me too"],
                "test2": [
                    {
                        "uuid": "HEJ2",
                        "virkning": {
                            "from": "2013-01-01T00:00:00+01:00",
                            "to": "2014-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2012-01-01T00:00:00+01:00",
                            "to": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ3",
                        "virkning": {
                            "from": "2014-01-01T00:00:00+01:00",
                            "to": "2015-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                ],
            },
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from,
            new_to,
            paths,
            original,
            payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_zto_expanding_to_time(self):
        # Arrange
        new_from = mora_util.parsedatetime("2012-01-01T00:00:00+01:00")
        new_to = mora_util.parsedatetime("2016-07-01T00:00:00+02:00")

        original = {
            "test1": {
                "test2": [
                    {
                        "uuid": "HEJ2",
                        "virkning": {
                            "from": "2013-01-01T00:00:00+01:00",
                            "to": "2014-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2012-01-01T00:00:00+01:00",
                            "to": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ3",
                        "virkning": {
                            "from": "2014-01-01T00:00:00+01:00",
                            "to": "2015-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                ]
            }
        }

        payload = {
            "whatever": ["I should remain untouched, please"],
            "test1": {"no": ["Me too"]},
            "note": "NOTE",
        }

        paths = [
            mapping.FieldTuple(("test1", "test2"), mapping.FieldTypes.ZERO_TO_ONE, lambda x: x)
        ]

        expected_result = {
            "whatever": ["I should remain untouched, please"],
            "note": "NOTE",
            "test1": {
                "no": ["Me too"],
                "test2": [
                    {
                        "uuid": "HEJ3",
                        "virkning": {
                            "from": "2014-01-01T00:00:00+01:00",
                            "to": "2016-07-01T00:00:00+02:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                ],
            },
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from,
            new_to,
            paths,
            original,
            payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_zto_expanding_from_time(self):
        # Arrange
        new_from = mora_util.parsedatetime("2010-01-01T00:00:00+01:00")
        new_to = mora_util.parsedatetime("2015-01-01T00:00:00+01:00")

        original = {
            "test1": {
                "test2": [
                    {
                        "uuid": "HEJ2",
                        "virkning": {
                            "from": "2013-01-01T00:00:00+01:00",
                            "to": "2014-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2012-01-01T00:00:00+01:00",
                            "to": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ3",
                        "virkning": {
                            "from": "2014-01-01T00:00:00+01:00",
                            "to": "2015-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                ]
            }
        }

        payload = {
            "whatever": ["I should remain untouched, please"],
            "test1": {"no": ["Me too"]},
            "note": "NOTE",
        }

        paths = [
            mapping.FieldTuple(("test1", "test2"), mapping.FieldTypes.ZERO_TO_ONE, lambda x: x)
        ]

        expected_result = {
            "whatever": ["I should remain untouched, please"],
            "note": "NOTE",
            "test1": {
                "no": ["Me too"],
                "test2": [
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2010-01-01T00:00:00+01:00",
                            "to": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                ],
            },
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from,
            new_to,
            paths,
            original,
            payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_zto_inside_bounds(self):
        # Arrange
        new_from = mora_util.parsedatetime("2012-01-01T00:00:00+01:00")
        new_to = mora_util.parsedatetime("2015-01-01T00:00:00+01:00")

        original = {
            "test1": {
                "test2": [
                    {
                        "uuid": "HEJ2",
                        "virkning": {
                            "from": "2013-01-01T00:00:00+01:00",
                            "to": "2014-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2012-01-01T00:00:00+01:00",
                            "to": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ3",
                        "virkning": {
                            "from": "2014-01-01T00:00:00+01:00",
                            "to": "2015-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                ]
            }
        }

        payload = {
            "whatever": ["I should remain untouched, please"],
            "test1": {"no": ["Me too"]},
            "note": "NOTE",
        }

        paths = [
            mapping.FieldTuple(("test1", "test2"), mapping.FieldTypes.ZERO_TO_ONE, lambda x: x)
        ]

        expected_result = {
            "whatever": ["I should remain untouched, please"],
            "note": "NOTE",
            "test1": {"no": ["Me too"]},
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from,
            new_to,
            paths,
            original,
            payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_zto_extending_both_ends(self):
        # Arrange
        new_from = mora_util.parsedatetime("2010-01-01T00:00:00+01:00")
        new_to = mora_util.parsedatetime("2020-01-01T00:00:00+01:00")

        original = {
            "test1": {
                "test2": [
                    {
                        "uuid": "HEJ2",
                        "virkning": {
                            "from": "2013-01-01T00:00:00+01:00",
                            "to": "2014-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2012-01-01T00:00:00+01:00",
                            "to": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ3",
                        "virkning": {
                            "from": "2014-01-01T00:00:00+01:00",
                            "to": "2015-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                ]
            }
        }

        payload = {
            "whatever": ["I should remain untouched, please"],
            "test1": {"no": ["Me too"]},
            "note": "NOTE",
        }

        paths = [
            mapping.FieldTuple(("test1", "test2"), mapping.FieldTypes.ZERO_TO_ONE, lambda x: x)
        ]

        expected_result = {
            "whatever": ["I should remain untouched, please"],
            "note": "NOTE",
            "test1": {
                "no": ["Me too"],
                "test2": [
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2010-01-01T00:00:00+01:00",
                            "to": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                    {
                        "uuid": "HEJ3",
                        "virkning": {
                            "from": "2014-01-01T00:00:00+01:00",
                            "to": "2020-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    },
                ],
            },
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from,
            new_to,
            paths,
            original,
            payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_zto_extending_both_ends_single_effect(self):
        # Arrange
        new_from = mora_util.parsedatetime("2010-01-01T00:00:00+01:00")
        new_to = mora_util.parsedatetime("2020-01-01T00:00:00+01:00")

        original = {
            "test1": {
                "test2": [
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2012-01-01T00:00:00+01:00",
                            "to": "2013-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    }
                ]
            }
        }

        payload = {
            "whatever": ["I should remain untouched, please"],
            "test1": {"no": ["Me too"]},
            "note": "NOTE",
        }

        paths = [
            mapping.FieldTuple(("test1", "test2"), mapping.FieldTypes.ZERO_TO_ONE, lambda x: x)
        ]

        expected_result = {
            "whatever": ["I should remain untouched, please"],
            "note": "NOTE",
            "test1": {
                "no": ["Me too"],
                "test2": [
                    {
                        "uuid": "HEJ1",
                        "virkning": {
                            "from": "2010-01-01T00:00:00+01:00",
                            "to": "2020-01-01T00:00:00+01:00",
                            "from_included": True,
                            "to_included": False,
                        },
                    }
                ],
            },
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from,
            new_to,
            paths,
            original,
            payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_ensure_bounds_handles_unknown_fields(self):
        # Arrange
        new_from = mora_util.parsedatetime("2010-01-01T00:00:00+01:00")
        new_to = mora_util.parsedatetime("2020-01-01T00:00:00+01:00")

        original = {"unknown": {}}

        payload = {
            "whatever": ["I should remain untouched, please"],
            "test1": {"no": ["Me too"]},
            "note": "NOTE",
        }

        paths = [
            mapping.FieldTuple(("test1", "test2"), mapping.FieldTypes.ZERO_TO_ONE, lambda x: x)
        ]

        expected_result = {
            "whatever": ["I should remain untouched, please"],
            "note": "NOTE",
            "test1": {"no": ["Me too"]},
        }

        # Act
        actual_result = common.ensure_bounds(
            new_from,
            new_to,
            paths,
            original,
            payload,
        )

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_merge_obj_1(self):
        """New obj overlaps beginning and ending of originals"""
        # Arrange
        orig_objs = [
            {
                "uuid": "whatever1",
                "virkning": {
                    "from": "2015-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2017-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever2",
                "virkning": {
                    "from": "2017-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2019-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
        ]

        new = [
            {
                "uuid": "whatever3",
                "virkning": {
                    "from": "2016-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2018-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            }
        ]

        expected_result = [
            {
                "uuid": "whatever1",
                "virkning": {
                    "from": "2015-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2016-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever3",
                "virkning": {
                    "from": "2016-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2018-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever2",
                "virkning": {
                    "from": "2018-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2019-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
        ]

        # Act
        actual_result = common._merge_obj_effects(orig_objs, new)

        actual_result = sorted(actual_result, key=lambda x: x.get("virkning").get("from"))

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_merge_obj_2(self):
        """Original timespan completely contains new timespan"""
        # Arrange
        orig_objs = [
            {
                "uuid": "whatever1",
                "virkning": {
                    "from": "2015-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2020-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            }
        ]

        new = [
            {
                "uuid": "whatever3",
                "virkning": {
                    "from": "2016-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2018-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            }
        ]

        expected_result = [
            {
                "uuid": "whatever1",
                "virkning": {
                    "from": "2015-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2016-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever3",
                "virkning": {
                    "from": "2016-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2018-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever1",
                "virkning": {
                    "from": "2018-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2020-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
        ]

        # Act
        actual_result = common._merge_obj_effects(orig_objs, new)

        actual_result = sorted(actual_result, key=lambda x: x.get("virkning").get("from"))

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_merge_obj_3(self):
        """New doesn't overlap with originals"""
        # Arrange
        orig_objs = [
            {
                "uuid": "whatever1",
                "virkning": {
                    "from": "2015-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2016-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever2",
                "virkning": {
                    "from": "2018-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2019-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
        ]

        new = [
            {
                "uuid": "whatever3",
                "virkning": {
                    "from": "2016-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2018-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            }
        ]

        expected_result = [
            {
                "uuid": "whatever1",
                "virkning": {
                    "from": "2015-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2016-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever3",
                "virkning": {
                    "from": "2016-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2018-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever2",
                "virkning": {
                    "from": "2018-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2019-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
        ]

        # Act
        actual_result = common._merge_obj_effects(orig_objs, new)

        actual_result = sorted(actual_result, key=lambda x: x.get("virkning").get("from"))

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_merge_obj_4(self):
        """New completely overlaps with old"""
        # Arrange
        orig_objs = [
            {
                "uuid": "whatever1",
                "virkning": {
                    "from": "2015-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2016-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever2",
                "virkning": {
                    "from": "2018-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2019-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
        ]

        new = [
            {
                "uuid": "whatever3",
                "virkning": {
                    "from": "2010-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2020-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            }
        ]

        expected_result = [
            {
                "uuid": "whatever3",
                "virkning": {
                    "from": "2010-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2020-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            }
        ]

        # Act
        actual_result = common._merge_obj_effects(orig_objs, new)

        actual_result = sorted(actual_result, key=lambda x: x.get("virkning").get("from"))

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_merge_obj_5(self):
        """Handle infinity"""
        # Arrange
        orig_objs = [
            {
                "uuid": "whatever1",
                "virkning": {
                    "from": "2014-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            }
        ]

        new = [
            {
                "uuid": "whatever2",
                "virkning": {
                    "from": "2016-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            }
        ]

        expected_result = [
            {
                "uuid": "whatever1",
                "virkning": {
                    "from": "2014-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "2016-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever2",
                "virkning": {
                    "from": "2016-01-01T00:00:00+01:00",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        # Act
        actual_result = common._merge_obj_effects(orig_objs, new)

        actual_result = sorted(actual_result, key=lambda x: x.get("virkning").get("from"))

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_merge_obj_6(self):
        """Handle -infinity"""
        # Arrange
        orig_objs = [
            {
                "uuid": "whatever1",
                "virkning": {
                    "from": "-infinity",
                    "from_included": False,
                    "to": "2016-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            }
        ]

        new = [
            {
                "uuid": "whatever2",
                "virkning": {
                    "from": "-infinity",
                    "from_included": False,
                    "to": "infinity",
                    "to_included": False,
                },
            }
        ]

        expected_result = [
            {
                "uuid": "whatever2",
                "virkning": {
                    "from": "-infinity",
                    "from_included": False,
                    "to": "infinity",
                    "to_included": False,
                },
            }
        ]

        # Act
        actual_result = common._merge_obj_effects(orig_objs, new)

        actual_result = sorted(actual_result, key=lambda x: x.get("virkning").get("from"))

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_merge_obj_7(self):
        """Handle writing more than one entry"""
        # Arrange
        orig_objs = [
            {
                "uuid": "whatever1",
                "virkning": {
                    "from": "-infinity",
                    "from_included": False,
                    "to": "2016-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            }
        ]

        new = [
            {
                "uuid": "whatever2",
                "virkning": {
                    "from": "-infinity",
                    "from_included": False,
                    "to": "infinity",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever3",
                "virkning": {
                    "from": "-infinity",
                    "from_included": False,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        expected_result = new

        # Act
        actual_result = common._merge_obj_effects(orig_objs, new)

        actual_result = sorted(actual_result, key=lambda x: x.get("virkning").get("from"))

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_merge_obj_8(self):
        """Handle overwriting more than one entry"""
        # Arrange
        orig_objs = [
            {
                "uuid": "whatever1",
                "virkning": {
                    "from": "-infinity",
                    "from_included": False,
                    "to": "2016-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever2",
                "virkning": {
                    "from": "-infinity",
                    "from_included": False,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        new = [
            {
                "uuid": "whatever3",
                "virkning": {
                    "from": "-infinity",
                    "from_included": False,
                    "to": "infinity",
                    "to_included": False,
                },
            }
        ]

        expected_result = new

        # Act
        actual_result = common._merge_obj_effects(orig_objs, new)

        actual_result = sorted(actual_result, key=lambda x: x.get("virkning").get("from"))

        # Assert
        self.assertEqual(expected_result, actual_result)

    def test_merge_obj_9(self):
        """Handle overwriting where orig contains multiple entries
        with semi-arbitrary virkningstider"""
        # Arrange
        orig_objs = [
            {
                "uuid": "whatever1",
                "virkning": {
                    "from": "-infinity",
                    "from_included": False,
                    "to": "2016-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever2",
                "virkning": {
                    "from": "2010-01-01T00:00:00+01:00",
                    "from_included": False,
                    "to": "2017-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever3",
                "virkning": {
                    "from": "2015-01-01T00:00:00+01:00",
                    "from_included": False,
                    "to": "2020-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever4",
                "virkning": {
                    "from": "2016-01-01T00:00:00+01:00",
                    "from_included": False,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        new = [
            {
                "uuid": "whatever5",
                "virkning": {
                    "from": "2014-01-01T00:00:00+01:00",
                    "from_included": False,
                    "to": "2018-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever6",
                "virkning": {
                    "from": "2014-01-01T00:00:00+01:00",
                    "from_included": False,
                    "to": "2018-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
        ]

        expected_result = [
            {
                "uuid": "whatever1",
                "virkning": {
                    "from": "-infinity",
                    "from_included": False,
                    "to": "2014-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever2",
                "virkning": {
                    "from": "2010-01-01T00:00:00+01:00",
                    "from_included": False,
                    "to": "2014-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever5",
                "virkning": {
                    "from": "2014-01-01T00:00:00+01:00",
                    "from_included": False,
                    "to": "2018-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever6",
                "virkning": {
                    "from": "2014-01-01T00:00:00+01:00",
                    "from_included": False,
                    "to": "2018-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever3",
                "virkning": {
                    "from": "2018-01-01T00:00:00+01:00",
                    "from_included": False,
                    "to": "2020-01-01T00:00:00+01:00",
                    "to_included": False,
                },
            },
            {
                "uuid": "whatever4",
                "virkning": {
                    "from": "2018-01-01T00:00:00+01:00",
                    "from_included": False,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        # Act
        actual_result = common._merge_obj_effects(orig_objs, new)

        actual_result = sorted(actual_result, key=lambda x: x.get("virkning").get("from"))

        # Assert
        self.assertEqual(expected_result, actual_result)

    @freezegun.freeze_time("2018-01-01")
    @util.MockAioresponses()
    def test_history_missing(self, mock):
        userid = "00000000-0000-0000-0000-000000000000"

        url = URL("http://mox/organisation/bruger")
        mock.get(
            url,
            payload={
                "results": [],
            },
        )

        with self.assertRaises(exceptions.HTTPException) as cm:
            mora.async_util.async_to_sync(common.add_history_entry)(
                lora.Connector().bruger,
                userid,
                "kaflaflibob",
            )

        call_args = one(mock.requests["GET", url])
        self.assertEqual(
            call_args.kwargs["json"],
            {
                "uuid": [userid],
                "virkningfra": "2018-01-01T00:00:00+01:00",
                "virkningtil": "2018-01-01T00:00:00.000001+01:00",
                "konsolider": "True",
            },
        )

        self.assertEqual(
            cm.exception.detail,
            {
                "description": "Not found.",
                "error": True,
                "error_key": "E_NOT_FOUND",
                "path": "organisation/bruger",
                "status": 404,
                "uuid": userid,
            },
        )
