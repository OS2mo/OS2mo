# SPDX-FileCopyrightText: 2018-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0
import collections
import datetime
import unittest
from unittest import TestCase
from unittest.mock import call
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from oio_rest import db
from oio_rest.app import create_app
from oio_rest.custom_exceptions import BadRequestException
from oio_rest.custom_exceptions import DBException
from oio_rest.custom_exceptions import NotFoundException


def get_mocked_cursor(mock):
    """Replace the context manager for a cursor object with magic mock"""
    _ = mock.return_value.cursor
    cursor = _.return_value.__enter__.return_value = MagicMock()
    return cursor


class TestDB(TestCase):
    def setUp(self):
        app = create_app()
        self.client = TestClient(app)

    @patch("oio_rest.db.get_relation_field_type")
    def test_convert_relation_value_default(self, mock_get_rel):
        mock_get_rel.return_value = "not a known field type"

        value = "value"

        actual_value = db.convert_relation_value("test", "field", value)

        assert value == actual_value

    @patch("oio_rest.db.get_relation_field_type")
    def test_convert_relation_value_journalnotat(self, mock_get_rel):
        from oio_rest.db.db_helpers import JournalNotat

        # Arrange
        mock_get_rel.return_value = "journalnotat"

        titel = "TITEL"
        notat = "NOTAT"
        format_ = "FORMAT"
        value = {"titel": titel, "notat": notat, "format": format_}

        expected_result = JournalNotat(titel, notat, format_)

        # Act
        actual_result = db.convert_relation_value("test", "field", value)

        # Assert
        assert expected_result == actual_result

    @patch("oio_rest.db.get_relation_field_type")
    def test_convert_relation_value_journaldokument(self, mock_get_rel):
        from oio_rest.db.db_helpers import JournalDokument, OffentlighedUndtaget

        # Arrange
        mock_get_rel.return_value = "journaldokument"

        dokumenttitel = "DOKUMENTTITEL"
        alternativtitel = "ALTERNATIVTITEL"
        hjemmel = "HJEMMEL"

        value = {
            "dokumenttitel": dokumenttitel,
            "offentlighedundtaget": {
                "alternativtitel": alternativtitel,
                "hjemmel": hjemmel,
            },
        }

        offentlighedundtaget = OffentlighedUndtaget(alternativtitel, hjemmel)

        expected_result = JournalDokument(dokumenttitel, offentlighedundtaget)

        # Act
        actual_result = db.convert_relation_value("test", "field", value)

        # Assert
        assert expected_result == actual_result

    @patch("oio_rest.db.get_relation_field_type")
    def test_convert_relation_value_aktoerattr(self, mock_get_rel):
        from oio_rest.db.db_helpers import AktoerAttr

        # Arrange
        mock_get_rel.return_value = "aktoerattr"

        accepteret = "ACCEPTERET"
        obligatorisk = "OBLIGATORISK"
        repraesentation_uuid = "REPRAESENTATION_UUID"
        repraesentation_urn = "REPRAESENTATION_URN"

        value = {
            "accepteret": accepteret,
            "obligatorisk": obligatorisk,
            "repraesentation_uuid": repraesentation_uuid,
            "repraesentation_urn": repraesentation_urn,
        }

        expected_result = AktoerAttr(
            accepteret, obligatorisk, repraesentation_uuid, repraesentation_urn
        )

        # Act
        actual_result = db.convert_relation_value("test", "field", value)

        # Assert
        assert expected_result == actual_result

    @patch("oio_rest.db.get_relation_field_type")
    def test_convert_relation_value_aktoerattr_no_value(self, mock_get_rel):
        # Arrange
        mock_get_rel.return_value = "aktoerattr"

        value = {}

        expected_result = value

        # Act
        actual_result = db.convert_relation_value("test", "field", value)

        # Assert
        assert expected_result == actual_result

    @patch("oio_rest.db.get_relation_field_type")
    def test_convert_relation_value_vaerdirelationattr(self, mock_get_rel):
        from oio_rest.db.db_helpers import VaerdiRelationAttr

        # Arrange
        mock_get_rel.return_value = "vaerdirelationattr"

        forventet = "FORVENTET"
        nominelvaerdi = "NOMINELVAERDI"

        value = {"forventet": forventet, "nominelvaerdi": nominelvaerdi}

        expected_result = VaerdiRelationAttr(forventet, nominelvaerdi)

        # Act
        actual_result = db.convert_relation_value("test", "field", value)

        # Assert
        assert expected_result == actual_result

    @patch("oio_rest.db.get_attribute_fields")
    def test_convert_attributes_no_value(self, mock_get_attr):
        # Arrange
        mock_get_attr.return_value = ["field1", "field2", "field3", "field4"]

        attributes = {}

        # Act
        actual_result = db.convert_attributes(attributes)

        # Assert
        assert attributes == actual_result

    @patch("oio_rest.db.get_attribute_fields")
    def test_convert_attributes_is_correct_order(self, mock_get_attr):
        # Arrange
        mock_get_attr.return_value = ["field1", "field2", "field3", "field4"]

        attributes = {
            "attribute": [
                {
                    "field2": "value2",
                    "field3": "value3",
                    "field1": "value1",
                    "field4": "value4",
                }
            ]
        }

        expected_result = {
            "attribute": [
                [
                    "value1",
                    "value2",
                    "value3",
                    "value4",
                ]
            ]
        }
        # Act
        actual_result = db.convert_attributes(attributes)

        # Assert
        assert expected_result == actual_result

    @patch("oio_rest.db.get_attribute_fields")
    def test_convert_attributes_adds_none_values(self, mock_get_attr):
        # Arrange
        mock_get_attr.return_value = ["field1", "field2", "field3", "field4"]

        attributes = {"attribute": [{}]}

        expected_result = {
            "attribute": [
                [
                    None,
                    None,
                    None,
                    None,
                ]
            ]
        }
        # Act
        actual_result = db.convert_attributes(attributes)

        # Assert
        assert expected_result == actual_result

    @patch("oio_rest.db.get_attribute_fields")
    def test_convert_attributes_handles_multiple_attributes(self, mock_get_attr):
        # Arrange
        mock_get_attr.return_value = ["field1", "field2", "field3", "field4"]

        attributes = {
            "attribute1": [{"field2": "value2"}],
            "attribute2": [{"field3": "value3"}],
        }

        expected_result = {
            "attribute1": [
                [
                    None,
                    "value2",
                    None,
                    None,
                ]
            ],
            "attribute2": [
                [
                    None,
                    None,
                    "value3",
                    None,
                ]
            ],
        }
        # Act
        actual_result = db.convert_attributes(attributes)

        # Assert
        assert expected_result == actual_result

    @patch("oio_rest.db.convert_relation_value")
    def test_convert_relations_no_value(self, mock_conv_rel):
        # type: (MagicMock) -> None
        # Arrange

        mock_conv_rel.return_value = "value"

        relations = {}

        # Act
        actual_result = db.convert_relations(relations, "classname")

        # Assert
        assert relations == actual_result

    @patch("oio_rest.db.convert_relation_value")
    def test_convert_relations_calls_convert_relation_value(self, mock_conv_rel):
        # type: (MagicMock) -> None
        # Arrange

        mock_conv_rel.return_value = "value"

        relations = {
            "relation1": [{"field1": "value1", "field2": "value2"}],
            "relation2": [{"field3": "value3", "field4": "value4"}],
        }

        # Act
        db.convert_relations(relations, "classname")

        # Assert
        assert call("classname", "field1", "value1") in mock_conv_rel.call_args_list
        assert call("classname", "field2", "value2") in mock_conv_rel.call_args_list
        assert call("classname", "field3", "value3") in mock_conv_rel.call_args_list
        assert call("classname", "field4", "value4") in mock_conv_rel.call_args_list

    @patch("oio_rest.db.convert_relation_value", new=lambda x, y, z: z)
    def test_convert_relations_returns_as_expected(self):
        # type: () -> None
        # Arrange

        relations = {
            "relation1": [{"field1": "value1", "field2": "value2"}],
            "relation2": [{"field3": "value3", "field4": "value4"}],
        }

        expected_result = {
            "relation1": [{"field1": "value1", "field2": "value2"}],
            "relation2": [{"field3": "value3", "field4": "value4"}],
        }

        # Act
        actual_result = db.convert_relations(relations, "classname")

        # Assert
        assert expected_result == actual_result

    def test_convert_relations_raises_on_malformed_relation(self):
        # Arrange
        relations = {"relation": ["This is not a dict"]}

        # Act & Assert
        with pytest.raises(BadRequestException):
            db.convert_relations(relations, "classname")

    def test_convert_variants_none_value(self):
        # Arrange
        variants = None

        # Act
        actual_result = db.convert_variants(variants)

        # Assert
        assert actual_result is None

    @patch("oio_rest.db.DokumentVariantType.input")
    def test_convert_variants_calls_constructor(self, mock_dvt_input):
        # type: (MagicMock) -> None
        # Arrange
        expected_result = ["value1", "value2"]
        mock_dvt_input.side_effect = expected_result

        variants = ["variant1", "variant2"]

        # Act
        actual_result = db.convert_variants(variants)

        # Assert
        assert mock_dvt_input.call_count == 2
        assert expected_result == actual_result

    @patch("oio_rest.db.get_field_type")
    def test_convert_attr_value_default(self, mock_get_field_type):
        # type: (MagicMock) -> None
        # Arrange
        value = "attribute_field_value"
        mock_get_field_type.return_value = "text"

        # Act
        actual_result = db.convert_attr_value(
            "attribute_name", "attribute_field_name", value
        )
        # Assert
        assert value == actual_result

    @patch("oio_rest.db.get_field_type")
    def test_convert_attr_value_soegeord(self, mock_get_field_type):
        # type: (MagicMock) -> None
        from oio_rest.db.db_helpers import Soegeord

        # Arrange
        mock_get_field_type.return_value = "soegeord"

        value = [
            ["identifier1", "description1", "category1"],
            ["identifier2", "description2", "category2"],
        ]

        expected_result = [Soegeord(*value[0]), Soegeord(*value[1])]

        # Act
        actual_result = db.convert_attr_value(
            "attribute_name", "attribute_field_name", value
        )
        # Assert
        assert expected_result == actual_result

    @patch("oio_rest.db.get_field_type")
    def test_convert_attr_value_offentlighedundtagettype(self, mock_get_field_type):
        # type: (MagicMock) -> None
        from oio_rest.db.db_helpers import OffentlighedUndtaget

        # Arrange
        mock_get_field_type.return_value = "offentlighedundtagettype"

        alternativtitel = "ALTERNATIVTITEL"
        hjemmel = "HJEMMEL"

        value = {"alternativtitel": alternativtitel, "hjemmel": hjemmel}

        expected_result = OffentlighedUndtaget(alternativtitel, hjemmel)

        # Act
        actual_result = db.convert_attr_value(
            "attribute_name", "attribute_field_name", value
        )
        # Assert
        assert expected_result == actual_result

    @patch("oio_rest.db.get_field_type")
    def test_convert_attr_value_offentlighedundtagettype_none(
        self, mock_get_field_type
    ):
        # type: (MagicMock) -> None

        # Arrange
        mock_get_field_type.return_value = "offentlighedundtagettype"

        value = {}

        expected_result = None

        # Act
        actual_result = db.convert_attr_value(
            "attribute_name", "attribute_field_name", value
        )
        # Assert
        assert expected_result == actual_result

    @patch("oio_rest.db.get_field_type")
    def test_convert_attr_value_date(self, mock_get_field_type):
        # type: (MagicMock) -> None

        # Arrange
        mock_get_field_type.return_value = "date"

        value = "2017-01-01"

        expected_result = datetime.date(2017, 1, 1)

        # Act
        actual_result = db.convert_attr_value(
            "attribute_name", "attribute_field_name", value
        )
        # Assert
        assert expected_result == actual_result

    @patch("oio_rest.db.get_field_type")
    def test_convert_attr_value_timestamptz(self, mock_get_field_type):
        # type: (MagicMock) -> None

        # Arrange
        mock_get_field_type.return_value = "timestamptz"

        value = "2017-01-01 00:00"

        expected_result = datetime.datetime(2017, 1, 1, 0, 0)

        # Act
        actual_result = db.convert_attr_value(
            "attribute_name", "attribute_field_name", value
        )
        # Assert
        assert expected_result == actual_result

    @patch("oio_rest.db.get_field_type")
    def test_convert_attr_value_interval(self, mock_get_field_type):
        # type: (MagicMock) -> None

        # Arrange
        mock_get_field_type.return_value = "interval(0)"

        value = "1 day"

        expected_result = "'1 day' :: interval"

        # Act
        actual_result = db.convert_attr_value(
            "attribute_name", "attribute_field_name", value
        )
        # Assert
        assert expected_result == str(actual_result)

    @patch("oio_rest.db.transform_virkning")
    @patch("oio_rest.db.filter_empty")
    @patch("oio_rest.db.simplify_cleared_wrappers")
    def test_filter_json_output(self, mock_transform, mock_filter, mock_simplify):
        # type: (MagicMock, MagicMock, MagicMock) -> None
        # Arrange
        mock_transform.side_effect = lambda x: x
        mock_filter.side_effect = lambda x: x
        mock_simplify.side_effect = lambda x: x

        expected_output = {"key": "value"}

        # Act
        actual_output = db.filter_json_output(expected_output)
        # Assert

        mock_transform.assert_called()
        mock_filter.assert_called()
        mock_simplify.assert_called()
        assert expected_output == actual_output

    def test_simplify_cleared_wrappers_dict_with_cleared(self):
        # Arrange
        value = {"cleared": "", "value": "testvalue", "bla": "whatever"}

        # Act
        actual_result = db.simplify_cleared_wrappers(value)

        # Assert
        assert actual_result == "testvalue"

    def test_simplify_cleared_wrappers_dict_without_cleared(self):
        # Arrange
        value = {"key1": "val1", "key2": "val2"}

        # Act
        actual_result = db.simplify_cleared_wrappers(value)

        # Assert
        assert value == actual_result

    def test_simplify_cleared_wrappers_list(self):
        # Arrange
        value = ["cleared", "val1", "val2", "val3"]

        # Act
        actual_result = db.simplify_cleared_wrappers(value)

        # Assert
        assert value == actual_result

    def test_simplify_cleared_wrappers_tuple(self):
        # Arrange
        value = ("cleared", "val1", "val2", "val3")

        # Act
        actual_result = db.simplify_cleared_wrappers(value)

        # Assert
        assert value == actual_result

    def test_simplify_cleared_wrappers_recursive(self):
        # Arrange
        value = (
            {"cleared": "", "value": "val1", "whatever": "1234"},
            [
                {"cleared": "", "value": "val2", "bla": "whatever"},
                {"untouched1": "1234", "untouched2": "5678"},
            ],
            ({"cleared": "", "value": "val4"}, ["should", "be", "untouched"]),
        )

        expected_result = (
            "val1",
            ["val2", {"untouched1": "1234", "untouched2": "5678"}],
            ("val4", ["should", "be", "untouched"]),
        )

        # Act
        actual_result = db.simplify_cleared_wrappers(value)

        # Assert
        assert expected_result == actual_result

    def test_simplify_cleared_wrappers_default(self):
        # Arrange
        value = 1234

        # Act
        actual_result = db.simplify_cleared_wrappers(value)

        # Assert
        assert value == actual_result

    def test_transform_virkning_parses_included(self):
        # Arrange
        value = (
            {"timeperiod": "[12345678,12345678]"},
            {"timeperiod": "(12345678,12345678)"},
        )
        # Act
        actual_result = db.transform_virkning(value)
        # Assert
        assert actual_result[0]["from_included"]
        assert actual_result[0]["to_included"]
        assert not actual_result[1]["from_included"]
        assert not actual_result[1]["to_included"]

    def test_transform_virkning_removes_quotes(self):
        # Arrange
        value = {"timeperiod": '("12345678","12345678")'}

        # Act
        actual_result = db.transform_virkning(value)

        # Assert
        assert actual_result["from"] == "12345678"
        assert actual_result["to"] == "12345678"

    def test_transform_virkning_dict_with_timeperiod(self):
        # Arrange
        value = {"timeperiod": '(12345678,"12345678"]'}

        expected_result = {
            "from": "12345678",
            "from_included": False,
            "to": "12345678",
            "to_included": True,
        }

        # Act
        actual_result = db.transform_virkning(value)

        # Assert
        assert expected_result == actual_result

    def test_transform_virkning_dict_without_timeperiod(self):
        # Arrange
        value = {"nottimeperiod": "asdasdasd test"}

        # Act
        actual_result = db.transform_virkning(value)

        # Assert
        assert value == actual_result

    def test_transform_virkning_list(self):
        # Arrange
        value = ["nottimeperiod", "asdasdasd test"]

        # Act
        actual_result = db.transform_virkning(value)

        # Assert
        assert value == actual_result

    def test_transform_virkning_tuple(self):
        # Arrange
        value = ("nottimeperiod", "asdasdasd test")

        # Act
        actual_result = db.transform_virkning(value)

        # Assert
        assert value == actual_result

    def test_transform_virkning_recursive(self):
        # Arrange
        value = (
            {"timeperiod": '(12345678,"12345678"]', "untouched": "1234"},
            [
                {"timeperiod": '(12345678,"12345678"]', "bla": "1234"},
                {"untouched1": "1234", "untouched2": "5678"},
            ],
            ({"timeperiod": '(12345678,"12345678"]'}, ["should", "be", "untouched"]),
        )

        expected_result = (
            {
                "from": "12345678",
                "from_included": False,
                "to": "12345678",
                "to_included": True,
                "untouched": "1234",
            },
            [
                {
                    "from": "12345678",
                    "from_included": False,
                    "to": "12345678",
                    "to_included": True,
                    "bla": "1234",
                },
                {"untouched1": "1234", "untouched2": "5678"},
            ],
            (
                {
                    "from": "12345678",
                    "from_included": False,
                    "to": "12345678",
                    "to_included": True,
                },
                ["should", "be", "untouched"],
            ),
        )

        # Act
        actual_result = db.transform_virkning(value)

        # Assert
        assert expected_result == actual_result

    def test_transform_virkning_default(self):
        # Arrange
        value = 1234

        # Act
        actual_result = db.transform_virkning(value)

        # Assert
        assert value == actual_result

    def test_filter_empty_with_dict(self):
        # Arrange
        value = {"emptykey1": "", "emptykey2": None, "nonempty": "12345"}

        expected_result = {"nonempty": "12345"}

        # Act
        actual_result = db.filter_empty(value)

        # Assert
        assert expected_result == actual_result

    def test_filter_empty_recursive(self):
        # Arrange
        value = (
            {"emptykey": "", "untouched": "1234"},
            [
                {"emptykey": None, "bla": "1234"},
                {"untouched1": "1234", "untouched2": "5678"},
            ],
            ({"emptykey": ""}, ["should", "be", "untouched"]),
        )

        expected_result = (
            {"untouched": "1234"},
            [{"bla": "1234"}, {"untouched1": "1234", "untouched2": "5678"}],
            (["should", "be", "untouched"],),
        )

        # Act
        actual_result = db.filter_empty(value)

        # Assert
        assert expected_result == actual_result

    def test_transform_relations_with_list_dict(self):
        # Arrange
        value = {
            "relationer": [
                {"reltype": "test1", "key1": "val1", "key2": "val2"},
                {"reltype": "test2", "key1": "val3", "key2": "val4"},
            ]
        }

        expected_result = {
            "relationer": {
                "test1": [{"key1": "val1", "key2": "val2"}],
                "test2": [{"key1": "val3", "key2": "val4"}],
            }
        }

        # Act
        actual_value = db.transform_relations(value)

        # Assert
        assert expected_result == actual_value

    def test_transform_relations_with_tuple_dict(self):
        # Arrange
        value = {
            "relationer": (
                {"reltype": "test1", "key1": "val1", "key2": "val2"},
                {"reltype": "test2", "key1": "val3", "key2": "val4"},
            )
        }

        expected_result = {
            "relationer": {
                "test1": [{"key1": "val1", "key2": "val2"}],
                "test2": [{"key1": "val3", "key2": "val4"}],
            }
        }

        # Act
        actual_value = db.transform_relations(value)

        # Assert
        assert expected_result == actual_value

    def test_transform_relations_recursive(self):
        # Arrange
        value = (
            [
                {
                    "relationer": (
                        {"reltype": "test1", "key1": "val1", "key2": "val2"},
                    ),
                    "whatever": "1234",
                }
            ],
            (
                {
                    "relationer": (
                        {"reltype": "test2", "key1": "val1", "key2": "val2"},
                    ),
                    "whatever": "5678",
                }
            ),
        )

        expected_result = (
            [
                {
                    "relationer": {
                        "test1": [
                            {"key1": "val1", "key2": "val2"},
                        ]
                    },
                    "whatever": "1234",
                }
            ],
            (
                {
                    "relationer": {
                        "test2": [
                            {"key1": "val1", "key2": "val2"},
                        ]
                    },
                    "whatever": "5678",
                }
            ),
        )

        # Act
        actual_value = db.transform_relations(value)

        # Assert
        assert expected_result == actual_value

    @patch("oio_rest.db.list_objects")
    def test_get_life_cycle_code(self, mock_list_objs):
        # type: (MagicMock) -> None
        # Arrange
        class_name = ""
        uuid = "e9eea92f-d404-48c4-85e1-222b56013e3e"
        results = [
            [
                {
                    "id": "8c949998-f01b-4e7c-953b-8ae4fec475a2",
                    "registreringer": [
                        {
                            "attributter": {},
                            "relationer": {},
                            "tilstande": {},
                            "livscykluskode": "Importeret",
                        }
                    ],
                }
            ]
        ]

        mock_list_objs.return_value = results

        # Act
        actual_result = db.get_life_cycle_code(class_name, uuid)

        # Assert
        assert actual_result == "Importeret"


class TestConsolidateVirkninger(unittest.TestCase):
    def test_consolidate_effects_works_correctly(self):
        # Arrange
        effects = [
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1950-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1900-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "1950-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
        ]

        expected = [
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1900-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            }
        ]

        # Act
        actual = db._consolidate_virkninger(effects)

        # Assert
        assert expected == actual

    def test_consolidate_handles_differing_attributes(self):
        # Arrange
        effects = [
            {
                "something": "garbage",
                "virkning": {
                    "from": "1900-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "1950-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1950-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "1980-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "whatever": "garbage2",
                "virkning": {
                    "from": "1980-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        # Act
        actual = db._consolidate_virkninger(effects)

        # Assert
        assert effects == actual

    def test_consolidate_handles_zero_to_many(self):
        """Handle overlapping intervals as found in zero-to-many relations"""
        # Arrange
        effects = [
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1900-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "1950-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1950-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "2000-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "whatever": "other garbage",
                "virkning": {
                    "from": "1900-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "1930-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "whatever": "other garbage",
                "virkning": {
                    "from": "1930-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "2000-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
        ]

        expected = [
            {
                "virkning": {
                    "from": "1900-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "2000-01-01 00:00:00+01",
                    "to_included": False,
                },
                "whatever": "garbage",
            },
            {
                "virkning": {
                    "from": "1900-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "2000-01-01 00:00:00+01",
                    "to_included": False,
                },
                "whatever": "other garbage",
            },
        ]

        # Act
        actual = db._consolidate_virkninger(effects)

        # Assert
        assert expected == actual

    def test_consolidate_handles_zero_to_many_many_equal_overlaps(self):
        """Handle overlapping intervals as found in zero-to-many relations"""
        # Arrange
        effects = [
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1900-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "1950-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1950-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "2000-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1920-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "1980-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
        ]

        expected = [
            {
                "virkning": {
                    "from": "1900-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "1950-01-01 00:00:00+01",
                    "to_included": False,
                },
                "whatever": "garbage",
            },
            {
                "virkning": {
                    "from": "1920-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "1980-01-01 00:00:00+01",
                    "to_included": False,
                },
                "whatever": "garbage",
            },
            {
                "virkning": {
                    "from": "1950-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "2000-01-01 00:00:00+01",
                    "to_included": False,
                },
                "whatever": "garbage",
            },
        ]

        # Act
        actual = db._consolidate_virkninger(effects)

        # Assert
        assert expected == actual

    def test_consolidate_handles_non_sequential_periods(self):
        # Arrange
        effects = [
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1900-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "1950-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1950-01-02 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        # Act
        actual = db._consolidate_virkninger(effects)

        # Assert
        assert effects == actual

    def test_consolidate_handles_single_element(self):
        # Arrange
        effects = [
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1900-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "1950-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
        ]

        # Act
        actual = db._consolidate_virkninger(effects)

        # Assert
        assert effects == actual

    def test_consolidate_handles_empty_list(self):
        # Arrange
        effects = []

        # Act
        actual = db._consolidate_virkninger(effects)

        # Assert
        assert effects == actual

    def test_consolidate_and_trim_removes_empty_keys(self):
        obj = [
            [
                {
                    "id": "6467fbb0-dd62-48ae-90be-abdef7e66aa7",
                    "registreringer": [
                        {
                            "attributter": {
                                "organisationfunktionegenskaber": [
                                    {
                                        "funktionsnavn": "navn 2",
                                        "virkning": {
                                            "from": "1970-04-30 22:00:00+00",
                                            "from_included": True,
                                            "to": "infinity",
                                            "to_included": False,
                                        },
                                    }
                                ],
                                "organisationfunktionudvidelser": [
                                    {
                                        "fraktion": 100,
                                        "virkning": {
                                            "from": "1920-04-30 22:00:00+00",
                                            "from_included": True,
                                            "to": "1930-04-30 22:00:00+00",
                                            "to_included": False,
                                        },
                                    }
                                ],
                            },
                            "brugerref": "42c432e8-9c4a-11e6-9f62-873cf34a735f",
                            "fratidspunkt": {
                                "graenseindikator": True,
                                "tidsstempeldatotid": "2019-12-18T09:37:49.811807"
                                "+00:00",
                            },
                            "livscykluskode": "Rettet",
                            "note": "Rediger engagement",
                        }
                    ],
                }
            ]
        ]

        actual = db._consolidate_and_trim_object_virkninger(
            obj, "1999-01-01 00:00:00+00", "infinity"
        )

        actual_attributes = actual[0][0]["registreringer"][0]["attributter"]

        # 'organisationfunktionudvidelser' should be gone at this point
        assert "organisationfunktionegenskaber" in actual_attributes
        assert "organisationfunktionudvidelser" not in actual_attributes

    def test_consolidate_and_trim_removes_empty_categories(self):
        obj = [
            [
                {
                    "id": "6467fbb0-dd62-48ae-90be-abdef7e66aa7",
                    "registreringer": [
                        {
                            "attributter": {
                                "organisationfunktionudvidelser": [
                                    {
                                        "fraktion": 100,
                                        "virkning": {
                                            "from": "1920-04-30 22:00:00+00",
                                            "from_included": True,
                                            "to": "1930-04-30 22:00:00+00",
                                            "to_included": False,
                                        },
                                    }
                                ]
                            },
                            "brugerref": "42c432e8-9c4a-11e6-9f62-873cf34a735f",
                            "fratidspunkt": {
                                "graenseindikator": True,
                                "tidsstempeldatotid": "2019-12-18T09:37:49.811807"
                                "+00:00",
                            },
                            "livscykluskode": "Rettet",
                            "note": "Rediger engagement",
                        }
                    ],
                }
            ]
        ]

        actual = db._consolidate_and_trim_object_virkninger(
            obj, "1999-01-01 00:00:00+00", "infinity"
        )

        actual_registration = actual[0][0]["registreringer"][0]

        # 'attributter' should be gone at this point
        assert "attributter" not in actual_registration

    def test_trim_virkninger_lower_bound_not_included(self):
        effects = [
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "-infinity",
                    "from_included": True,
                    "to": "1950-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1950-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        expected = [
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1950-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            }
        ]

        actual = db._trim_virkninger(effects, "1950-01-01 00:00:00+01", "infinity")

        assert expected == actual

    def test_trim_virkninger_lower_bound_included(self):
        effects = [
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "-infinity",
                    "from_included": True,
                    "to": "1950-01-01 00:00:00+01",
                    "to_included": True,
                },
            },
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1950-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        expected = [
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "-infinity",
                    "from_included": True,
                    "to": "1950-01-01 00:00:00+01",
                    "to_included": True,
                },
            },
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1950-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        actual = db._trim_virkninger(effects, "1950-01-01 00:00:00+01", "infinity")

        assert expected == actual

    def test_trim_virkninger_upper_bound_not_included(self):
        effects = [
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "-infinity",
                    "from_included": True,
                    "to": "1950-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1950-01-01 00:00:00+01",
                    "from_included": False,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        expected = [
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "-infinity",
                    "from_included": True,
                    "to": "1950-01-01 00:00:00+01",
                    "to_included": False,
                },
            }
        ]

        actual = db._trim_virkninger(effects, "-infinity", "1950-01-01 00:00:00+01")

        assert expected == actual

    def test_trim_virkninger_upper_bound_included(self):
        effects = [
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "-infinity",
                    "from_included": True,
                    "to": "1950-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1950-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        expected = [
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "-infinity",
                    "from_included": True,
                    "to": "1950-01-01 00:00:00+01",
                    "to_included": False,
                },
            },
            {
                "whatever": "garbage",
                "virkning": {
                    "from": "1950-01-01 00:00:00+01",
                    "from_included": True,
                    "to": "infinity",
                    "to_included": False,
                },
            },
        ]

        actual = db._trim_virkninger(effects, "-infinity", "1950-01-01 00:00:00+01")

        assert expected == actual


@patch("oio_rest.db.sql_convert_registration", new=MagicMock())
class TestDBObjectFunctions(unittest.TestCase):
    @patch("oio_rest.db.get_connection")
    @patch("oio_rest.db.jinja_env")
    def test_update_object_returns_uuid(self, mock_jinja_env, mock_get_conn):
        # type: (MagicMock, MagicMock) -> None
        # Arrange
        uuid = "uuid"

        # Act
        actual_result = db.update_object("classname", {}, "note", uuid)

        # Assert
        assert uuid == actual_result

    @patch("oio_rest.db.get_connection")
    @patch("oio_rest.db.jinja_env")
    def test_list_objects_raises_on_no_results(self, mock_jinja_env, mock_get_conn):
        # type: (MagicMock, MagicMock) -> None
        # Arrange
        cursor = get_mocked_cursor(mock_get_conn)
        cursor.fetchone.return_value = None

        # Act
        with pytest.raises(NotFoundException):
            db.list_objects(
                "classname",
                ["uuid"],
                "virkning_fra",
                "virkning_til",
                "registrering_fra",
                "registrering_til",
            )


class TestDBGeneralSQL(unittest.TestCase):
    @patch("oio_rest.db.sql_attribute_array")
    @patch("oio_rest.db.sql_relations_array")
    @patch("oio_rest.db.get_attribute_names")
    @patch("oio_rest.db.convert_attributes", new=lambda x: x)
    @patch("oio_rest.db.get_state_names", new=MagicMock())
    def test_sql_convert_registration_attributes(
        self,
        mock_get_attribute_names,
        mock_sql_relations_array,
        mock_sql_attribute_array,
    ):
        # type: (MagicMock, MagicMock, MagicMock) -> None
        mock_get_attribute_names.return_value = ["attribute1", "attribute2"]
        mock_sql_relations_array.return_value = []
        mock_sql_attribute_array.side_effect = lambda *x: x

        # Arrange
        registration = {
            "states": {},
            "attributes": {
                "attribute1": ["val1"],
                "attribute3": ["val3"],
                "whatever": "whatever",
            },
            "relations": {},
        }

        class_name = "classname"

        expected_result = {
            "states": [],
            "attributes": [("attribute1", ["val1"]), ("attribute2", None)],
            "relations": [],
        }

        # Act
        actual_result = db.sql_convert_registration(registration, class_name)

        # Assert
        sql_state_array_args = mock_sql_attribute_array.call_args_list
        assert call("attribute1", ["val1"]) in sql_state_array_args
        assert call("attribute2", None) in sql_state_array_args
        assert len(sql_state_array_args) == 2

        assert expected_result == actual_result

    @patch("oio_rest.db.sql_state_array")
    @patch("oio_rest.db.sql_relations_array")
    @patch("oio_rest.db.get_attribute_names", new=MagicMock())
    @patch("oio_rest.db.get_state_names")
    def test_sql_convert_registration_states(
        self, mock_get_state_names, mock_sql_relations_array, mock_sql_state_array
    ):
        # type: (MagicMock, MagicMock, MagicMock) -> None
        mock_get_state_names.return_value = ["state1", "state2"]
        mock_sql_relations_array.return_value = []
        mock_sql_state_array.side_effect = lambda *x: x

        # Arrange
        registration = {
            "states": {
                "classnamestate1": "val1",
                "classnamestate3": "val3",
                "whatever": "whatever",
            },
            "attributes": {},
            "relations": {},
        }

        class_name = "classname"

        expected_result = {
            "states": [("state1", "val1", "classname"), ("state2", None, "classname")],
            "attributes": [],
            "relations": [],
        }

        # Act
        actual_result = db.sql_convert_registration(registration, class_name)

        # Assert
        sql_state_array_args = mock_sql_state_array.call_args_list
        assert call("state1", "val1", "classname") in sql_state_array_args
        assert call("state2", None, "classname") in sql_state_array_args
        assert len(sql_state_array_args) == 2

        assert expected_result == actual_result

    @patch("oio_rest.db.sql_relations_array")
    @patch("oio_rest.db.convert_relations", new=lambda x, y: x)
    @patch("oio_rest.db.get_attribute_names", new=MagicMock())
    @patch("oio_rest.db.get_state_names", new=MagicMock())
    def test_sql_convert_registration_relations(self, mock_sql_relations_array):
        # type: (MagicMock) -> None
        mock_sql_relations_array.side_effect = lambda *x: x

        # Arrange
        registration = {
            "states": {},
            "attributes": {},
            "relations": {"relation1": [], "relation2": []},
        }

        class_name = "classname"

        # Act
        db.sql_convert_registration(registration, class_name)

        # Assert
        sql_state_array_args = mock_sql_relations_array.call_args_list
        assert (
            call("classname", {"relation1": [], "relation2": []})
            in sql_state_array_args
        )

    @patch("oio_rest.db.convert_variants")
    @patch("oio_rest.db.adapt")
    @patch("oio_rest.db.convert_relations", new=lambda x, y: x)
    @patch("oio_rest.db.get_attribute_names", new=MagicMock())
    @patch("oio_rest.db.get_state_names", new=MagicMock())
    def test_sql_convert_registration_variants(self, mock_adapt, mock_convert_variants):
        # type: (MagicMock, MagicMock) -> None
        mock_adapt.side_effect = lambda x: x
        mock_convert_variants.side_effect = lambda x: x

        # Arrange
        variants = ["variant1", "variant2"]
        registration = {
            "variants": variants,
            "states": {},
            "attributes": {},
            "relations": {},
        }

        class_name = "classname"

        # Act
        db.sql_convert_registration(registration, class_name)

        # Assert
        mock_adapt.assert_called_with(variants)
        mock_convert_variants.assert_called_with(variants)


Diagnostics = collections.namedtuple("Diagnostics", ["message_primary"])


@patch("oio_rest.db.get_connection")
@patch("oio_rest.db.sql_get_registration", new=MagicMock())
@patch("oio_rest.db.sql_convert_registration", new=MagicMock())
@patch("oio_rest.db.jinja_env.get_template", new=MagicMock())
class TestPGErrors(unittest.TestCase):
    class TestException(Exception):
        def __init__(self, code="MO123", message="1 2 3 testing..."):
            self.pgcode = code
            self.pgerror = message
            self.diag = Diagnostics(message)

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_object_exists_raises_on_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        classname = "classname"
        uuid = "1c3236a1-9384-4730-82ab-5443e95bcead"

        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = TestPGErrors.TestException

        # Act
        with pytest.raises(Exception):
            db.object_exists(classname, uuid)

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_object_exists_raises_on_unknown_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        classname = "classname"
        uuid = "1c3236a1-9384-4730-82ab-5443e95bcead"

        cursor = get_mocked_cursor(mock_get_conn)
        exception = TestPGErrors.TestException("12345")
        cursor.execute.side_effect = exception

        # Act
        with pytest.raises(TestPGErrors.TestException):
            db.object_exists(classname, uuid)

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_get_document_from_content_url_raises_on_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = TestPGErrors.TestException

        # Act
        with pytest.raises(DBException):
            db.get_document_from_content_url("")

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_get_document_from_content_url_raises_on_unknown_pgerror(
        self, mock_get_conn
    ):
        # type: (MagicMock) -> None

        # Arrange
        cursor = get_mocked_cursor(mock_get_conn)
        exception = TestPGErrors.TestException()
        exception.pgcode = "12345"
        cursor.execute.side_effect = exception

        # Act
        with pytest.raises(TestPGErrors.TestException):
            db.get_document_from_content_url("")

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_create_or_import_object_raises_on_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = TestPGErrors.TestException

        # Act
        with pytest.raises(DBException):
            db.create_or_import_object("", "", "", "")

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    @patch("oio_rest.db.object_exists", new=lambda *x: False)
    def test_create_or_import_object_raises_on_noop_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        class_name = "class"
        uuid = "61ae604b-e7fb-4892-a09a-55e5f6822435"
        exception = TestPGErrors.TestException()
        exception.message = (
            "Aborted updating {} with id [{}] as the given "
            "data, does not give raise to a new "
            "registration."
        ).format(class_name, uuid)
        exception.pgcode = "12345"

        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = exception

        # Act
        with pytest.raises(TestPGErrors.TestException):
            db.create_or_import_object(class_name, "", "", uuid)

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_create_or_import_object_raises_on_unknown_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        class_name = "class"
        uuid = "61ae604b-e7fb-4892-a09a-55e5f6822435"
        exception = TestPGErrors.TestException()
        exception.pgcode = "12345"

        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = exception

        # Act
        with pytest.raises(TestPGErrors.TestException):
            db.create_or_import_object(class_name, "", "", uuid)

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_delete_object_raises_on_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = TestPGErrors.TestException

        # Act
        with pytest.raises(DBException):
            db.delete_object("", "", "", "")

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    @patch("oio_rest.db.object_exists", new=lambda *x: False)
    def test_delete_object_raises_on_notfound_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        class_name = "classname"
        uuid = "40910e35-feeb-47ca-8020-a88fffe6d6f3"

        exception = TestPGErrors.TestException(
            "12345",
            (
                "Unable to update {} with uuid [{}], "
                "being unable to find any previous registrations."
            ).format(class_name.lower(), uuid),
        )

        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = exception

        # Act
        with pytest.raises(NotFoundException):
            db.delete_object(class_name, "", "", uuid)

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_delete_object_raises_on_unknown_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        exception = TestPGErrors.TestException()
        exception.pgcode = "12345"
        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = exception

        # Act
        with pytest.raises(TestPGErrors.TestException):
            db.delete_object("", "", "", "")

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_passivate_object_raises_on_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        exception = TestPGErrors.TestException()
        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = exception

        # Act
        with pytest.raises(DBException):
            db.passivate_object("", "", "", "")

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_passivate_object_raises_on_unknown_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        exception = TestPGErrors.TestException()
        exception.pgcode = "123456"
        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = exception

        # Act
        with pytest.raises(TestPGErrors.TestException):
            db.passivate_object("", "", "", "")

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_update_object_raises_on_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        exception = TestPGErrors.TestException()
        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = exception

        # Act
        with pytest.raises(DBException):
            db.update_object("", "", "", "")

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_update_object_returns_uuid_on_noop_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        class_name = "classname"
        uuid = "8abdb359-ce8a-47d9-a5d0-c9a1c6d36c44"

        exception = TestPGErrors.TestException(
            message="Aborted updating {} with id [{}] as the given data, "
            "does not give raise to a new registration.".format(
                class_name.lower(), uuid
            )
        )
        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = exception

        # Act
        actual_result = db.update_object(class_name, "", "", uuid)

        # Assert
        assert uuid == actual_result

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_update_object_raises_on_unknown_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        exception = TestPGErrors.TestException()
        exception.pgcode = "123456"
        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = exception

        # Act
        with pytest.raises(TestPGErrors.TestException):
            db.update_object("", "", "", "")

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_list_objects_raises_on_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        exception = TestPGErrors.TestException()
        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = exception

        # Act
        with pytest.raises(DBException):
            db.list_objects("", "", "", "", "", "")

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_list_objects_raises_on_unknown_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        exception = TestPGErrors.TestException()
        exception.pgcode = "123456"
        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = exception

        # Act
        with pytest.raises(TestPGErrors.TestException):
            db.list_objects("", "", "", "", "", "")

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_search_objects_raises_on_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        exception = TestPGErrors.TestException()
        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = exception

        # Act
        with pytest.raises(DBException):
            db.search_objects("", "", "")

    @patch("oio_rest.db.psycopg2.Error", new=TestException)
    def test_search_objects_raises_on_unknown_pgerror(self, mock_get_conn):
        # type: (MagicMock) -> None

        # Arrange
        exception = TestPGErrors.TestException()
        exception.pgcode = "123456"
        cursor = get_mocked_cursor(mock_get_conn)
        cursor.execute.side_effect = exception

        # Act
        with pytest.raises(TestPGErrors.TestException):
            db.search_objects("", "", "")
