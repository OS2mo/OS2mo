# SPDX-FileCopyrightText: 2019-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0
from unittest.mock import patch

import pytest

from mora import exceptions
from mora.service.address_handler.www import WWWAddressHandler
from tests import util


@pytest.fixture
def url_value() -> str:
    return "http://www.test.org/"


async def test_from_effect(url_value):
    # Arrange
    effect = {"relationer": {"adresser": [{"urn": f"urn:magenta.dk:www:{url_value}"}]}}

    address_handler = await WWWAddressHandler.from_effect(effect)

    # Act
    actual_value = address_handler.value

    # Assert
    assert url_value == actual_value


async def test_from_request(url_value):
    # Arrange
    request = {"value": url_value}
    address_handler = await WWWAddressHandler.from_request(request)

    # Act
    actual_value = address_handler.value

    # Assert
    assert url_value == actual_value


async def test_get_mo_address(url_value):
    # Arrange
    async def async_facet_get_one_class(x, y, *args, **kwargs):
        return {"uuid": y}

    visibility = "dd5699af-b233-44ef-9107-7a37016b2ed1"
    address_handler = WWWAddressHandler(url_value, visibility)

    expected = {
        "href": None,
        "name": "http://www.test.org/",
        "value": "http://www.test.org/",
        "value2": None,
        "visibility": {"uuid": "dd5699af-b233-44ef-9107-7a37016b2ed1"},
    }

    # Act
    with patch("mora.service.facet.get_one_class", new=async_facet_get_one_class):
        actual = await address_handler.get_mo_address_and_properties()

        # Assert
        assert expected == actual


def test_get_lora_address(url_value):
    # Arrange
    address_handler = WWWAddressHandler(url_value, None)

    expected = {
        "objekttype": "WWW",
        "urn": "urn:magenta.dk:www:http://www.test.org/",
    }

    # Act
    actual = address_handler.get_lora_address()

    # Assert
    assert expected == actual


async def test_validation_fails_on_invalid_value():
    # Arrange
    value = "@$@#$@#$"  # Not a valid URL

    # Act & Assert
    with pytest.raises(exceptions.HTTPException):
        await WWWAddressHandler.validate_value(value)


async def test_validation_succeeds_on_correct_values():
    # Arrange
    valid_values = [
        "http://www.test.com",
        "https://www.test.com",
        "http://subdomain.hej.com/welcome/to/test.html",
    ]

    # Act & Assert
    for value in valid_values:
        # Shouldn't raise exception
        await WWWAddressHandler.validate_value(value)


async def test_validation_succeeds_with_force():
    # Arrange
    value = "GARBAGEGARBAGE"  # Not a valid URL

    # Act & Assert
    with util.patch_query_args({"force": "1"}):
        await WWWAddressHandler.validate_value(value)
