# SPDX-FileCopyrightText: 2022 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import pytest

from mora.exceptions import HTTPException
from mora.service.itsystem import ItsystemRequestHandler
from mora.service.itsystem import ITUserGroupValidation


class TestITUserGroupValidation:
    def test_validation(self):
        obj = {
            "employee_uuid": "uuid",
            "it_system_uuid": "uuid",
            "it_user_username": "uuid",
        }
        validation = ITUserGroupValidation([obj])
        with pytest.raises(HTTPException):
            validation.validate(obj)


class TestITSystemRequestHandlerValidation:
    def test_get_group_validation(self):
        validation = ItsystemRequestHandler.get_group_validation([])
        assert isinstance(validation, ITUserGroupValidation)
        assert validation.validation_items == []
