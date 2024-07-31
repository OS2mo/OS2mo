# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from pydantic.v1 import EmailStr
from pydantic.v1 import parse_obj_as
from pydantic.v1 import ValidationError

from . import base
from ... import exceptions
from ..validation.validator import forceable


class EmailAddressHandler(base.AddressHandler):
    scope = "EMAIL"
    prefix = "urn:mailto:"

    @property
    def href(self):
        return f"mailto:{self.value}"

    @staticmethod
    @forceable
    async def validate_value(value):
        """Ensure that value is correct email"""
        try:
            parse_obj_as(EmailStr, value)
        except ValidationError:
            exceptions.ErrorCodes.V_INVALID_ADDRESS_EMAIL(
                value=value,
            )
