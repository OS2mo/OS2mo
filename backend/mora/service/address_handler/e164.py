# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import phonenumbers

from . import base
from ... import exceptions
from ...config import get_settings


def _parse_phonenumber(value: str) -> phonenumbers.PhoneNumber:
    settings = get_settings()
    try:
        # Parsing may fail due to missing/invalid region or from invalid characters
        return phonenumbers.parse(value, settings.phonenumber_default_region_code)
    except phonenumbers.phonenumberutil.NumberParseException as e:
        exceptions.ErrorCodes.V_INVALID_ADDRESS_PHONE(
            detail="Unable to parse phone number: " + str(e), value=value
        )


class E164AddressHandler(base.AddressHandler):
    scope = "E164"
    prefix = "urn:magenta.dk:e164:"

    def __init__(self, value: str, visibility, value2: str | None = None) -> None:
        self.visibility = visibility

        assert value2 is None
        self._value2 = None

        pn = _parse_phonenumber(value)
        self._value = phonenumbers.format_number(
            pn, phonenumbers.PhoneNumberFormat.E164
        )

    # TODO: We may have to overload the 'urn' method to handle characters outside of
    #       RFC3986 Section 2, especially if we wish to support Egyptian phone-numbers
    #       as these use native digits instead of ASCII digits.
    #       The overload should probably just percent-encode the value.
    # TODO: Should we always percent-encode the values in the URN to ensure compliance
    #       with RFC3986 Section 2?

    @property
    def href(self) -> str:
        # Returns the phone number in accordance with RFC3966 Section 5.1 Global Form
        # The RFC states that Global Form SHOULD be used whenever possible.
        # Note: This decision means we cannot support private numbering plans,
        #       emergency numbers ("911", "112"), directory-assistence numbers and other
        #       "service codes" as these cannot be represented in global (E.164) form.
        #       Should we need to support these, we need local form with phone-context.
        #       See RFC3966 Section 5.1.5 for details should this be required.
        return f"tel:{self._value}"

    @property
    def name(self) -> str:
        # TODO: Would we rather have name return the localized format?
        pn = _parse_phonenumber(self.value)
        return phonenumbers.format_number(
            pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        )

    @staticmethod
    async def validate_value(value) -> None:
        # Parsing may raise an exception related to format errors
        pn = _parse_phonenumber(value)
        # A possible number has the right number of digits, etc
        if phonenumbers.is_possible_number(pn) is False:
            exceptions.ErrorCodes.V_INVALID_ADDRESS_PHONE(
                detail="Impossible phonenumber", value=value
            )
        # A valid number is within an allocated block of numbers
        if phonenumbers.is_valid_number(pn) is False:
            exceptions.ErrorCodes.V_INVALID_ADDRESS_PHONE(
                detail="Invalid phonenumber", value=value
            )
