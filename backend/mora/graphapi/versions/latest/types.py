# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import datetime
import json
from base64 import b64decode
from base64 import b64encode
from textwrap import dedent
from uuid import UUID
from uuid import uuid4

import strawberry
from pydantic import BaseModel
from pydantic import Field

from mora.util import CPR

# https://strawberry.rocks/docs/integrations/pydantic#classes-with-__get_validators__
CPRType = strawberry.scalar(
    CPR,
    serialize=str,
    parse_value=CPR.validate,
    description=dedent(
        """\
        Scalar implementing the danish national identification number / civil registration number.

        The number is a unique identifier for a single individual, although individuals may go through several numbers over time.

        The number is expected to have 10 digits, 6 digits defining a date, and a 4 digit serial number.
        The number does not have to fulfill the modulo 11 checksum.
        It does however (optionally) have to define a valid date.
        No dash should be included to separate the date and serial number sections.

        For further details refer to the Central Person Register (CPR) at:
        * https://cpr.dk/

        Or "Bekendtgørelse af lov om Det Centrale Personregister" ("CPR-Loven"):
        * https://www.retsinformation.dk/eli/lta/2017/646

        Examples:
        * `"0106875049"`
        * `"0106878994"`
        * `"406568970"`
        """
    ),
)


class _Cursor(BaseModel):
    offset: int
    registration_time: datetime.datetime

    # The purpose of this field is solely to make cursors look different
    # Prior to adding this field cursors would look similar, even if they were different
    randomization_uuid: UUID = Field(default_factory=uuid4)


Cursor = strawberry.scalar(
    _Cursor,
    serialize=lambda v: b64encode(v.json().encode("ascii")).decode("ascii"),
    parse_value=lambda v: _Cursor(**json.loads(b64decode(v))),
    description=dedent(
        """\
        Scalar implementing the cursor of cursor-based pagination.

        The cursor is opaque by design abstracting away the underlying implementation details.

        Examples:
        * `"Njk="`
        * `"NDIw"`
        * `"MTMzNw=="`

        Note:

        As the cursor is to be considered opaque its implementation may change in the future.
        I.e. in the future it may be implemented as a simple integer or a complex object.

        The caller should not concern themselves with the actual value contained within, but rather simply pass whatever is returned in the `cursor` argument to continue iteration.
        """
    ),
)
