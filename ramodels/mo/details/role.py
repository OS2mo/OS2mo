#!/usr/bin/env python3
# --------------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2021 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
from typing import Literal
from uuid import UUID

from pydantic import Field

from .._shared import MOBase
from .._shared import OrgUnitRef
from .._shared import PersonRef
from .._shared import RoleType
from .._shared import Validity

# --------------------------------------------------------------------------------------
# Role
# --------------------------------------------------------------------------------------


class RoleBase(MOBase):
    """A MO role object."""

    type_: str = Field("role", alias="type", description="The object type.")
    validity: Validity = Field(description="Validity of the role object.")


class RoleRead(RoleBase):
    """A MO role read object."""

    org_unit_uuid: UUID = Field(
        description="UUID of the organisation unit related to the association."
    )
    person_uuid: UUID = Field(description="UUID of the person related to the role.")
    role_type_uuid: UUID = Field(description="UUID of the role type klasse.")


class RoleWrite(RoleBase):
    """A MO role write object."""

    org_unit: OrgUnitRef = Field(
        description="Reference to the organisation unit for the role."
    )
    person: PersonRef = Field(
        description="Reference to the person for which the role should be created."
    )
    role_type: RoleType = Field(description="Reference to the role type klasse.")


class Role(MOBase):
    type_: Literal["role"] = Field("role", alias="type", description="The object type.")
    role_type: RoleType = Field(description="Reference to the role type facet")
    person: PersonRef = Field(
        description="Reference to the person object for which the role should "
        "be created."
    )
    org_unit: OrgUnitRef = Field(
        description="Reference to the organisation unit for which the role should "
        "be created."
    )
    validity: Validity = Field(description="Validity of the created role object.")
