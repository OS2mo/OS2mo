#!/usr/bin/env python3
# --------------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2021 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
from typing import List
from uuid import UUID

from pydantic import Field

from .._shared import MOBase
from .._shared import OrgUnitRef
from .._shared import Validity

# --------------------------------------------------------------------------------------
# Engagement models
# --------------------------------------------------------------------------------------


class RelatedUnitBase(MOBase):
    """A MO relatedUnit object."""

    type_: str = Field("related_unit", alias="type", description="The object type.")
    validity: Validity = Field(description="Validity of the relatedUnit object.")


class RelatedUnitRead(RelatedUnitBase):
    """A MO RelatedUnitRead object."""

    org_unit: List[UUID] = Field(description="UUIDs of the related organisation units.")


class RelatedUnitWrite(RelatedUnitBase):
    """A MO RelatedUnitWrite object."""

    org_unit: List[OrgUnitRef] = Field(
        description="List of references of the related the organisation units."
    )
