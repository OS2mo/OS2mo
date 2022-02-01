#!/usr/bin/env python3
# --------------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2021 - 2022 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
from typing import Optional
from uuid import UUID

from pydantic import Field

from ramodels.mo._shared import MOBase

# --------------------------------------------------------------------------------------
# Code
# --------------------------------------------------------------------------------------


class ClassRead(MOBase):
    """A MO Class read object."""

    type_: str = Field("class", alias="type", description="The object type")
    name: str = Field(description="Name/title of the class.")
    user_key: str = Field(description="Short, unique key.")
    facet_uuid: UUID = Field(description="UUID of the related facet.")
    org_uuid: UUID = Field(description="UUID of the related organisation.")
    scope: Optional[str] = Field(description="Scope of the class.")
    published: Optional[str] = Field(description="Published state of the class object.")
    parent_uuid: Optional[UUID] = Field(description="UUID of the parent class.")
