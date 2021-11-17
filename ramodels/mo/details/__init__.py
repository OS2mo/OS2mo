#!/usr/bin/env python3
# --------------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2021 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
from typing import Union

from .address import Address
from .association import Association
from .association import AssociationBase
from .association import AssociationRead
from .association import AssociationWrite
from .engagement import Engagement
from .engagement import EngagementAssociation
from .it_system import ITSystemBinding
from .leave import Leave
from .manager import Manager
from .role import Role

# --------------------------------------------------------------------------------------
# All
# --------------------------------------------------------------------------------------
Details = Union[
    Association, Engagement, EngagementAssociation, Manager, ITSystemBinding, Role
]
EmployeeDetails = Union[Details, Address, Leave]
OrgUnitDetails = Details

__all__ = [
    "EmployeeDetails",
    "OrgUnitDetails",
    "Address",
    "Association",
    "AssociationBase",
    "AssociationRead",
    "AssociationWrite",
    "Engagement",
    "EngagementAssociation",
    "ITSystemBinding",
    "Manager",
    "Role",
    "Leave",
]
