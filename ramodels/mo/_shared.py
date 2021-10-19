#!/usr/bin/env python3
# --------------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2021 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
from datetime import datetime
from typing import Any
from typing import Dict
from typing import Optional
from uuid import UUID
from uuid import uuid4

from pydantic import Field
from pydantic import root_validator
from pydantic import validator

from ramodels.base import RABase
from ramodels.base import tz_isodate

try:
    import zoneinfo
except ImportError:  # pragma: no cover
    from backports import zoneinfo  # type: ignore

UTC = zoneinfo.ZoneInfo("UTC")

# --------------------------------------------------------------------------------------
# MOBase
# --------------------------------------------------------------------------------------


class MOBase(RABase):
    """Base model for MO data models."""

    def __new__(cls, *args: Any, **kwargs: Any) -> Any:
        if cls is MOBase:
            raise TypeError("MOBase may not be instantiated")
        return super().__new__(cls)

    uuid: UUID = Field(
        None, description="UUID to be created. Will be autogenerated if not specified."
    )

    # Autogenerate UUID if necessary
    @validator("uuid", pre=True, always=True)
    def set_uuid(cls, _uuid: Optional[UUID]) -> UUID:
        return _uuid or uuid4()


# --------------------------------------------------------------------------------------
# Shared models
# --------------------------------------------------------------------------------------


class MORef(RABase):
    """
    Reference base.
    """

    uuid: UUID = Field(description="The UUID of the reference.")


class AddressType(MORef):
    """Address type reference."""

    pass


class EngagementAssociationType(MORef):
    """Engagement Association type reference."""

    pass


class EngagementRef(MORef):
    """Engagement reference."""

    pass


class EngagementType(MORef):
    """Engagement type reference."""

    pass


class AssociationType(MORef):
    """Association type reference."""

    pass


class ITSystemRef(MORef):
    """IT System reference."""

    pass


class JobFunction(MORef):
    """Job function reference."""

    pass


class LeaveType(MORef):
    """Leave type reference."""

    pass


class ManagerLevel(MORef):
    """Manager level reference."""

    pass


class ManagerType(MORef):
    """Manager type reference."""

    pass


class OrganisationRef(MORef):
    """Organisation reference."""

    pass


class OrgUnitHierarchy(MORef):
    """Organisation unit hierarchy reference."""

    pass


class OrgUnitLevel(MORef):
    """Organisation unit level reference."""

    pass


class OrgUnitRef(MORef):
    """Organisation unit reference."""

    pass


class OrgUnitType(MORef):
    """Organisation unit type."""

    pass


class ParentRef(MORef):
    """Parent reference."""

    pass


class PersonRef(MORef):
    """Person reference."""

    pass


class Primary(MORef):
    """Primary type reference."""

    pass


class Responsibility(MORef):
    """Responsibility type reference."""

    pass


class RoleType(MORef):
    """Role type reference."""

    pass


class Validity(RABase):
    """Validity of a MO object."""

    from_date: datetime = Field(alias="from", description="Start date of the validity.")
    to_date: Optional[datetime] = Field(
        alias="to", description="End date of the validity, if applicable."
    )

    @validator("from_date", pre=True, always=True)
    def parse_from_date(cls, from_date: Any) -> datetime:
        return tz_isodate(from_date)

    @validator("to_date", pre=True, always=True)
    def parse_to_date(cls, to_date: Optional[Any]) -> Optional[datetime]:
        return tz_isodate(to_date) if to_date is not None else None

    @root_validator
    def check_from_leq_to(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        # Note: the values of from_date & to_date are not changed here
        # just leq compared.
        cmp_from_dt, _to_dt = values.get("from_date"), values.get("to_date")
        cmp_to_dt = _to_dt if _to_dt else datetime.max.replace(tzinfo=UTC)
        if all([cmp_from_dt, cmp_to_dt]) and not (cmp_from_dt <= cmp_to_dt):
            raise ValueError("from_date must be less than or equal to to_date")
        return values


class Visibility(MORef):
    """Visbility type reference."""

    pass
