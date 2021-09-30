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
from typing import Callable
from typing import Dict
from typing import Iterator
from typing import List
from typing import Literal
from typing import Optional
from typing import Union
from uuid import UUID
from uuid import uuid4

from pydantic import Field
from pydantic import root_validator
from pydantic import validator

from ramodels.base import NEG_INF
from ramodels.base import POS_INF
from ramodels.base import RABase
from ramodels.base import tz_isodate

try:
    import zoneinfo
except ImportError:  # pragma: no cover
    from backports import zoneinfo  # type: ignore

UTC = zoneinfo.ZoneInfo("UTC")

# --------------------------------------------------------------------------------------
# LoRaBase
# --------------------------------------------------------------------------------------


class LoraBase(RABase):
    """Base model for LoRa data models.

    Attributes:
        uuid:
    """

    # TODO: This is duplicated to each class that cannot be instantiated.
    # We should probably find a better solution.
    def __new__(cls, *args: Any, **kwargs: Any) -> Any:
        if cls is LoraBase:
            raise TypeError("LoraBase may not be instantiated")
        return super().__new__(cls)

    uuid: UUID = Field(None)

    # Autogenerate UUID if necessary
    # TODO: in pydantic v2, this can be replaced with Field(default_factory=uuid4)
    # However, the beta version of default_factory is still unstable and prone to
    # side-effects.
    @validator("uuid", pre=True, always=True)
    def set_uuid(cls, _uuid: Optional[UUID]) -> UUID:
        return _uuid or uuid4()


# --------------------------------------------------------------------------------------
# Infinite Datetime
# --------------------------------------------------------------------------------------


class InfiniteDatetime(str):
    # Inspired by
    # https://pydantic-docs.helpmanual.io/usage/types/#classes-with-__get_validators__

    """Class handling InfiniteDatetimes for LoRa.

    Please note: This class is *not* meant to be instantiated directly.
    If a new object is desired, please use the from_value class method."""

    @classmethod
    def from_value(cls, value: Union[str, datetime]) -> "InfiniteDatetime":
        return cls.validate(value)

    @classmethod
    def __get_validators__(cls) -> Iterator[Callable]:
        """Magic method used by pydantic to collect validators.

        Returns:
            One (or more) validation functions, which are evaluated in order.
        """
        yield cls.validate

    @classmethod
    def validate(cls, value: Any) -> "InfiniteDatetime":
        """Validate an incoming value against InfiniteDatetime logic.

        Args:
            value: The value to validate

        Raises:
            TypeError: If the value is not a `str` or `datetime` object.
            ISOParseError: If the value cannot be parsed as either the strings
                `-infinity`, `infinity`, or an ISO-8601 datetime string.

        Returns:
            Either `-infinity`, `infinity`, or an ISO-8601 datetime string.
        """

        if not isinstance(value, (str, datetime)):
            raise TypeError("string or datetime required")

        if value in {POS_INF, NEG_INF}:
            return cls(value)

        dt = tz_isodate(value)
        return cls(dt.isoformat())

    def __repr__(self) -> str:
        return f"InfiniteDatetime({super().__repr__()})"

    def __lt__(self, other: Any) -> bool:
        # other is not explictly typed because mypy complains about LSP violations.
        """Implements the less than magic method for InfiniteDatetime.

        Args:
            other: value to compare against.
        Raises:
            TypeError: If other turns out to not be an instance of InfiniteDatetime.

        Returns:
            True if `dt(self) < dt(other)`, otherwise False.
        """
        if not isinstance(other, InfiniteDatetime):
            raise TypeError(
                f"Comparison between {type(self)} and {type(other)} not defined"
            )

        def _cast_dt(inf_dt: "InfiniteDatetime") -> datetime:
            if inf_dt == POS_INF:
                return datetime.max.replace(tzinfo=UTC)
            if inf_dt == NEG_INF:
                return datetime.min.replace(tzinfo=UTC)
            return datetime.fromisoformat(inf_dt)

        return _cast_dt(self) < _cast_dt(other)

    def __le__(self, other: Any) -> bool:
        """Implements the less than or equal to magic method for InfiniteDatetime.

        This method is defined using `__lt__` and `__eq__`.
        """
        return self.__lt__(other) or self.__eq__(other)

    def __gt__(self, other: Any) -> bool:
        """Implements the greater than magic method for InfiniteDatetime.

        This method is defined by negating `__le__`.
        """
        return not self.__le__(other)

    def __ge__(self, other: Any) -> bool:
        """Implements the less than or equal to magic method for InfiniteDatetime.

        This method is defined using `__gt__` and `__eq__`.
        """
        return self.__gt__(other) or self.__eq__(other)


# --------------------------------------------------------------------------------------
# Shared models
# --------------------------------------------------------------------------------------


class EffectiveTime(RABase):
    """
    The effective time of a given object in LoRa.
    """

    from_date: InfiniteDatetime = Field(
        alias="from", description="Start of the effective time interval."
    )
    to_date: InfiniteDatetime = Field(
        alias="to", description="End of the effective time interval."
    )

    @root_validator
    def check_from_lt_to(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        from_date, to_date = values.get("from_date"), values.get("to_date")
        # Mypy complains here about unsupported use of operators due to Nones,
        # but we catch those with if all...
        if all([from_date, to_date]) and from_date >= to_date:  # type: ignore
            raise ValueError("from_date must be strictly less than to_date")
        return values


class Authority(RABase):
    """Authority as given by URN."""

    urn: str = Field(
        regex=r"^urn:[a-z0-9][a-z0-9-]{0,31}:[a-z0-9()+,\-.:=@;$_!*'%/?#]+$",
        description="URN of the authority.",
    )
    effective_time: EffectiveTime = Field(
        alias="virkning", description="Effective time of the authority."
    )


class FacetProperties(RABase):
    """
    Properties of a given LoRa facet.
    """

    user_key: str = Field(alias="brugervendtnoegle", description="Short, unique key.")
    effective_time: EffectiveTime = Field(
        alias="virkning", description="Effective time of the property."
    )


class FacetAttributes(RABase):
    """
    Attributes of a given LoRa facet.
    """

    properties: List[FacetProperties] = Field(
        alias="facetegenskaber",
        min_items=1,
        max_items=1,
        description="The facet property denoting the attributes.",
    )


class Published(RABase):
    """
    Published state of a given object in LoRa.
    """

    # TODO: published are actually Enums in LoRa, but it's currently not possible
    # to lift them from LoRa systematically. We should definitely fix this!

    published: str = Field(
        "Publiceret",
        alias="publiceret",
        description="String representing the published status.",
    )
    effective_time: EffectiveTime = Field(
        alias="virkning", description="The effective time of the states."
    )


class FacetStates(RABase):
    """
    States of a given LoRa facet.
    """

    published_state: List[Published] = Field(
        alias="facetpubliceret",
        min_items=1,
        max_items=1,
        description="The published state of the facet.",
    )


class Responsible(RABase):
    """
    Responsible object in LoRa.
    """

    object_type: Literal["organisation"] = Field(
        "organisation", alias="objekttype", description="Object type."
    )
    uuid: UUID = Field(description="UUID of the object.")
    effective_time: EffectiveTime = Field(
        alias="virkning", description="Effective time of the object."
    )


class FacetRef(RABase):
    """
    Reference to given LoRa facets.
    """

    object_type: Literal["facet"] = Field(
        "facet", alias="objekttype", description="Object type."
    )
    uuid: UUID = Field(description="UUID of the reference.")
    effective_time: EffectiveTime = Field(
        alias="virkning", description="Effective time of the reference."
    )


class FacetRelations(RABase):
    """
    Facet relations given by responsible objects.
    """

    responsible: List[Responsible] = Field(
        alias="ansvarlig",
        min_items=1,
        max_items=1,
        description="The responsible object.",
    )


class KlasseProperties(RABase):
    """
    LoRa klasse properties.
    """

    user_key: str = Field(alias="brugervendtnoegle", description="Short, unique key.")
    title: str = Field(alias="titel", description="Title of the LoRa Klasse.")
    scope: Optional[str] = Field(
        alias="omfang", description="Scope of the LoRa Klasse."
    )
    effective_time: EffectiveTime = Field(
        alias="virkning", description="Effective time of the properties."
    )


class KlasseRelations(RABase):
    """
    Klasse relations given by responsible objects and facet references.
    """

    responsible: List[Responsible] = Field(
        alias="ansvarlig",
        min_items=1,
        max_items=1,
        description="The responsible object.",
    )
    facet: List[FacetRef] = Field(
        min_items=1, max_items=1, description="Facet reference."
    )


class KlasseAttributes(RABase):
    """
    LoRa Klasse attributes.
    """

    properties: List[KlasseProperties] = Field(
        alias="klasseegenskaber",
        min_items=1,
        max_items=1,
        description="Properties denoting the klasse attributes.",
    )


class KlasseStates(RABase):
    """
    Published state of a LoRa Klasse.
    """

    published_state: List[Published] = Field(
        alias="klassepubliceret",
        min_items=1,
        max_items=1,
        description="Published state objects. ",
    )


class OrganisationProperties(RABase):
    """
    LoRa organisation properties.
    """

    user_key: str = Field(alias="brugervendtnoegle", description="Short, unique key.")
    name: str = Field(
        alias="organisationsnavn", description="Name of the organisation."
    )
    effective_time: EffectiveTime = Field(
        alias="virkning", description="Effective time of the properties."
    )


class OrganisationAttributes(RABase):
    """
    LoRa organisation attributes.
    """

    properties: List[OrganisationProperties] = Field(
        alias="organisationegenskaber",
        min_items=1,
        max_items=1,
        description="Properties denoting the attributes.",
    )


class OrganisationValidState(RABase):
    """
    State of an organisation in LoRa.
    """

    state: str = Field(
        "Aktiv",
        alias="gyldighed",
        description="String describing the validity of an organisation.",
    )
    effective_time: EffectiveTime = Field(
        alias="virkning", description="Effective time of the valid states."
    )


class OrganisationStates(RABase):
    """
    Organisation validity as given by OrganisationValidState.
    """

    valid_state: List[OrganisationValidState] = Field(
        alias="organisationgyldighed",
        min_items=1,
        max_items=1,
        description="Valid states denoting the overall state.",
    )


class OrganisationRelations(RABase):
    """
    Organisation relations given by an authority object.
    """

    authority: List[Authority] = Field(
        alias="myndighed",
        min_items=1,
        max_items=1,
        description="Authority object denoting the relations.",
    )
