#!/usr/bin/env python3
# --------------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2021 - 2022 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
import datetime
import logging
import typing
from enum import Enum
from typing import Optional
from uuid import UUID

import strawberry
from pydantic import BaseModel
from pydantic import Field
from ramodels.mo import OpenValidity
from ramodels.mo._shared import UUIDBase

from mora import common
from mora import exceptions
from mora.util import ONE_DAY
from mora.util import POSITIVE_INFINITY

logger = logging.getLogger(__name__)
from ramodels.mo._shared import MOBase

# --------------------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------------------


@strawberry.enum
class FileStore(Enum):
    EXPORTS = 1
    INSIGHTS = 2


class HealthRead(BaseModel):
    """Payload model for health."""

    identifier: str = Field(description="Short, unique key.")


class FileRead(BaseModel):
    """Payload model for file download."""

    file_store: FileStore = Field(description="The file store the file is stored in.")
    file_name: str = Field(description="Name of the export file.")


class OrganisationUnitRefreshRead(BaseModel):
    """Payload model for organisation unit refresh mutation."""

    message: str = Field(description="Refresh message containing trigger responses.")


class ConfigurationRead(BaseModel):
    """Payload model for configuration."""

    key: str = Field(description="Settings key.")


class Validity(OpenValidity):
    """Model representing an entities validity range."""

    # from_date: Optional[datetime.datetime] = Field(
    #     alias="from", description="Start date of the validity."
    # )
    #
    # to_date: Optional[datetime.datetime] = Field(
    #     alias="to", description="End date of the validity, if applicable."
    # )

    class Config:
        allow_population_by_field_name = True
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


class MoraTriggerRequest(BaseModel):
    """Model representing a MoRa Trigger Request."""

    type: str = Field(description="Type of the request, ex. 'org_unit'.")

    uuid: UUID = Field(
        description="UUID for the entity accessed in the request. "
        "Ex type=ORG_UNIT, then this UUID will be the UUID of the ORG_UNIT"
    )

    validity: Validity = Field(description="Type of the request, ex. 'org_unit'.")


class MoraTrigger(BaseModel):
    """Model representing a MoRa Trigger."""

    request_type: str = Field(
        description="Request type to do, ex CREATE, EDIT, TERMINATE or REFRESH. "
        "Ref: mora.mapping.RequestType"
    )

    request: MoraTriggerRequest = Field(description="The Request for the trigger.")

    role_type: str = Field(description="Role type for the trigger, ex 'org_unit'.")

    event_type: str = Field(
        description="Trigger event-type. " "Ref: mora.mapping.EventType"
    )

    uuid: UUID = Field(
        description="UUID of the entity being handled in the trigger. "
        "Ex. type=ORG_UNIT, this this is the org-unit-uuid."
    )

    result: typing.Any = Field(description="Result of the trigger", default=None)

    def to_trigger_dict(self) -> dict:
        trigger_dict = self.dict(by_alias=True)
        return MoraTrigger.convert_trigger_dict_fields(trigger_dict)

    @staticmethod
    def convert_trigger_dict_fields(trigger_dict: dict) -> dict:
        for key in trigger_dict.keys():
            if isinstance(trigger_dict[key], dict):
                trigger_dict[key] = MoraTrigger.convert_trigger_dict_fields(
                    trigger_dict[key]
                )
                continue

            if isinstance(trigger_dict[key], UUID):
                trigger_dict[key] = str(trigger_dict[key])
                continue

            if isinstance(trigger_dict[key], datetime.datetime):
                trigger_dict[key] = trigger_dict[key].isoformat()
                continue

        return trigger_dict


class MoraTriggerOrgUnit(MoraTrigger):
    """Model representing a mora-trigger, specific for organization-units."""

    org_unit_uuid: UUID = Field(
        description="UUID for the organization unit in question."
    )


class OrganisationUnit(UUIDBase):
    """Model representing a Organization-Unit."""

    pass


class OrganisationUnitTerminate(OrganisationUnit, OpenValidity):
    """Model representing a organization-unit termination."""

    triggerless: Optional[bool] = Field(
        description="Flag specifying if triggers should not be invoked, if true.",
        default=False,
    )

    def get_lora_payload(self) -> dict:
        return {
            "tilstande": {
                "organisationenhedgyldighed": [
                    {"gyldighed": "Inaktiv", "virkning": self.get_termination_effect()}
                ]
            },
            "note": "Afslut enhed",
        }

    def get_termination_effect(self) -> dict:
        if self.from_date and self.to_date:
            return common._create_virkning(
                self.get_terminate_effect_from_date(),
                self.get_terminate_effect_to_date(),
            )

        if not self.from_date and self.to_date:
            logger.warning(
                'terminate org unit called without "from" in "validity"',
            )
            return common._create_virkning(
                self.get_terminate_effect_to_date(), "infinity"
            )

        raise exceptions.ErrorCodes.V_MISSING_REQUIRED_VALUE(
            key="Organization Unit must be set with either 'to' or both 'from' "
            "and 'to'",
            unit={
                "from": self.from_date.isoformat() if self.from_date else None,
                "to": self.to_date.isoformat() if self.to_date else None,
            },
        )

    def get_terminate_effect_from_date(self) -> datetime.datetime:
        if not self.from_date or not isinstance(self.from_date, datetime.datetime):
            raise exceptions.ErrorCodes.V_MISSING_START_DATE()

        if self.from_date.time() != datetime.time.min:
            exceptions.ErrorCodes.E_INVALID_INPUT(
                "{!r} is not at midnight!".format(self.from_date.isoformat()),
            )

        return self.from_date

    def get_terminate_effect_to_date(self) -> datetime.datetime:
        if not self.to_date:
            return POSITIVE_INFINITY

        if self.to_date.time() != datetime.time.min:
            exceptions.ErrorCodes.E_INVALID_INPUT(
                "{!r} is not at midnight!".format(self.to_date.isoformat()),
            )

        return self.to_date + ONE_DAY
class ITSystemBase(MOBase):
    """A MO IT-system base object."""

    type_: str = Field("itsystem", alias="type", description="The object type")


class ITSystemWrite(ITSystemBase):
    """A MO IT-system write object."""

    name: str = Field(description="Name/titel of the itsystem.")
    user_key: str = Field(description="Short, unique key.")
    uuid: Optional[UUID] = Field(description="The ITSystem UUID")
    system_type: Optional[str] = Field(description="The ITSystem type.")
