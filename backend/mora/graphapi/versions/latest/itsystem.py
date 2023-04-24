# SPDX-FileCopyrightText: 2022 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import asyncio
from datetime import datetime
from uuid import UUID

import strawberry
from pydantic import BaseModel
from pydantic import Extra
from pydantic import Field

from mora.util import to_lora_time
from oio_rest import db
from oio_rest import validate


class ITSystemCreate(BaseModel):
    """Model representing an itsystem creation."""

    class Config:
        frozen = True
        allow_population_by_field_name = True
        extra = Extra.forbid

    user_key: str
    name: str
    from_date: datetime | None = Field(
        None, alias="from", description="Start date of the validity."
    )
    to_date: datetime | None = Field(
        None, alias="to", description="End date of the validity, if applicable."
    )

    def to_registration(self, organisation_uuid: UUID) -> dict:
        from_time = to_lora_time(self.from_date or "-infinity")
        to_time = to_lora_time(self.to_date or "infinity")

        input = {
            "attributter": {
                "itsystemegenskaber": [
                    {
                        "brugervendtnoegle": self.user_key,
                        "virkning": {
                            "from": from_time,
                            "to": to_time,
                        },
                        "itsystemnavn": self.name,
                    }
                ]
            },
            "tilstande": {
                "itsystemgyldighed": [
                    {
                        "gyldighed": "Aktiv",
                        "virkning": {
                            "from": from_time,
                            "to": to_time,
                        },
                    }
                ]
            },
            "relationer": {
                "tilknyttedeorganisationer": [
                    {
                        "uuid": str(organisation_uuid),
                        "virkning": {
                            "from": from_time,
                            "to": to_time,
                        },
                    }
                ],
            },
        }
        validate.validate(input, "itsystem")
        return {
            "states": input["tilstande"],
            "attributes": input["attributter"],
            "relations": input["relationer"],
        }


@strawberry.experimental.pydantic.input(
    model=ITSystemCreate,
    all_fields=True,
)
class ITSystemCreateInput:
    """input model for creating itsystems."""


async def create_itsystem(
    input: ITSystemCreate, organisation_uuid: UUID, note: str
) -> UUID:
    # Construct a LoRa registration object from our input arguments
    registration = input.to_registration(organisation_uuid=organisation_uuid)
    # Let LoRa's SQL templates do their magic
    uuid = await asyncio.to_thread(
        db.create_or_import_object, "itsystem", note, registration
    )
    return uuid


async def update_itsystem(
    input: ITSystemCreate, itsystem_uuid: UUID, organisation_uuid: UUID, note: str
) -> UUID:
    exists = await asyncio.to_thread(db.object_exists, "itsystem", str(itsystem_uuid))
    if not exists:
        raise ValueError("Cannot update a non-existent object")

    # Construct a LoRa registration object from our input arguments
    lifecycle_code = await asyncio.to_thread(
        db.get_life_cycle_code, "itsystem", str(itsystem_uuid)
    )

    # Let LoRa's SQL templates do their magic
    registration = input.to_registration(organisation_uuid=organisation_uuid)
    if lifecycle_code in (db.Livscyklus.SLETTET.value, db.Livscyklus.PASSIVERET.value):
        # Reactivate and update
        uuid = await asyncio.to_thread(
            db.update_object,
            "itsystem",
            note,
            registration,
            uuid=str(itsystem_uuid),
            life_cycle_code=db.Livscyklus.IMPORTERET.value,
        )
    else:
        # Update
        uuid = await asyncio.to_thread(
            db.create_or_import_object,
            "itsystem",
            note,
            registration,
            str(itsystem_uuid),
        )
    return uuid


async def delete_itsystem(itsystem_uuid: UUID, note: str) -> UUID:
    # Gather a blank registration
    registration: dict[str, dict] = {
        "states": {},
        "attributes": {},
        "relations": {},
    }
    # Let LoRa's SQL templates do their magic
    await asyncio.to_thread(
        db.delete_object, "itsystem", registration, note, str(itsystem_uuid)
    )
    return itsystem_uuid
