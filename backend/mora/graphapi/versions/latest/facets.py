# SPDX-FileCopyrightText: 2022 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import asyncio
from uuid import UUID

from .models import FacetCreate
from .models import FacetTerminate
from .models import FacetUpdate
from mora import lora
from oio_rest import db


async def create_facet(input: FacetCreate, organisation_uuid: UUID) -> UUID:
    # Construct a LoRa registration object from our input arguments
    registration = input.to_registration(organisation_uuid=organisation_uuid)
    # Let LoRa's SQL templates do their magic
    uuid = await asyncio.to_thread(
        db.create_or_import_object, "facet", "", registration
    )
    return uuid


async def update_facet(input: FacetUpdate, organisation_uuid: UUID) -> UUID:
    exists = await asyncio.to_thread(db.object_exists, "facet", str(input.uuid))
    if not exists:
        raise ValueError("Cannot update a non-existent object")

    # Construct a LoRa registration object from our input arguments
    registration = input.to_registration(organisation_uuid=organisation_uuid)

    # Let LoRa's SQL templates do their magic
    life_cycle_code = await asyncio.to_thread(
        db.get_life_cycle_code, "facet", str(input.uuid)
    )
    if life_cycle_code in (db.Livscyklus.SLETTET.value, db.Livscyklus.PASSIVERET.value):
        # Reactivate and update
        uuid = await asyncio.to_thread(
            db.update_object,
            "facet",
            "",
            registration,
            uuid=str(input.uuid),
            life_cycle_code=db.Livscyklus.IMPORTERET.value,
        )
    else:
        # Update
        uuid = await asyncio.to_thread(
            db.create_or_import_object,
            "facet",
            "",
            registration,
            str(input.uuid),
        )
    return uuid


async def terminate_facet(input: FacetTerminate) -> UUID:
    await lora.Connector().facet.update(input.to_registration(), input.uuid)
    return input.uuid


async def delete_facet(facet_uuid: UUID) -> UUID:
    # Gather a blank registration
    registration: dict = {
        "states": {},
        "attributes": {},
        "relations": {},
    }
    # Let LoRa's SQL templates do their magic
    await asyncio.to_thread(
        db.delete_object, "facet", registration, "", str(facet_uuid)
    )
    return facet_uuid
