# SPDX-FileCopyrightText: 2021 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import datetime
from uuid import UUID

from .models import AddressTerminate
from .types import AddressTerminateType
from mora import exceptions
from mora import lora
from mora import mapping
from mora.triggers import Trigger


async def terminate_addr(address_terminate: AddressTerminate) -> AddressTerminateType:
    original_addr = await _get_original_addr(
        address_terminate.uuid, address_terminate.from_date
    )
    if not original_addr:
        exceptions.ErrorCodes.E_NOT_FOUND(
            uuid=str(address_terminate.uuid),
            original=original_addr,
        )

    address_trigger = address_terminate.get_address_trigger()
    trigger_dict = address_trigger.to_trigger_dict()

    # ON_BEFORE
    if not address_terminate.triggerless:
        _ = await Trigger.run(trigger_dict)

    # Do LoRa update
    lora_conn = lora.Connector()
    lora_result = await lora_conn.organisationfunktion.update(
        address_terminate.get_lora_payload(), str(address_terminate.uuid)
    )

    # ON_AFTER
    trigger_dict.update(
        {
            Trigger.RESULT: lora_result,
            Trigger.EVENT_TYPE: mapping.EventType.ON_AFTER,
        }
    )

    if not address_terminate.triggerless:
        _ = await Trigger.run(trigger_dict)

    return AddressTerminateType(uuid=UUID(lora_result))


async def _get_original_addr(
    addr_uuid: UUID, from_date: datetime.datetime | None
) -> dict | None:
    original = await lora.Connector(effective_date=from_date).organisationfunktion.get(
        str(addr_uuid)
    )

    return original
