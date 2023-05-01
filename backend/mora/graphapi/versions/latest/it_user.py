# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from uuid import UUID

from .models import ITUserCreate
from .models import ITUserTerminate
from .models import ITUserUpdate
from mora import lora
from mora import mapping
from mora.service.itsystem import ItsystemRequestHandler
from mora.triggers import Trigger


async def create(input: ITUserCreate) -> UUID:
    input_dict = input.to_handler_dict()

    handler = await ItsystemRequestHandler.construct(
        input_dict, mapping.RequestType.CREATE
    )
    uuid = await handler.submit()

    return UUID(uuid)


async def terminate(input: ITUserTerminate) -> UUID:
    trigger = input.get_trigger()
    trigger_dict = trigger.to_trigger_dict()

    # ON_BEFORE
    _ = await Trigger.run(trigger_dict)

    # Do LoRa update
    lora_conn = lora.Connector()
    lora_result = await lora_conn.organisationfunktion.update(
        input.get_lora_payload(), str(input.uuid)
    )

    # ON_AFTER
    trigger_dict.update(
        {
            Trigger.RESULT: lora_result,
            Trigger.EVENT_TYPE: mapping.EventType.ON_AFTER,
        }
    )

    _ = await Trigger.run(trigger_dict)

    return UUID(lora_result)


async def update(input: ITUserUpdate) -> UUID:
    input_dict = input.to_handler_dict()

    req = {
        mapping.TYPE: mapping.IT,
        mapping.UUID: str(input.uuid),
        mapping.DATA: input_dict,
    }

    request = await ItsystemRequestHandler.construct(req, mapping.RequestType.EDIT)
    uuid = await request.submit()

    return UUID(uuid)
