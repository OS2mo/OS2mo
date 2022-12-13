# SPDX-FileCopyrightText: 2021 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
"""GraphQL engagement related helper functions."""
from uuid import UUID

from .models import EngagementCreate
from .models import EngagementTerminate
from .models import EngagementUpdate
from .types import UUIDReturn
from mora import lora
from mora import mapping
from mora.service.engagement import EngagementRequestHandler
from mora.triggers import Trigger


async def terminate_engagement(input: EngagementTerminate) -> UUIDReturn:
    trigger = input.get_engagement_trigger()
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

    return UUIDReturn(uuid=UUID(lora_result))


async def create_engagement(input: EngagementCreate) -> UUIDReturn:
    input_dict = input.to_handler_dict()

    handler = await EngagementRequestHandler.construct(
        input_dict, mapping.RequestType.CREATE
    )
    uuid = await handler.submit()

    return UUIDReturn(uuid=UUID(uuid))


async def update_engagement(input: EngagementUpdate) -> UUIDReturn:
    input_dict = input.to_handler_dict()

    req = {
        mapping.TYPE: mapping.ENGAGEMENT,
        mapping.UUID: str(input.uuid),
        mapping.DATA: input_dict,
    }

    request = await EngagementRequestHandler.construct(req, mapping.RequestType.EDIT)
    uuid = await request.submit()

    return UUIDReturn(uuid=UUID(uuid))
