#!/usr/bin/env python3
# --------------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2021 - 2022 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
import datetime

from ramodels.mo.employee import EmployeeTerminate
from ramodels.mo.employee import EmployeeTerminate as RaModelEmployeeTerminate
from ramodels.mo.employee import OpenValidity

from mora import common
from mora import lora
from mora import mapping
from mora import util
from mora.graphapi.employee import termination_handlers
from mora.graphapi.models import EmployeeTermination
from mora.graphapi.models import EmployeeTrigger
from mora.graphapi.models import MoraTriggerRequest
from mora.graphapi.models import Validity
from mora.graphapi.types import EmployeeType
from mora.service import handlers
from mora.triggers import Trigger


async def terminate_employee(e_termination: EmployeeTermination) -> EmployeeType:
    """Termination handler for employee."""
    uuid = str(e_termination.uuid)
    ramodel = RaModelEmployeeTerminate(
        validity=OpenValidity(
            from_date=e_termination.from_date, to_date=e_termination.to_date
        )
    )

    date = e_termination.get_terminate_effect_to_date()
    if e_termination.from_date and e_termination.to_date:
        date = e_termination.get_terminate_effect_from_date()

    terminate_request_dict = _create_request_dict_from_e_terminate(ramodel)
    c = lora.Connector(effective_date=date, virkningtil="infinity")

    terminate_handlers = await _get_employee_terminate_methods(
        e_termination, date, terminate_request_dict
    )

    request_handlers = [
        await handlers.get_handler_for_function(obj).construct(
            {
                "uuid": objid,
                "vacate": util.checked_get(terminate_request_dict, "vacate", False),
                "validity": {
                    "to": util.to_iso_date(
                        # we also want to handle _future_ relations
                        max(date, min(map(util.get_effect_from, util.get_states(obj)))),
                        is_end=True,
                    ),
                },
            },
            mapping.RequestType.TERMINATE,
        )
        for objid, obj in await c.organisationfunktion.get_all(
            tilknyttedebrugere=uuid,
            gyldighed="Aktiv",
        )
    ]

    employee_trigger = EmployeeTrigger(
        employee_uuid=e_termination.uuid,
        request_type=mapping.RequestType.TERMINATE,
        request=MoraTriggerRequest(
            type=mapping.ORG_UNIT,
            uuid=e_termination.uuid,
            validity=Validity(
                from_date=e_termination.from_date,
                to_date=e_termination.to_date,
            ),
        ),
        role_type=mapping.ORG_UNIT,
        event_type=mapping.EventType.ON_BEFORE,
        uuid=e_termination.uuid,
    )

    trigger_dict = employee_trigger.to_trigger_dict()

    if not e_termination.triggerless:
        await Trigger.run(trigger_dict)

    for handler in request_handlers:
        await handler.submit()

    result = uuid

    trigger_dict[Trigger.EVENT_TYPE] = mapping.EventType.ON_AFTER
    trigger_dict[Trigger.RESULT] = result

    if not e_termination.triggerless:
        await Trigger.run(trigger_dict)

    # Write a noop entry to the user, to be used for the history
    await common.add_history_entry(c.bruger, uuid, "Afslut medarbejder")

    return EmployeeType(uuid=result)


# PRIVATE methods for this module.


def _create_request_dict_from_e_terminate(
    employee_terminate: EmployeeTerminate,
) -> dict:
    request_dict = employee_terminate.dict(by_alias=True)
    if employee_terminate.validity.from_date:
        request_dict[mapping.VALIDITY][
            mapping.FROM
        ] = employee_terminate.validity.from_date.strftime("%Y-%m-%d")
    else:
        del request_dict[mapping.VALIDITY][mapping.FROM]

    if employee_terminate.validity.to_date:
        request_dict[mapping.VALIDITY][
            mapping.TO
        ] = employee_terminate.validity.to_date.strftime("%Y-%m-%d")
    else:
        del request_dict[mapping.VALIDITY][mapping.TO]

    return request_dict


async def _get_employee_terminate_methods(
    e_termination: EmployeeTermination, date: datetime.datetime, request_dict: dict
):
    c = lora.Connector(effective_date=date, virkningtil="infinity")
    org_functions = await c.organisationfunktion.get_all(
        tilknyttedebrugere=e_termination.uuid, gyldighed="Aktiv"
    )

    handlers = []
    for objid, obj in org_functions:
        obj_function_key = ""
        (key,) = {
            attrs["funktionsnavn"] for attrs in mapping.ORG_FUNK_EGENSKABER_FIELD(obj)
        }

        # Find termination handler for this org-function
        org_func_term_handler = termination_handlers.HANDLERS_BY_FUNCTION_KEY.get(
            obj_function_key, None
        )

        if not org_func_term_handler:
            continue

        # Create termination object for org-function
        termination_obj = {
            "uuid": objid,
            "vacate": util.checked_get(request_dict, "vacate", False),
            "validity": {
                "to": util.to_iso_date(
                    # we also want to handle _future_ relations
                    max(date, min(map(util.get_effect_from, util.get_states(obj)))),
                    is_end=True,
                ),
            },
        }

        handlers.append(
            (
                termination_handlers.HANDLERS_BY_FUNCTION_KEY.get(obj_function_key),
                termination_obj,
            )
        )

    tap = "test"


def get_key_for_function(obj: dict) -> str:
    """Obtain the function key class corresponding to the given LoRA object"""

    # use unpacking to ensure that the set contains just one element
    (key,) = {
        attrs["funktionsnavn"] for attrs in mapping.ORG_FUNK_EGENSKABER_FIELD(obj)
    }

    return key
