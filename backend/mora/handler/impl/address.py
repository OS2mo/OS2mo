# SPDX-FileCopyrightText: 2019-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0

import logging

from .. import reading
from ... import common
from ... import mapping
from ...service import employee
from ...service import facet
from ...service import orgunit
from ...service.address_handler import base

ROLE_TYPE = "address"

logger = logging.getLogger(__name__)


@reading.register(ROLE_TYPE)
class AddressReader(reading.OrgFunkReadingHandler):
    function_key = mapping.ADDRESS_KEY

    @classmethod
    def get_mo_object_from_effect(cls, effect, start, end, funcid):
        c = common.get_connector()

        person = mapping.USER_FIELD.get_uuid(effect)
        org_unit = mapping.ASSOCIATED_ORG_UNIT_FIELD.get_uuid(effect)
        address_type = mapping.ADDRESS_TYPE_FIELD.get_uuid(effect)

        scope = mapping.SINGLE_ADDRESS_FIELD(effect)[0].get("objekttype")
        handler = base.get_handler_for_scope(scope).from_effect(effect)

        base_obj = super().get_mo_object_from_effect(effect, start, end, funcid)

        r = {
            **base_obj,
            mapping.ADDRESS_TYPE: facet.get_one_class_full(c, address_type),
            **handler.get_mo_address_and_properties(),
        }
        if person:
            r[mapping.PERSON] = employee.get_one_employee(c, person)
        if org_unit:
            r[mapping.ORG_UNIT] = orgunit.get_one_orgunit(
                c, org_unit, details=orgunit.UnitDetails.MINIMAL
            )

        return r
