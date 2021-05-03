# SPDX-FileCopyrightText: 2018-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0

'''
Roles
-----

This section describes how to interact with employee roles.

'''

import uuid
import lora_connector as lora

import mora.async_util
from . import handlers
from . import org
from .validation import validator
from .. import common
from .. import exceptions
from .. import mapping
from .. import util


class RoleRequestHandler(handlers.OrgFunkRequestHandler):
    role_type = mapping.ROLE
    function_key = mapping.ROLE_KEY

    def prepare_create(self, req):
        org_unit = util.checked_get(req, mapping.ORG_UNIT,
                                    {}, required=True)
        org_unit_uuid = util.get_uuid(org_unit, required=True)

        employee = util.checked_get(req, mapping.PERSON, {}, required=True)
        employee_uuid = util.get_uuid(employee, required=True)

        valid_from, valid_to = util.get_validities(req)

        # Validation
        mora.async_util.async_to_sync(validator.is_date_range_in_org_unit_range)(
            org_unit,
            valid_from,
            valid_to)
        mora.async_util.async_to_sync(validator.is_date_range_in_employee_range)(
            employee,
            valid_from,
            valid_to)

        org_uuid = mora.async_util.async_to_sync(org.get_configured_organisation)(
            util.get_mapping_uuid(req, mapping.ORG, required=False))["uuid"]

        role_type_uuid = util.get_mapping_uuid(req, mapping.ROLE_TYPE,
                                               required=True)

        func_id = util.get_uuid(req, required=False) or str(uuid.uuid4())
        bvn = util.checked_get(req, mapping.USER_KEY, func_id)

        role = common.create_organisationsfunktion_payload(
            funktionsnavn=mapping.ROLE_KEY,
            valid_from=valid_from,
            valid_to=valid_to,
            brugervendtnoegle=bvn,
            tilknyttedebrugere=[employee_uuid],
            tilknyttedeorganisationer=[org_uuid],
            tilknyttedeenheder=[org_unit_uuid],
            funktionstype=role_type_uuid,
            integration_data=req.get(mapping.INTEGRATION_DATA),
        )

        self.payload = role
        self.uuid = func_id
        self.trigger_dict.update({
            "employee_uuid": employee_uuid,
            "org_unit_uuid": org_unit_uuid
        })

    def prepare_edit(self, req: dict):
        role_uuid = req.get('uuid')
        # Get the current org-funktion which the user wants to change
        c = lora.Connector(virkningfra='-infinity', virkningtil='infinity')
        original = mora.async_util.async_to_sync(c.organisationfunktion.get)(
            uuid=role_uuid)

        if not original:
            exceptions.ErrorCodes.E_NOT_FOUND(uuid=role_uuid)

        data = req.get('data')
        new_from, new_to = util.get_validities(data)

        # Get org unit uuid for validation purposes
        org_unit = mapping.ASSOCIATED_ORG_UNIT_FIELD(original)[0]

        payload = dict()
        payload['note'] = 'Rediger rolle'

        original_data = req.get('original')
        if original_data:
            # We are performing an update
            old_from, old_to = util.get_validities(original_data)
            payload = common.inactivate_old_interval(
                old_from, old_to, new_from, new_to, payload,
                ('tilstande', 'organisationfunktiongyldighed')
            )

        update_fields = list()

        # Always update gyldighed
        update_fields.append((
            mapping.ORG_FUNK_GYLDIGHED_FIELD,
            {'gyldighed': "Aktiv"}
        ))

        try:
            attributes = mapping.ORG_FUNK_EGENSKABER_FIELD(original)[-1].copy()
        except (TypeError, LookupError):
            attributes = {}
        new_attributes = {}

        if mapping.USER_KEY in data:
            new_attributes['brugervendtnoegle'] = util.checked_get(
                data, mapping.USER_KEY, "")

        if new_attributes:
            update_fields.append((
                mapping.ORG_FUNK_EGENSKABER_FIELD,
                {
                    **attributes,
                    **new_attributes
                },
            ))

        if mapping.ROLE_TYPE in data:
            update_fields.append((
                mapping.ORG_FUNK_TYPE_FIELD,
                {'uuid': data.get(mapping.ROLE_TYPE).get('uuid')},
            ))

        if mapping.ORG_UNIT in data:
            update_fields.append((
                mapping.ASSOCIATED_ORG_UNIT_FIELD,
                {'uuid': (util.get_mapping_uuid(data, mapping.ORG_UNIT))},
            ))

        if mapping.PERSON in data:
            employee = data.get(mapping.PERSON)
            employee_uuid = employee.get('uuid')

            update_fields.append((
                mapping.USER_FIELD,
                {'uuid': employee_uuid},
            ))
        else:
            employee = util.get_obj_value(
                original, mapping.USER_FIELD.path)[-1]

        payload = common.update_payload(new_from, new_to, update_fields,
                                        original,
                                        payload)

        bounds_fields = list(
            mapping.ROLE_FIELDS.difference({x[0] for x in update_fields}))
        payload = common.ensure_bounds(new_from, new_to, bounds_fields,
                                       original, payload)

        mora.async_util.async_to_sync(validator.is_date_range_in_employee_range)(
            employee,
            new_from,
            new_to)

        self.payload = payload
        self.uuid = role_uuid
        self.trigger_dict.update({
            "org_unit_uuid": util.get_uuid(org_unit, required=False),
            "employee_uuid": (
                util.get_mapping_uuid(data, mapping.PERSON) or
                mapping.USER_FIELD.get_uuid(original)
            )
        })
