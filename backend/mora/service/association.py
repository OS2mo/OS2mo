# SPDX-FileCopyrightText: 2018-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0

"""
Associations
------------

This section describes how to interact with employee associations.

"""
import uuid
from datetime import date
from typing import Any
from typing import Dict
from typing import Optional

from structlog import get_logger

from . import handlers
from . import org
from .validation import validator
from ..service.itsystem import ItsystemRequestHandler
from ..service.facet import get_classes_under_facet
from .. import common
from .. import conf_db
from .. import lora
from .. import mapping
from .. import util


logger = get_logger()


class AssociationRequestHandler(handlers.OrgFunkRequestHandler):
    role_type = mapping.ASSOCIATION
    function_key = mapping.ASSOCIATION_KEY

    @staticmethod
    def substitute_is_needed(association_type_uuid: str) -> bool:
        """
        checks whether the chosen association needs a substitute
        """
        substitute_roles: str = conf_db.get_configuration()[conf_db.SUBSTITUTE_ROLES]
        if substitute_roles == "":
            # no role need substitute
            return False

        if association_type_uuid in substitute_roles.split(","):
            # chosen role does need substitute
            return True
        else:
            return False

    async def prepare_create(self, req: Dict[Any, Any]):
        """
        To create a vacant association, set employee_uuid to None and set a
        value org_unit_uuid
        :param req: request as received by flask
        :return:
        """
        org_unit = util.checked_get(req, mapping.ORG_UNIT, {}, required=True)
        org_unit_uuid = util.get_uuid(org_unit, required=True)

        dynamic_classes = util.checked_get(req, mapping.CLASSES, [])
        dynamic_classes = list(map(util.get_uuid, dynamic_classes))

        employee = util.checked_get(req, mapping.PERSON, {})
        employee_uuid = util.get_uuid(employee, required=False)

        org_ = await org.get_configured_organisation(
            util.get_mapping_uuid(req, mapping.ORG, required=False)
        )
        org_uuid = org_["uuid"]

        association_type_uuid = util.get_mapping_uuid(
            req, mapping.ASSOCIATION_TYPE, required=True
        )

        valid_from, valid_to = util.get_validities(req)

        func_id = util.get_uuid(req, required=False) or str(uuid.uuid4())
        bvn = util.checked_get(req, mapping.USER_KEY, func_id)

        primary = util.get_mapping_uuid(req, mapping.PRIMARY)
        substitute_uuid = util.get_mapping_uuid(req, mapping.SUBSTITUTE)
        job_function_uuid = util.get_mapping_uuid(req, mapping.JOB_FUNCTION)
        it_user = util.checked_get(req, mapping.IT, {})

        # Validation
        # remove substitute if not needed
        await validator.is_mutually_exclusive(substitute_uuid, job_function_uuid)
        if substitute_uuid:  # substitute is specified
            await validator.is_substitute_allowed(association_type_uuid)
        await validator.is_date_range_in_org_unit_range(org_unit, valid_from, valid_to)
        if employee:
            await validator.is_date_range_in_employee_range(
                employee, valid_from, valid_to
            )
        if employee_uuid:
            await validator.does_employee_have_existing_association(
                employee_uuid, org_unit_uuid, valid_from
            )
            validator.is_substitute_self(
                employee_uuid=employee_uuid, substitute_uuid=substitute_uuid
            )

        if substitute_uuid:
            rel_orgfunc_uuids = [substitute_uuid]
        elif job_function_uuid:
            rel_orgfunc_uuids = [job_function_uuid]
        else:
            rel_orgfunc_uuids = []

        payload_kwargs = dict(
            funktionsnavn=mapping.ASSOCIATION_KEY,
            primær=primary,
            valid_from=valid_from,
            valid_to=valid_to,
            brugervendtnoegle=bvn,
            tilknyttedebrugere=[employee_uuid],
            tilknyttedeorganisationer=[org_uuid],
            tilknyttedeenheder=[org_unit_uuid],
            tilknyttedeklasser=dynamic_classes,
            tilknyttedefunktioner=rel_orgfunc_uuids,
            funktionstype=association_type_uuid,
        )

        if it_user:
            it_user_system = util.checked_get(
                it_user, mapping.ITSYSTEM, {}, required=True,
            )
            it_user_system_uuid = util.get_uuid(it_user_system, required=True)
            it_user_is_primary = bool(
                util.checked_get(it_user, mapping.PRIMARY, True, required=True)
            )
            it_user_username = it_user[mapping.USER_KEY]
            it_system_binding_uuid = await _create_it_system_binding(
                org_uuid=org_uuid,
                org_unit_uuid=org_unit_uuid,
                employee_uuid=employee_uuid,
                it_system_uuid=it_user_system_uuid,
                primary=it_user_is_primary,
                user_key=it_user_username,
                valid_from=valid_from,
                valid_to=valid_to,
            )
            # Create relation between the IT system binding and the association, making
            # the association an "IT association."
            payload_kwargs["tilknyttedeitsystemer"] = [it_system_binding_uuid]

        association = common.create_organisationsfunktion_payload(**payload_kwargs)

        self.payload = association
        self.uuid = func_id
        self.trigger_dict.update(
            {
                "employee_uuid": employee_uuid,
                "org_unit_uuid": org_unit_uuid,
            }
        )

    async def prepare_edit(self, req: Dict[Any, Any]):
        """
        To edit into a vacant association, set employee_uuid to None and set a
        value org_unit_uuid
        :param req: request as received by flask
        :return:
        """
        association_uuid = req.get("uuid")
        # Get the current org-funktion which the user wants to change
        c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")
        original = await c.organisationfunktion.get(uuid=association_uuid)

        data = req.get("data")
        new_from, new_to = util.get_validities(data)

        payload = dict()
        payload["note"] = "Rediger tilknytning"

        original_data = req.get("original")
        if original_data:
            # We are performing an update
            old_from, old_to = util.get_validities(original_data)
            payload = common.inactivate_old_interval(
                old_from,
                old_to,
                new_from,
                new_to,
                payload,
                ("tilstande", "organisationfunktiongyldighed"),
            )

        update_fields = list()

        # Always update gyldighed
        update_fields.append((mapping.ORG_FUNK_GYLDIGHED_FIELD, {"gyldighed": "Aktiv"}))

        try:
            attributes = mapping.ORG_FUNK_EGENSKABER_FIELD(original)[-1].copy()
        except (TypeError, LookupError):
            attributes = {}
        new_attributes = {}

        if mapping.USER_KEY in data:
            new_attributes["brugervendtnoegle"] = util.checked_get(
                data, mapping.USER_KEY, ""
            )

        if new_attributes:
            update_fields.append(
                (
                    mapping.ORG_FUNK_EGENSKABER_FIELD,
                    {**attributes, **new_attributes},
                )
            )

        if mapping.ASSOCIATION_TYPE in data:
            association_type_uuid = data.get(mapping.ASSOCIATION_TYPE).get("uuid")
            update_fields.append(
                (
                    mapping.ORG_FUNK_TYPE_FIELD,
                    {"uuid": association_type_uuid},
                )
            )

            if not util.is_substitute_allowed(association_type_uuid):
                update_fields.append(
                    (mapping.ASSOCIATED_FUNCTION_FIELD, {"uuid": "", "urn": ""})
                )

        if mapping.ORG_UNIT in data:
            org_unit_uuid = data.get(mapping.ORG_UNIT).get("uuid")

            update_fields.append(
                (
                    mapping.ASSOCIATED_ORG_UNIT_FIELD,
                    {"uuid": org_unit_uuid},
                )
            )
        else:
            org_unit_uuid = util.get_obj_uuid(
                original,
                mapping.ASSOCIATED_ORG_UNIT_FIELD.path,
            )

        if mapping.PERSON in data:
            employee = data.get(mapping.PERSON, {})
            if employee:
                employee_uuid = employee.get("uuid")
                update_payload = {
                    "uuid": employee_uuid,
                }
            else:  # allow missing, e.g. vacant association
                employee_uuid = util.get_mapping_uuid(data, mapping.PERSON)
                update_payload = {"uuid": "", "urn": ""}

            update_fields.append(
                (
                    mapping.USER_FIELD,
                    update_payload,
                )
            )
            # update_fields.append((mapping.USER_FIELD, {'uuid': employee_uuid}))
        else:
            employee = util.get_obj_value(original, mapping.USER_FIELD.path)[-1]
            employee_uuid = util.get_uuid(employee)

        if mapping.SUBSTITUTE in data and data.get(mapping.SUBSTITUTE):
            substitute = data.get(mapping.SUBSTITUTE)
            substitute_uuid = substitute.get("uuid")
            if employee_uuid:
                validator.is_substitute_self(
                    employee_uuid=employee_uuid, substitute_uuid=substitute_uuid
                )

            if not substitute_uuid:
                update_fields.append(
                    (mapping.ASSOCIATED_FUNCTION_FIELD, {"uuid": "", "urn": ""})
                )
            else:
                association_type_uuid = util.get_mapping_uuid(
                    data, mapping.ASSOCIATION_TYPE, required=True
                )
                validator.is_substitute_allowed(association_type_uuid)
                update_fields.append(
                    (mapping.ASSOCIATED_FUNCTION_FIELD, {"uuid": substitute_uuid})
                )

        if mapping.PRIMARY in data and data.get(mapping.PRIMARY):
            primary = util.get_mapping_uuid(data, mapping.PRIMARY)

            update_fields.append((mapping.PRIMARY_FIELD, {"uuid": primary}))

        for clazz in util.checked_get(data, mapping.CLASSES, []):
            update_fields.append(
                (mapping.ORG_FUNK_CLASSES_FIELD, {"uuid": util.get_uuid(clazz)})
            )

        payload = common.update_payload(
            new_from, new_to, update_fields, original, payload
        )

        bounds_fields = list(
            mapping.ASSOCIATION_FIELDS.difference({x[0] for x in update_fields})
        )
        payload = common.ensure_bounds(
            new_from, new_to, bounds_fields, original, payload
        )

        # Validation
        if employee:
            await validator.is_date_range_in_employee_range(employee, new_from, new_to)

        if employee:
            await validator.does_employee_have_existing_association(
                employee_uuid, org_unit_uuid, new_from, association_uuid
            )

        self.payload = payload
        self.uuid = association_uuid
        self.trigger_dict.update(
            {
                "employee_uuid": employee_uuid,
                "org_unit_uuid": org_unit_uuid,
            }
        )

    async def prepare_terminate(self, request: Dict[Any, Any]):
        """Initialize a 'termination' request. Performs validation and all
        necessary processing

        Unlike the other handlers for ``organisationfunktion``, this
        one checks for and handles the ``vacate`` field in the
        request. If this is set, the manager is merely marked as
        *vacant*, i.e. without an employee or person.

        :param request: A dict containing a request

        """
        if util.checked_get(request, "vacate", False):
            self.termination_field = mapping.USER_FIELD
            self.termination_value = {}

        await super().prepare_terminate(request)


async def _create_it_system_binding(
    org_uuid: uuid.UUID,
    org_unit_uuid: uuid.UUID,
    employee_uuid: uuid.UUID,
    it_system_uuid: uuid.UUID,
    primary: bool,
    user_key: str,
    valid_from: Optional[date] = None,
    valid_to: Optional[date] = None,
) -> uuid.UUID:
    "Create an IT system binding, using the `ItsystemRequestHandler` class."

    # Figure out the UUIDs of facet "primary_type"
    primary_classes = await get_classes_under_facet(
        org_uuid,
        "primary_type",
        only_primary_uuid=False,
    )
    primary_uuid_lookup = {
        cls[mapping.USER_KEY]: cls[mapping.UUID]
        for cls in primary_classes[mapping.DATA]["items"]
    }
    primary_uuid = primary_uuid_lookup["primary" if primary else "not_primary"]

    # Build request for the `ItsystemRequestHandler`
    request = {
        mapping.ORG_UNIT: {mapping.UUID: str(org_unit_uuid)},
        mapping.PERSON: {mapping.UUID: str(employee_uuid)},
        mapping.ITSYSTEM: {mapping.UUID: str(it_system_uuid)},
        mapping.PRIMARY: {mapping.UUID: str(primary_uuid)},
        mapping.USER_KEY: user_key,
        mapping.VALIDITY: {
            mapping.FROM: util.to_iso_date(valid_from),
            mapping.TO: util.to_iso_date(valid_to, is_end=True),
        },
    }
    # Prepare and submit request
    handler = ItsystemRequestHandler(request, mapping.RequestType.CREATE)
    await handler.prepare_create(request)
    it_system_binding_uuid = await handler.submit()
    return it_system_binding_uuid
