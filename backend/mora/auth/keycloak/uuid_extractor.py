# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import asyncio
import functools
import re
from collections.abc import AsyncIterable
from typing import Any
from uuid import UUID

from fastapi import Request
from more_itertools import one
from structlog import get_logger

from mora import common
from mora.exceptions import ErrorCodes
from mora.exceptions import HTTPException
from mora.graphapi.versions.latest.permissions import CollectionPermissionType
from mora.graphapi.versions.latest.permissions import Collections
from mora.mapping import ASSOCIATED_ORG_UNITS_FIELD
from mora.mapping import ASSOCIATION
from mora.mapping import CHILDREN
from mora.mapping import DATA
from mora.mapping import ENGAGEMENT
from mora.mapping import EntityType
from mora.mapping import MANAGER
from mora.mapping import ORG_UNIT
from mora.mapping import PARENT
from mora.mapping import PARENT_FIELD
from mora.mapping import PERSON
from mora.mapping import ROLEBINDING
from mora.mapping import TYPE
from mora.mapping import USER_FIELD

# import mora.main

logger = get_logger()


def _get_terminate_entity_regex(entity: EntityType) -> re.Pattern:
    return re.compile(
        f"/service/{entity.value}/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-"
        f"[0-9a-f]{{4}}-[0-9a-f]{{12}}/terminate"
    )


UUID_KEY = "uuid"

# URL paths

# TODO: re-introduce feature where the paths below are fetched via
#  the main.app-url_path_for(...). The importing of mora.main
#  causes the instrumentation to fail why we are temporarily using
#  hard-coded constants instead -
#  see https://redmine.magenta-aps.dk/issues/45047

# CREATE_OU = mora.main.app.url_path_for('create_org_unit')
# TERMINATE_DETAIL = mora.main.app.url_path_for('terminate')
# TERMINATE_UNIT = _get_terminate_entity_regex('terminate_org_unit')
# TERMINATE_EMPLOYEE = _get_terminate_entity_regex('terminate_employee')

CREATE_OU = "/service/ou/create"
TERMINATE_DETAIL = "/service/details/terminate"
TERMINATE_UNIT = _get_terminate_entity_regex(EntityType.ORG_UNIT)
TERMINATE_EMPLOYEE = _get_terminate_entity_regex(EntityType.EMPLOYEE)


def return_value_logger(coro):
    @functools.wraps(coro)
    async def wrapper(*args, **kwargs):
        result = await coro(*args, **kwargs)
        logger.debug(f"{coro.__name__} returns", return_value=result)
        return result

    return wrapper


def get_ancestor_uuids(tree: list[dict]) -> set[UUID]:
    """
    Recursively extract org unit UUIDs from org unit ancestor tree.

    :param tree: (sub)tree containing the descendants of an org unit
    :return: set of UUIDs of all the org units in the tree
    """

    # So far in the org unit RBAC case we have only experienced lists
    # containing exactly one element, but let's leave this assertion until
    # the entire RBAC code is done
    assert len(tree) == 1  # Fix

    node = tree[0]

    uuids = {UUID(node.get(UUID_KEY))}  # Do not assume non-empty list
    if CHILDREN in node:
        uuids = uuids.union(get_ancestor_uuids(node[CHILDREN]))
    return uuids


# The following functions (or coroutines) are strategies for extracting the
# org unit UUID(s) when an endpoint with the RBAC feature enabled is called.
# These UUIDs are required in order to determine the owner of the
# corresponding org units


async def get_entity_uuids(request: Request) -> set[UUID]:
    # State like pattern - choose appropriate UUID extraction strategy based
    # on the URL path of the incoming request
    """Extract the UUID(s) for the relevant entity (org unit or employee).

    NOTE: This function should (try to) be equivalent to the one for GraphQL defined
    below.

    :param request: the incoming request to the endpoint
    :return: list of the entity UUID(s)
    """
    logger.debug("uuid_extract_strategy called")

    if request.url.path == CREATE_OU:
        return await create_ou_extract_strategy(request)
    if TERMINATE_UNIT.match(request.url.path):
        return path_extract_strategy(request)
    if TERMINATE_EMPLOYEE.match(request.url.path):
        return path_extract_strategy(request)
    if request.url.path == TERMINATE_DETAIL:
        return await terminate_detail_extract_strategy(request)
    return await json_extract_strategy(request)


async def create_ou_extract_strategy(request: Request) -> set[UUID]:
    # Strategy pattern
    """
    Extract org unit UUID from the request payload when creating a new
    org unit.

    :param request: the incoming request to the endpoint
    :return: list containing the org unit UUID
    """

    logger.debug("create_ou_uuid_extract_strategy called")

    payload = await request.json()
    if PARENT not in payload:
        return set()
    uuid = payload[PARENT][UUID_KEY]
    logger.debug("Parent org unit UUID is " + uuid)

    return {UUID(uuid)}


def path_extract_strategy(request: Request) -> set[UUID]:
    # Strategy pattern
    """
    Extract org unit UUID from the request path.

    :param request: the incoming request to the endpoint
    :return: list containing the org unit UUID
    """

    logger.debug("path_extract_strategy called")

    return {UUID(request.path_params.get(UUID_KEY))}


async def terminate_detail_extract_strategy(request: Request) -> set[UUID]:
    # Strategy pattern
    """
    Extract org unit UUID from the request payload when terminating an
    org unit detail.

    :param request: the incoming request to the endpoint
    :return: list containing the org unit UUID
    """

    logger.debug("terminate_detail_uuid_extract_strategy called")

    payload = await request.json()

    # Example payload
    # {
    #     "type": "address",
    #     "uuid": "8086178e-f2e2-418a-a46c-de6f3699d747",
    #     "validity": {
    #         "to": "2021-07-01"
    #     }
    # }

    if payload[TYPE] == ORG_UNIT:
        return {UUID(payload[UUID_KEY])}

    org_function = await _get_org_function(payload[UUID_KEY])
    org_unit_uuid = ASSOCIATED_ORG_UNITS_FIELD.get_uuid(org_function)
    if org_unit_uuid:
        return {UUID(org_unit_uuid)}
    employee_uuid = USER_FIELD.get_uuid(org_function)

    return {UUID(employee_uuid)}


async def json_extract_strategy(request: Request) -> set[UUID]:
    # Strategy pattern
    """
    Extract org unit UUID from the request payload when creating, editing,
    renaming or moving an org unit. In the case where we are moving an org
    unit, the list returned will contain exactly two elements (the source and
    target unit) and in all other cases the list will only contain the source
    unit UUID.

    :param request: the incoming request to the endpoint
    :return: list of the org unit UUID(s)
    """

    logger.debug("json_uuid_extract_strategy called")

    payload = await request.json()
    if isinstance(payload, dict):
        payload = [payload]

    if not all(obj.get(TYPE) == payload[0].get(TYPE) for obj in payload):
        logger.debug("Object types not identical")
        raise HTTPException(
            error_key=ErrorCodes.E_INVALID_INPUT,
            message="Object types in payload list must be identical",
        )
    _type = payload[0].get(TYPE)

    async def obj_to_uuid(obj: dict) -> UUID | None:
        # All role, association and manager manipulations should be
        # granted access via the org unit(s)
        if _type in {ENGAGEMENT, ROLEBINDING, ASSOCIATION, MANAGER}:
            if ORG_UNIT in obj:
                return UUID(obj[ORG_UNIT][UUID_KEY])
            if obj[TYPE] == ENGAGEMENT:
                org_function = await _get_org_function(obj[UUID_KEY])
                org_unit_uuid = ASSOCIATED_ORG_UNITS_FIELD.get_uuid(org_function)
                return UUID(org_unit_uuid)
            return UUID(obj[DATA][ORG_UNIT][UUID_KEY])
        # Creating or editing detail (address, IT-system,...)
        if _type != ORG_UNIT:
            if ORG_UNIT in obj:
                return UUID(obj[ORG_UNIT][UUID_KEY])
            return UUID(obj[PERSON][UUID_KEY])
        return None

    uuids = set(await asyncio.gather(*(obj_to_uuid(obj) for obj in payload)))
    uuids.discard(None)
    if uuids:
        return uuids

    # Renaming, moving or editing the details of the unit itself (i.e.
    # not address details and similar)

    data = one(payload)[DATA]
    if PARENT in data and ORG_UNIT not in one(payload):
        # Moving a unit
        return {UUID(data[UUID_KEY]), UUID(data[PARENT][UUID_KEY])}

    # Renaming or editing details on the unit itself
    return {UUID(data[UUID_KEY])}


@return_value_logger
async def get_entity_type(request: Request) -> EntityType:
    # NOTE: This function should (try to) be equivalent to the one for GraphQL defined
    # below.
    if request.url.path == CREATE_OU or TERMINATE_UNIT.match(request.url.path):
        return EntityType.ORG_UNIT

    payload = await request.json()
    if isinstance(payload, dict):
        payload = [payload]

    async def obj_to_type(obj: dict) -> EntityType:
        if request.url.path == TERMINATE_DETAIL:
            if obj[TYPE] == ORG_UNIT:
                return EntityType.ORG_UNIT
            else:
                org_function = await _get_org_function(obj[UUID_KEY])
                org_unit_uuid = ASSOCIATED_ORG_UNITS_FIELD.get_uuid(org_function)
                return EntityType.ORG_UNIT if org_unit_uuid else EntityType.EMPLOYEE
        if obj.get(TYPE) in {ENGAGEMENT, ROLEBINDING, ASSOCIATION, MANAGER}:
            return EntityType.ORG_UNIT
        if ORG_UNIT in obj or obj.get(TYPE) == ORG_UNIT:
            return EntityType.ORG_UNIT

        return EntityType.EMPLOYEE

    types = await asyncio.gather(*(obj_to_type(obj) for obj in payload))
    if not all(_type == types[0] for _type in types):
        logger.debug("Types not identical")
        raise HTTPException(
            error_key=ErrorCodes.E_INVALID_INPUT,
            message="Object types in payload list must be identical",
        )

    return types[0]


async def get_entities_graphql(
    input: Any, collection: Collections, permission_type: CollectionPermissionType
) -> AsyncIterable[tuple[EntityType, UUID]]:
    """Extract the types and UUID(s) for the relevant entities (org unit or employee).

    NOTE: This function should (try to) be equivalent to the ones for the Service-API
    defined above.

    Args:
        input: The `input` object from the GraphQL mutator.
        collection: The object collection (address, employee, org_unit, etc.).
        permission_type: The operation type (create, update, terminate, delete).

    Returns:
        An iterable of (entity_type, uuid) tuples for check_owner().
    """

    async def extract() -> AsyncIterable[tuple[EntityType, UUID | None]]:
        # Allow both employee and person to avoid bugs in the future
        if collection in {"employee", "person"}:
            yield EntityType.EMPLOYEE, getattr(input, "uuid")
            return

        if collection == "org_unit":
            # Create requires ownership of the parent we are trying to insert under
            if permission_type == "create":
                yield EntityType.ORG_UNIT, getattr(input, "parent", None)
                return
            # Otherwise, changes always requires ownership of the org unit itself
            yield EntityType.ORG_UNIT, getattr(input, "uuid")
            # Additionally, moving an org unit (changing its parent) requires ownership
            # of the new parent. GraphQL edits always contain the full object, so we
            # must compare with the current parent in the database to figure out if it
            # was changed.
            if parent := getattr(input, "parent", None):
                current = await _get_org_unit(getattr(input, "uuid"))
                current_parent = PARENT_FIELD.get_uuid(current)
                if str(parent) != current_parent:
                    yield EntityType.ORG_UNIT, parent
            return

        if collection == "related_unit":
            # Related units have a single `origin` field and a list of `destination`s
            yield EntityType.ORG_UNIT, getattr(input, "origin", None)
            if destinations := getattr(input, "destination", None):
                for destination in destinations:
                    yield EntityType.ORG_UNIT, destination
            return

        # Even though most of the remaining object types (addresses,
        # associations, engagements, IT-users, leaves, managers, owners and
        # role-bindings, at time of writing) can reference both employees and
        # org units, we prefer org units and short-circuit if that is set.
        # Everything (except creates) requires ownership of both the existing
        # database object as well as the new object from the input.
        if permission_type != "create":
            org_function = await _get_org_function(getattr(input, "uuid"))
            if org_unit_str := ASSOCIATED_ORG_UNITS_FIELD.get_uuid(org_function):
                yield EntityType.ORG_UNIT, UUID(org_unit_str)
            elif person_str := USER_FIELD.get_uuid(org_function):
                yield EntityType.EMPLOYEE, UUID(person_str)

        # Existing database object. Again, we prefer org unit over person.
        if org_unit := getattr(input, "org_unit", None):
            yield EntityType.ORG_UNIT, org_unit
            return
        yield EntityType.EMPLOYEE, getattr(input, "employee", None)
        yield EntityType.EMPLOYEE, getattr(input, "person", None)

    async for entity_type, uuid in extract():
        # Make sure we don't yield None as UUID! Doing so makes the later code behave
        # wrongly and may grant too wide access.
        if uuid:
            yield entity_type, uuid


async def _get_org_unit(uuid: UUID) -> dict | None:
    c = common.get_connector()
    return await c.organisationenhed.get(uuid=uuid)


async def _get_org_function(uuid: UUID) -> dict | None:
    c = common.get_connector()
    return await c.organisationfunktion.get(uuid=uuid)


# TODO: so far there are only integration tests covering this module -
#  unit tests are still missing - and since this code probably will be
#  removed later we should not spend too much effort on this
