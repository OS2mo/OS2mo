# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from typing import Annotated
from uuid import UUID

import strawberry
from more_itertools import one
from more_itertools import only
from strawberry.types import Info

from .filters import EmployeeFilter
from .resolvers import employee_resolver
from keycloak import KeycloakAdmin
from mora.auth.keycloak.oidc import LEGACY_AUTH_UUID
from mora.auth.keycloak.oidc import NO_AUTH_UUID
from mora.auth.middleware import LORA_USER_UUID
from mora.config import get_settings

BEFORE_ACTOR_UUID = UUID("42c432e8-9c4a-11e6-9f62-873cf34a735f")


# TODO: Create dataloader for this
# TODO: This should be asyncio
def fetch_integration_actor_map() -> dict[UUID, str]:
    settings = get_settings()

    admin = KeycloakAdmin(
        server_url=f"{settings.keycloak_schema}://{settings.keycloak_host}:{settings.keycloak_port}/auth/",
        username=settings.keycloak_admin_username,
        password=settings.keycloak_admin_password,
        realm_name=settings.keycloak_realm,
        user_realm_name="master",
    )
    actor_map = {}
    for client in admin.get_clients():
        client_name = client["clientId"]

        for mapper in client["protocolMappers"]:
            if mapper["name"] == "hardcoded-uuid":
                actor_uuid = UUID(mapper["config"]["claim.value"])
                assert actor_uuid not in actor_map
                actor_map[actor_uuid] = client_name
    return actor_map


@strawberry.interface
class Actor:
    uuid: UUID


@strawberry.type
class IntegrationActor(Actor):
    @strawberry.field
    async def name(self, root: "IntegrationActor") -> str:
        actor_map = fetch_integration_actor_map()
        return actor_map[root.uuid]


LazySchema = strawberry.lazy(".schema")
LazyEmployee = Annotated["Employee", LazySchema]


@strawberry.type
class PersonActor(Actor):
    # TODO: This should probably return a response object
    #       However this is difficult due to cyclic dependencies
    @strawberry.field
    async def person(self, root: "PersonActor", info: Info) -> LazyEmployee:
        result = await employee_resolver(
            info=info, filter=EmployeeFilter(uuids=[root.uuid])
        )
        state = one(result[root.uuid])
        return state

    pass


@strawberry.type
class SpecialActor(Actor):
    details: str


async def actor_uuid_to_actor(actor_uuid: UUID, info: Info) -> Actor:
    well_known_uuids = {
        LORA_USER_UUID: "The change was made with an unknown actor",
        NO_AUTH_UUID: "The change was made when auth was disabled",
        LEGACY_AUTH_UUID: "The change was made through the legacy auth system",
        BEFORE_ACTOR_UUID: "The change was made before actors were registered",
    }
    # Check if the UUID is one of our magic UUIDs
    if actor_uuid in well_known_uuids:
        return SpecialActor(uuid=actor_uuid, details=well_known_uuids[actor_uuid])
    # Check if the UUID is an employee
    result = only(
        await employee_resolver(info=info, filter=EmployeeFilter(uuids=[actor_uuid]))
    )
    if result:
        return PersonActor(uuid=actor_uuid)
    # Check if the UUID is an known integration
    actor_map = fetch_integration_actor_map()
    if actor_uuid in actor_map:
        return IntegrationActor(uuid=actor_uuid)
    # TODO: Check if the UUID is a known keycloak user, although not in MO?

    # Fail to translate, let the user know
    return SpecialActor(uuid=actor_uuid, details="The actor could not be translated")
