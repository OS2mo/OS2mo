# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from uuid import UUID

import strawberry
from fastapi.encoders import jsonable_encoder
from strawberry.types import Info

from ..latest.facets import FacetUpdateInput
from ..latest.inputs import ClassUpdateInput
from ..latest.permissions import gen_update_permission
from ..latest.permissions import IsAuthenticatedPermission
from ..v10.version import GraphQLVersion as NextGraphQLVersion
from ..v13.mutators import uuid2response
from ..v13.schema import Class
from ..v13.schema import Facet
from ..v13.schema import ITSystem
from ..v13.schema import Response
from ..v14.version import ITSystemCreateInput
from mora.graphapi.shim import execute_graphql  # type: ignore[attr-defined]
from ramodels.mo import ClassRead
from ramodels.mo import FacetRead
from ramodels.mo.details import ITSystemRead


@strawberry.type
class Mutation(NextGraphQLVersion.schema.mutation):  # type: ignore[name-defined]
    @strawberry.mutation(
        description="Updates a class.",
        permission_classes=[
            IsAuthenticatedPermission,
            gen_update_permission("class"),
        ],
    )
    async def class_update(
        self, info: Info, uuid: UUID, input: ClassUpdateInput
    ) -> Response[Class]:
        input.uuid = uuid  # type: ignore
        payload = jsonable_encoder(input)
        if "validity" in payload:
            payload["validity"] = {
                "from": payload["validity"]["from"]
                if "from" in payload["validity"]
                else payload["validity"]["from_date"],
                "to": payload["validity"]["to"]
                if "to" in payload["validity"]
                else payload["validity"]["to_date"],
            }

        response = await execute_graphql(
            """
            mutation ClassUpdate($input: ClassUpdateInput!){
                class_update(input: $input) {
                    uuid
                }
            }
            """,
            graphql_version=NextGraphQLVersion,
            context_value=info.context,
            variable_values={"input": payload},
        )
        uuid = response.data["class_update"]["uuid"]
        return uuid2response(uuid, ClassRead)

    @strawberry.mutation(
        description="Updates a facet.",
        permission_classes=[
            IsAuthenticatedPermission,
            gen_update_permission("facet"),
        ],
    )
    async def facet_update(
        self, info: Info, input: FacetUpdateInput, uuid: UUID
    ) -> Response[Facet]:
        input.uuid = uuid  # type: ignore

        response = await execute_graphql(
            """
            mutation FacetUpdate($input: FacetUpdateInput!){
                facet_update(input: $input) {
                    uuid
                }
            }
            """,
            graphql_version=NextGraphQLVersion,
            context_value=info.context,
            variable_values={"input": jsonable_encoder(input)},
        )
        uuid = response.data["facet_update"]["uuid"]
        return uuid2response(uuid, FacetRead)

    @strawberry.mutation(
        description="Updates an ITSystem.",
        permission_classes=[
            IsAuthenticatedPermission,
            gen_update_permission("itsystem"),
        ],
    )
    async def itsystem_update(
        self, info: Info, input: ITSystemCreateInput, uuid: UUID
    ) -> Response[ITSystem]:
        input.uuid = uuid  # type: ignore

        response = await execute_graphql(
            """
            mutation ItSystemUpdate($input: ITSystemCreateInput!){
                itsystem_update(input: $input) {
                    uuid
                }
            }
            """,
            graphql_version=NextGraphQLVersion,
            context_value=info.context,
            variable_values={"input": jsonable_encoder(input)},
        )
        uuid = response.data["itsystem_update"]["uuid"]
        return uuid2response(uuid, ITSystemRead)


class GraphQLSchema(NextGraphQLVersion.schema):  # type: ignore
    """Version 9 of the GraphQL Schema.

    Version 10 introduced a breaking change to the itsystem, facet and class mutators,
    which removes their uuid argument to align with other mutators.
    Version 9 ensures that the old functionality is still available.
    """

    mutation = Mutation


class GraphQLVersion(NextGraphQLVersion):
    """GraphQL Version 9."""

    version = 9
    schema = GraphQLSchema
