# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from collections.abc import Awaitable
from collections.abc import Callable
from typing import Any

import strawberry
from fastapi import Depends
from fastramqpi.ramqp import AMQPSystem
from pydantic import PositiveInt

from ..base import BaseGraphQLSchema
from ..base import BaseGraphQLVersion
from .actor import IntegrationActor
from .actor import PersonActor
from .actor import SpecialActor
from .audit import get_audit_loaders
from .dataloaders import get_loaders
from .mutators import Mutation as LatestMutation
from .query import Query as LatestQuery
from .types import CPRType
from mora import db
from mora import depends
from mora.auth.keycloak.models import Token
from mora.auth.keycloak.oidc import token_getter
from mora.graphapi.versions.latest.schema import DARAddress
from mora.graphapi.versions.latest.schema import DefaultAddress
from mora.graphapi.versions.latest.schema import MultifieldAddress
from mora.util import CPR


class LatestGraphQLSchema(BaseGraphQLSchema):
    """Latest GraphQL Schema."""

    query = LatestQuery
    mutation = LatestMutation

    types = [
        DefaultAddress,
        DARAddress,
        MultifieldAddress,
        IntegrationActor,
        PersonActor,
        SpecialActor,
    ]

    scalar_overrides = {
        CPR: CPRType,
        PositiveInt: strawberry.scalar(int),
    }


class LatestGraphQLVersion(BaseGraphQLVersion):
    """Latest GraphQL API version.

    The latest version is never explicitly versioned or exposed directly. Clients should
    always refer and pin themselves to a specific version, which is available as the
    latest `vN` version package, inheriting from this class without modifications.
    When a new breaking change must be introduced to the GraphQL schema, the change is
    made in `latest` and the `vN` package is changed to be an adapter which maintains
    backwards-compatibility. A new `vN+1` package is created to expose latest.

    As an example, see the merge request for the first breaking change:
    https://git.magenta.dk/rammearkitektur/os2mo/-/merge_requests/1184
    """

    # Even though the latest version isn't exposed, we use it internally for the
    # service API shims. Therefore, we must define a version number to avoid
    # having None-checks everywhere.
    version = 1000
    schema = LatestGraphQLSchema

    @classmethod
    async def get_context(
        cls,
        # NOTE: If you add or remove any parameters, make sure to keep the
        # execute_graphql ajour.
        get_token: Callable[[], Awaitable[Token]] = Depends(token_getter),
        amqp_system: AMQPSystem = Depends(depends.get_amqp_system),
        session: db.AsyncSession = Depends(db.get_session),
    ) -> dict[str, Any]:
        return {
            **await super().get_context(),
            **await get_loaders(),
            "get_token": get_token,
            "amqp_system": amqp_system,
            "session": session,
            **get_audit_loaders(session),
        }
