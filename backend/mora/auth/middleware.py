# SPDX-FileCopyrightText: 2015-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0
"""Middleware for authentification."""
from contextvars import ContextVar
from contextvars import Token
from uuid import UUID

from fastapi import Depends
from fastapi import Request


# This magical UUID was introduced into LoRas source code back in
# December of 2015, it is kept here for backwards compatabiltiy, but should
# be eliminated in the future, by ensuring that Keycloak UUIDs are always set.
# For more information, see the commit messsage of the change introducing this.
LORA_USER_UUID = UUID("42c432e8-9c4a-11e6-9f62-873cf34a735f")


_authenticated_user: ContextVar[UUID | None] = ContextVar("_authenticated_user")


async def fetch_authenticated_user(request: Request) -> UUID:
    return None


async def set_authenticated_user(
    user_uuid: UUID | None = Depends(fetch_authenticated_user),
) -> None:
    if user_uuid is None:
        yield
        return

    token: Token = _authenticated_user.set(user_uuid)
    yield
    _authenticated_user.reset(token)


def get_authenticated_user() -> UUID:
    """Return UUID of the authenticated user."""
    return _authenticated_user.get(LORA_USER_UUID)
