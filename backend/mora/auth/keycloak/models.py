# SPDX-FileCopyrightText: 2021 Magenta ApS
# SPDX-License-Identifier: MPL-2.0
import binascii
from base64 import b64decode
from typing import Any
from uuid import UUID

from os2mo_fastapi_utils.auth.models import Token as BaseToken
from pydantic import BaseModel
from pydantic import Extra
from pydantic import root_validator
from pydantic import validator

from mora import config


class KeycloakToken(BaseToken):
    @root_validator
    def uuid_attribute_required_for_mo_client(
        cls, values: dict[str, Any]
    ) -> dict[str, Any]:
        if (
            config.get_settings().keycloak_rbac_enabled
            and values.get("azp") == config.get_settings().keycloak_mo_client
            and ("owner" in values["realm_access"].roles and values.get("uuid") is None)
        ):
            raise ValueError("The uuid user attribute is required for owners.")
        return values

    @validator("uuid", pre=True)
    def parse_base64_uuid(uuid):
        """Attempt to parse incoming UUID as base64"""
        if uuid is not None:
            try:
                uuid = UUID(bytes_le=b64decode(uuid))
            except (ValueError, binascii.Error):
                pass
        return uuid

    class Config:
        extra = Extra.ignore


# TODO: Remove the stuff below, once a proper auth solution is in place,
#  that works for local DIPEX development.
#  https://redmine.magenta-aps.dk/issues/44020


class NoAuthToken(BaseModel):
    pass


Token = KeycloakToken
if not config.get_settings().os2mo_auth:
    Token = NoAuthToken
