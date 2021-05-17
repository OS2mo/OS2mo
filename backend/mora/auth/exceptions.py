# SPDX-FileCopyrightText: 2019-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0
from fastapi.exceptions import HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED
from jwt.exceptions import InvalidTokenError


class AuthError(Exception):

    def __init__(self, exc: Exception):
        self.__exc = exc

    @property
    def exc(self) -> Exception:
        return self.__exc

    def is_client_side_error(self) -> bool:
        """
        Return True if the error is a client side error (e.g. an expired
        token) and False otherwise (e.g. if Keycloak is unreachable)
        """
        return True if (isinstance(self.__exc, InvalidTokenError) or
                        (isinstance(self.__exc, HTTPException) and
                         self.__exc.status_code == HTTP_401_UNAUTHORIZED))\
            else False
