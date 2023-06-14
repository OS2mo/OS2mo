# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from functools import lru_cache

from pydantic import BaseSettings


class Settings(BaseSettings):
    """
    These settings can be overwritten by environment variables
    The environement variable name is the upper-cased version of the variable name below
    E.g. DB_NAME == db_name
    """

    db_name: str = "mox"
    db_user: str = "mox"
    db_password: str | None
    db_host: str = "mox-db"
    db_port: str = "5432"
    db_sslmode: str | None

    # Authentication
    lora_auth: bool = True
    keycloak_schema: str = "https"
    keycloak_host: str = "keycloak"
    keycloak_port: int = 8080
    keycloak_realm: str = "lora"
    keycloak_signing_alg: str = "RS256"
    keycloak_verify_audience: bool = True

    # If enabled, expose /testing/db-* endpoint for setup, reset and teardown of a
    # test database. Useful for integration tests from other components such as MO.
    # Does not work when running multi-threaded.
    testing_api: bool = False

    # If enabled, exposes /db/truncate endpoint, for truncating the current
    # database.
    truncate_api: bool = False

    # The log level for the Python application
    lora_log_level: str = "WARNING"

    # If enabled, uses alternative search implementation
    quick_search: bool = True

    # Whether authorization is enabled.
    # If not, the restrictions module is not called.
    enable_restrictions: bool = False


@lru_cache
def get_settings():
    return Settings()
