# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import os
from enum import Enum
from functools import lru_cache
from typing import Any

from pydantic import AnyHttpUrl
from pydantic import BaseSettings
from pydantic import Field
from pydantic import root_validator
from pydantic import validator
from pydantic.types import DirectoryPath
from pydantic.types import FilePath
from pydantic.types import PositiveInt
from pydantic.types import UUID
from structlog import get_logger

logger = get_logger()


class NavLink(BaseSettings):
    href: AnyHttpUrl
    text: str


class Environment(str, Enum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ServicePlatformenSettings(BaseSettings):
    sp_service_uuid: UUID
    sp_agreement_uuid: UUID
    sp_municipality_uuid: UUID
    sp_system_uuid: UUID
    sp_certificate_path: FilePath
    sp_production: bool = False
    sp_api_version: int = 4

    @validator("sp_certificate_path")
    def validate_certificate_not_empty(cls, v):
        if not v.stat().st_size:
            raise ValueError("Serviceplatformen certificate can not be empty")
        return v

    @validator("sp_api_version")
    def validate_api_version(cls, v):
        if v not in {4, 5}:
            raise ValueError(
                f"Serviceplatformen API version must be either 4 or 5 (not {v!r})"
            )
        return v


class FileSystemSettings(BaseSettings):
    query_export_dir: DirectoryPath = "/queries"
    query_insight_dir: DirectoryPath | None = None


class Settings(BaseSettings):
    """
    These settings can be overwritten by environment variables
    The environement variable name is the upper-cased version of the variable name below
    """

    commit_tag: str | None
    commit_sha: str | None

    sentry_dsn: str | None

    # Misc OS2mo settings
    environment: Environment = Environment.PRODUCTION
    os2mo_log_level: str = "WARNING"
    navlinks: list[NavLink] = []

    # File Store settings
    file_storage: str = "noop"
    filesystem_settings: FileSystemSettings | None = None

    @root_validator
    def check_filesystem_settings(cls, values: dict[str, Any]) -> dict[str, Any]:
        if values.get("file_storage") != "filesystem":
            return values

        values["filesystem_settings"] = FileSystemSettings()
        return values

    # Enable auth-endpoints and auth
    os2mo_auth: bool = True
    # When graphql_rbac is disabled, it is in fact still enabled for graphql mutators.
    # This is due to a hotfix for a security security vulnerability in the orgviewer.
    # This hotfix will be removed again later, once the security issues has been fixed.
    graphql_rbac: bool = False

    log_level: LogLevel = LogLevel.INFO

    @root_validator
    def graphql_rbac_dependencies(cls, values: dict[str, Any]) -> dict[str, Any]:
        if not values["graphql_rbac"]:
            return values

        dependencies = {"os2mo_auth", "keycloak_rbac_enabled"}
        for dependency in dependencies:
            if not values[dependency]:
                raise ValueError(
                    f"'{dependency}' must be true when graphql_rbac is enabled"
                )
        return values

    # airgapped options
    enable_dar: bool = True

    # Legacy auth
    os2mo_legacy_session_support: bool = False
    session_db_user = "sessions"
    session_db_password: str | None
    session_db_host = "mox-db"
    session_db_port = "5432"
    session_db_name = "sessions"

    # Bulked LoRa DataLoader fetching
    bulked_fetch: bool = True

    # HTTP Trigger settings
    http_endpoints: list[str] | None
    fetch_trigger_timeout: int = 5
    run_trigger_timeout: int = 5

    # HTTPX
    httpx_timeout: PositiveInt = 60

    # AMQP settings
    amqp_enable: bool = False
    # AMQP connection settings are extracted from environment variables by the RAMQP
    # library directly.
    amqp_enable_new_subsystem: bool = False

    enable_sp: bool = False
    sp_settings: ServicePlatformenSettings | None = None

    @root_validator
    def check_sp_configuration(cls, values: dict[str, Any]) -> dict[str, Any]:
        # If SP is not enabled, no reason to check configuration
        if not values.get("enable_sp"):
            return values
        values["sp_settings"] = ServicePlatformenSettings()
        return values

    # Keycloak settings
    keycloak_schema: str = "https"
    keycloak_host: str = "keycloak"
    keycloak_port: int = 443
    keycloak_realm: str = "mo"
    keycloak_mo_client: str = "mo-frontend"
    keycloak_signing_alg: str = "RS256"
    keycloak_verify_audience: bool = True
    keycloak_auth_server_url: AnyHttpUrl = "http://localhost:8081/auth/"
    keycloak_ssl_required: str = "external"
    keycloak_rbac_enabled: bool = False

    # Lora client
    lora_client_id: str = "mo"
    lora_client_secret: str | None
    lora_auth_realm: str = "lora"
    lora_auth_server: AnyHttpUrl = "http://keycloak:8080/auth"

    # ConfDB settings
    confdb_show_roles: bool = True
    confdb_show_kle: bool = False
    confdb_show_user_key: bool = True
    confdb_show_location: bool = True
    confdb_show_time_planning: bool = False
    confdb_show_level: bool = True
    confdb_show_primary_engagement: bool = False
    confdb_show_primary_association: bool = False

    # Show the refresh button for org-units
    confdb_show_org_unit_button: bool = False
    confdb_inherit_manager: bool = True
    confdb_association_dynamic_facets: str = ""
    confdb_substitute_roles: str = ""
    confdb_show_cpr_no: bool = Field(
        True, description="Make CPR number visible under the Employee tab"
    )
    confdb_show_user_key_in_search: bool = False
    confdb_extension_field_ui_labels: str = ""
    confdb_show_engagement_hyperlink: bool = False
    confdb_show_seniority: bool = False
    confdb_show_custom_logo: str = ""

    # Autocomplete: use new API? Requires LoRa 1.13 or later.
    # See #38239.
    confdb_autocomplete_use_new_api: bool = False
    # List of class UUIDs whose title and value will be displayed for each
    # matching employee.
    confdb_autocomplete_attrs_employee: list[UUID] | None
    # List of class UUIDs whose title and value will be displayed for each
    # matching organisation unit.
    confdb_autocomplete_attrs_orgunit: list[UUID] | None

    # MO allows "fictitious" birthdates in CPR numbers, if this is set to False
    cpr_validate_birthdate: bool = True

    # MO UI displays an "IT associations" tab for employees, if this is set to True
    show_it_associations_tab: bool = False

    # MO displays access address in organiasation-address-autocomplete-endpoint.
    dar_address_autocomplete_includes_access_addresses: bool = True

    # MO disables/enables IT System Entry form-fields when in edit mode.
    confdb_it_system_entry_edit_fields_disabled: bool = False

    # The flag is used by the frontend to hide employee association columns in the details table
    # Ex. CONFDB_EMPLOYEE_HIDE_ASSOCIATION_COLUMNS=["org_unit", "third_party_association_type"]
    confdb_employee_hide_association_columns: list[str] | None

    # This flag fixes the datepicker using different timezones, resulting in choosing
    # 1 day before the picked date. This feature-flag is temporary,
    # until feature is accepted by customers.
    confdb_datepicker_fix_timezone: bool = False

    # This flag shows the birthday of an employee in the search bar
    confdb_show_employee_birthday_in_search: bool = False

    # String telling OS2Mo what DIPEX version is being used to import & export data
    # to and from the system - SHOULD ONLY BE USED IF FORCED TO BY CUSTOMER!
    confdb_dipex_version__do_not_use: str | None

    # If flag is set, it will be possible to pick OrgUnit hierarchy for the new units
    confdb_org_unit_hierarchy_in_create: bool = False

    # If flag is set, autocomplete-v2 will use the fixed version
    confdb_autocomplete_v2_orgunits_fixes: bool = False

    def is_production(self) -> bool:
        """Return whether we are running in a production environment."""
        return self.environment is Environment.PRODUCTION

    def is_under_test(self) -> bool:
        return os.environ.get("PYTEST_RUNNING") is not None


@lru_cache
def get_settings(*args, **kwargs) -> Settings:
    return Settings(*args, **kwargs)


def get_public_settings() -> set[str]:
    """Set of settings keys that are exposed to the world.

    Returns:
        Set of settings keys.
    """
    various_keys = {
        "commit_tag",
        "commit_sha",
        "environment",
        "navlinks",
        "show_it_associations_tab",
        "keycloak_rbac_enabled",
        "file_storage",
    }
    confdb_keys = filter(
        lambda key: key.startswith("confdb_"), Settings.__fields__.keys()
    )
    return set.union(various_keys, confdb_keys)
