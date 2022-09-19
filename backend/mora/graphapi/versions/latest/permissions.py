# SPDX-FileCopyrightText: 2022 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from functools import cache
from typing import Any

from prometheus_client import Counter
from strawberry import BasePermission
from strawberry.types import Info

from mora.config import get_settings


rbac_counter = Counter("graphql_rbac", "Number of RBAC checks", ["role", "allowed"])


@cache
def gen_role_permission(
    role_name: str, message: str | None = None, force_permission_check: bool = False
) -> type[BasePermission]:
    """Generator function for permission classes.

    Args:
        role_name: The role to check existence for.
        message: Optional message override.

    Returns:
        Permission class that checks if `role_name` is in the OIDC token.
    """
    fail_message = message or f"User does not have required role: {role_name}"

    class CheckRolePermission(BasePermission):
        """Permission class that checks that a given role exists on the OIDC token."""

        message = fail_message

        def has_permission(self, source: Any, info: Info, **kwargs: Any) -> bool:
            """Returns `True` if `role_name` exists in the token's roles."""
            settings = get_settings()
            # If GraphQL RBAC is not enabled, do not check permissions, unless forced
            if (not settings.graphql_rbac) and (not force_permission_check):
                return True
            # Allow access only if expected role is in roles
            token = info.context["token"]
            # No token, no access
            if token is None:
                return False
            if isinstance(token, dict):
                roles = token["realm_access"]["roles"]
            else:
                roles = token.realm_access.roles

            allow_access = role_name in roles
            rbac_counter.labels(role=role_name, allowed=allow_access).inc()
            return allow_access

    return CheckRolePermission


# Should this list should either just be dynamic or an enum?
PERMISSIONS = {
    f"read_{collection_name}"
    for collection_name in {
        "addresses",
        "associations",
        "classes",
        "configuration",
        "employees",
        "engagement_associations",
        "engagements",
        "facets",
        "files",
        "healths",
        "itsystems",
        "itusers",
        "kles",
        "leaves",
        "managers",
        "org",
        "org_units",
        "related_units",
        "roles",
        "version",
    }
}


def gen_read_permission(collection_name: str) -> type[BasePermission]:
    """Generator function for permission classes.

    Utilizes `gen_role_permission` with a generated role-name and a custom message.

    Args:
        collection_name: Name of the collection to check access to.

    Returns:
        Permission class that checks if the `collection_name` derived role is in the
        OIDC token.
    """
    permission_name = f"read_{collection_name}"
    assert permission_name in PERMISSIONS, f"{permission_name} not in PERMISSIONS"
    return gen_role_permission(
        permission_name,
        f"User does not have read-access to {collection_name}",
    )
