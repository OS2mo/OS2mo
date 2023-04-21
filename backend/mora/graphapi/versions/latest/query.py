# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from functools import wraps
from typing import Any
from typing import cast

import strawberry
from pydantic import parse_obj_as
from strawberry.types import Info

from .health import health_map
from .models import ConfigurationRead
from .models import FileRead
from .models import FileStore
from .models import HealthRead
from .permissions import gen_read_permission
from .permissions import IsAuthenticatedPermission
from .resolvers import AddressResolver
from .resolvers import AssociationResolver
from .resolvers import ClassResolver
from .resolvers import EmployeeResolver
from .resolvers import EngagementAssociationResolver
from .resolvers import EngagementResolver
from .resolvers import FacetResolver
from .resolvers import ITSystemResolver
from .resolvers import ITUserResolver
from .resolvers import KLEResolver
from .resolvers import LeaveResolver
from .resolvers import ManagerResolver
from .resolvers import OrganisationUnitResolver
from .resolvers import RelatedUnitResolver
from .resolvers import RoleResolver
from .resolver_map import resolver_map
from .schema import Address
from .schema import Association
from .schema import Class
from .schema import Configuration
from .schema import Employee
from .schema import Engagement
from .schema import EngagementAssociation
from .schema import Facet
from .schema import File
from .schema import Health
from .schema import ITSystem
from .schema import ITUser
from .schema import KLE
from .schema import Leave
from .schema import Manager
from .schema import Organisation
from .schema import OrganisationUnit
from .schema import Paged
from .schema import PageInfo
from .schema import RelatedUnit
from .schema import Response
from .schema import Role
from .schema import Version
from .types import Cursor
from mora.config import get_public_settings


def to_response(resolver):  # type: ignore
    @wraps(resolver.resolve)
    async def resolve_response(*args, **kwargs):  # type: ignore
        result = await resolver.resolve(*args, **kwargs)
        model = resolver_map[type(resolver)]
        return [
            Response(uuid=uuid, model=model, object_cache=objects)
            for uuid, objects in result.items()
        ]

    return resolve_response


@strawberry.type(description="Entrypoint for all read-operations")
class Query:
    """Query is the top-level entrypoint for all read-operations.

    Operations are listed hereunder using @strawberry.field, grouped by their model.

    Most of the endpoints here are implemented by simply calling their dataloaders.
    """

    # Addresses
    # ---------
    addresses: list[Response[Address]] = strawberry.field(
        resolver=to_response(AddressResolver()),
        description="Get a list of all addresses, optionally by uuid(s)",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("address")],
    )

    # Associations
    # ------------
    associations: list[Response[Association]] = strawberry.field(
        resolver=to_response(AssociationResolver()),
        description="Get a list of all Associations, optionally by uuid(s)",
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("association"),
        ],
    )

    # Classes
    # -------
    classes: list[Class] = strawberry.field(
        resolver=ClassResolver().resolve,
        description="Get a list of all classes, optionally by uuid(s)",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    # Employees
    # ---------
    employees: list[Response[Employee]] = strawberry.field(
        resolver=to_response(EmployeeResolver()),
        description="Get a list of all employees, optionally by uuid(s)",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("employee")],
    )

    # Engagements
    # -----------
    engagements: list[Response[Engagement]] = strawberry.field(
        resolver=to_response(EngagementResolver()),
        description="Get a list of all engagements, optionally by uuid(s)",
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("engagement"),
        ],
    )

    # EngagementsAssociations
    # -----------
    engagement_associations: list[Response[EngagementAssociation]] = strawberry.field(
        resolver=to_response(EngagementAssociationResolver()),
        description="Get a list of engagement associations",
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("engagement_association"),
        ],
    )

    # Facets
    # ------
    facets: list[Facet] = strawberry.field(
        resolver=FacetResolver().resolve,
        description="Get a list of all facets, optionally by uuid(s)",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("facet")],
    )

    # ITSystems
    # ---------
    itsystems: list[ITSystem] = strawberry.field(
        resolver=ITSystemResolver().resolve,
        description="Get a list of all ITSystems, optionally by uuid(s)",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("itsystem")],
    )

    # ITUsers
    # -------
    itusers: list[Response[ITUser]] = strawberry.field(
        resolver=to_response(ITUserResolver()),
        description="Get a list of all ITUsers, optionally by uuid(s)",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("ituser")],
    )

    # KLEs
    # ----
    kles: list[Response[KLE]] = strawberry.field(
        resolver=to_response(KLEResolver()),
        description="Get a list of all KLE's, optionally by uuid(s)",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("kle")],
    )

    # Leave
    # -----
    leaves: list[Response[Leave]] = strawberry.field(
        resolver=to_response(LeaveResolver()),
        description="Get a list of all leaves, optionally by uuid(s)",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("leave")],
    )

    # Managers
    # --------
    managers: list[Response[Manager]] = strawberry.field(
        resolver=to_response(ManagerResolver()),
        description="Get a list of all managers, optionally by uuid(s)",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("manager")],
    )

    # Root Organisation
    # -----------------
    @strawberry.field(
        description=(
            "Get the root-organisation. "
            "This endpoint fails if not exactly one exists in LoRa."
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org")],
    )
    async def org(self, info: Info) -> Organisation:
        return await info.context["org_loader"].load(0)

    # Organisational Units
    # --------------------
    org_units: list[Response[OrganisationUnit]] = strawberry.field(
        resolver=to_response(OrganisationUnitResolver()),
        description="Get a list of all organisation units, optionally by uuid(s)",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
    )

    # Related Units
    # -------------
    related_units: list[Response[RelatedUnit]] = strawberry.field(
        resolver=to_response(RelatedUnitResolver()),
        description="Get a list of related organisation units, optionally by uuid(s)",
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("related_unit"),
        ],
    )

    # Roles
    # -----
    roles: list[Response[Role]] = strawberry.field(
        resolver=to_response(RoleResolver()),
        description="Get a list of all roles, optionally by uuid(s)",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("role")],
    )

    # Version
    # -------
    @strawberry.field(
        description="Get component versions",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("version")],
    )
    async def version(self) -> Version:
        return Version()

    # Health
    # ------
    @strawberry.field(
        description="Get a list of all health checks, optionally by identifier(s)",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("health")],
    )
    async def healths(
        self,
        limit: int | None = None,
        # Cursor's input is a Base64 encoded string eg. `Mw==`, but is parsed as an int
        # and returned again as a Base64 encoded string.
        # This way we can use it for indexing and calculations
        cursor: Cursor | None = None,
        identifiers: list[str] | None = None,
    ) -> Paged[Health]:
        healthchecks = set(health_map.keys())
        if identifiers is not None:
            healthchecks = healthchecks.intersection(set(identifiers))

        def construct(identifier: Any) -> dict[str, Any]:
            return {"identifier": identifier}

        healths = list(map(construct, healthchecks))

        healths = healths[cursor:][:limit]

        end_cursor: int = (cursor or 0) + len(healths)

        parsed_healths = parse_obj_as(list[HealthRead], healths)
        health_objects = list(map(Health.from_pydantic, parsed_healths))
        return Paged(objects=health_objects, page_info=PageInfo(next_cursor=end_cursor))

    # Files
    # -----
    @strawberry.field(
        description="Get a list of all files, optionally by filename(s)",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("file")],
    )
    async def files(
        self, info: Info, file_store: FileStore, file_names: list[str] | None = None
    ) -> list[File]:
        filestorage = info.context["filestorage"]
        found_files = filestorage.list_files(file_store)
        if file_names is not None:
            found_files = found_files.intersection(set(file_names))

        def construct(file_name: str) -> dict[str, Any]:
            return {"file_store": file_store, "file_name": file_name}

        files = list(map(construct, found_files))
        parsed_files = parse_obj_as(list[FileRead], files)
        return list(map(File.from_pydantic, parsed_files))

    # Configuration
    # -------------
    @strawberry.field(
        description="Get a list of configuration variables.",
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("configuration"),
        ],
    )
    async def configuration(
        self, identifiers: list[str] | None = None
    ) -> list[Configuration]:
        settings_keys = get_public_settings()
        if identifiers is not None:
            settings_keys = settings_keys.intersection(set(identifiers))

        def construct(identifier: Any) -> dict[str, Any]:
            return {"key": identifier}

        settings = list(map(construct, settings_keys))
        parsed_settings = parse_obj_as(list[ConfigurationRead], settings)
        return cast(list[Configuration], parsed_settings)
