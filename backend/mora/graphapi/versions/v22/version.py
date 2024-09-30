# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from textwrap import dedent
from typing import Annotated
from typing import Any
from uuid import UUID

import strawberry
from strawberry.types import Info

from ..latest.filters import ClassFilter
from ..latest.filters import ManagerFilter
from ..latest.filters import OwnerFilter
from ..latest.models import AddressRead
from ..latest.paged import CursorType
from ..latest.paged import LimitType
from ..latest.permissions import gen_read_permission
from ..latest.permissions import IsAuthenticatedPermission
from ..latest.resolvers import address_resolver
from ..latest.resolvers import association_resolver
from ..latest.resolvers import class_resolver
from ..latest.resolvers import engagement_resolver
from ..latest.resolvers import filter2uuids_func
from ..latest.resolvers import generic_resolver
from ..latest.resolvers import get_employee_uuids
from ..latest.resolvers import get_org_unit_uuids
from ..latest.resolvers import it_user_resolver
from ..latest.resolvers import kle_resolver
from ..latest.resolvers import leave_resolver
from ..latest.resolvers import organisation_unit_child_count
from ..latest.resolvers import organisation_unit_has_children
from ..latest.resolvers import organisation_unit_resolver
from ..latest.resolvers import owner_resolver
from ..latest.resolvers import registration_filter
from ..latest.resolvers import related_unit_resolver
from ..latest.schema import gen_uuid_field_deprecation
from ..latest.schema import LazyAddress
from ..latest.schema import LazyAssociation
from ..latest.schema import LazyClass
from ..latest.schema import LazyEngagement
from ..latest.schema import LazyITUser
from ..latest.schema import LazyKLE
from ..latest.schema import LazyLeave
from ..latest.schema import LazyOrganisationUnit
from ..latest.schema import LazyRelatedUnit
from ..latest.schema import Manager
from ..latest.schema import Owner
from ..latest.schema import to_list
from ..latest.schema import to_only
from ..latest.schema import uuid2list
from ..latest.schema import Validity
from ..latest.schema import validity_sub_query_hack
from ..latest.seed_resolver import seed_resolver
from ..v23.version import GraphQLVersion as NextGraphQLVersion
from mora.graphapi.gmodels.mo import OrganisationUnitRead
from mora.graphapi.gmodels.mo.details import AssociationRead
from mora.graphapi.gmodels.mo.details import ITUserRead
from mora.graphapi.gmodels.mo.details import ManagerRead
from mora.handler.reading import get_handler_for_type


@strawberry.experimental.pydantic.type(
    model=OrganisationUnitRead,
    description="Organisation unit within the organisation tree",
)
class OrganisationUnit:
    parent: LazyOrganisationUnit | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                organisation_unit_resolver,
                {"uuids": lambda root: uuid2list(root.parent_uuid)},
            )
        ),
        description=dedent(
            """\
            The parent organisation unit in the organisation tree.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
    )

    @strawberry.field(
        description=dedent(
            """\
            All ancestor organisational units in the organisation tree.

            The result of collecting organisational units by following `parent` until `parent` becomes `null`.
            I.e. the list of all ancestors on the way to the organisation tree root.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
    )
    async def ancestors(
        self, root: OrganisationUnitRead, info: Info
    ) -> list[LazyOrganisationUnit]:
        """Get all ancestors in the organisation tree.

        Returns:
            A list of all the ancestors.
        """
        parent = await OrganisationUnit.parent(root=root, info=info)  # type: ignore
        if parent is None:
            return []
        ancestors = await OrganisationUnit.ancestors(self=self, root=parent, info=info)  # type: ignore
        return [parent] + ancestors

    children: list[LazyOrganisationUnit] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                organisation_unit_resolver,
                {"parents": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            The immediate descendants in the organisation tree
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
    )

    child_count: int = strawberry.field(
        resolver=seed_resolver(
            organisation_unit_child_count,
            {"parents": lambda root: [root.uuid]},
        ),
        description="Children count of the organisation unit. For performance, consider if `has_children` can answer your query instead.",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
    )

    has_children: bool = strawberry.field(
        resolver=seed_resolver(
            organisation_unit_has_children,
            {"parents": lambda root: [root.uuid]},
        ),
        description="Returns whether the organisation unit has children.",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
    )

    # TODO: Remove org prefix from RAModel and remove it here too
    # TODO: Add _uuid suffix to RAModel and remove _model suffix here
    # TODO: Should this be a list?
    org_unit_hierarchy_model: LazyClass | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                class_resolver,
                {"uuids": lambda root: uuid2list(root.org_unit_hierarchy)},
            )
        ),
        description=dedent(
            """\
            Organisation unit hierarchy.

            Can be used to label an organisational structure to belong to a certain subset of the organisation tree.

            Examples of user-keys:
            * `"Line-management"`
            * `"Self-owned institution"`
            * `"Outside organisation"`
            * `"Hidden"`

            Note:
            The organisation-gatekeeper integration is one option to keep hierarchy labels up-to-date.
        """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    unit_type: LazyClass | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                class_resolver, {"uuids": lambda root: uuid2list(root.unit_type_uuid)}
            )
        ),
        description=dedent(
            """\
            Organisation unit type.

            Organisation units can represent a lot of different classes of hierarchical structures.
            Sometimes they represent cooperations, governments, NGOs or other true organisation types.
            Oftentimes they represent the inner structure of these organisations.
            Othertimes they represent project management structures such as project or teams.

            This field is used to distriguish all these different types of organisations.

            Examples of user-keys:
            * `"Private Company"`
            * `"Educational Institution"`
            * `"Activity Center"`
            * `"Daycare"`
            * `"Team"`
            * `"Project"`
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    # TODO: Remove org prefix from RAModel and remove it here too
    org_unit_level: LazyClass | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                class_resolver,
                {"uuids": lambda root: uuid2list(root.org_unit_level_uuid)},
            )
        ),
        # TODO: Document this
        description=dedent(
            """\
            Organisation unit level.

            Examples of user-keys:
            * `"N1"`
            * `"N5"`
            * `"N7"`
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    time_planning: LazyClass | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                class_resolver,
                {"uuids": lambda root: uuid2list(root.time_planning_uuid)},
            )
        ),
        # TODO: DOcument this
        description=dedent(
            """\
            Time planning strategy.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    engagements: list[LazyEngagement] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                engagement_resolver,
                {"org_units": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            Engagements for the organistion unit.

            May be an empty list if the organistion unit does not have any people employeed.
            This situation may occur especially in the middle or the organisation tree.
            """
        ),
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("engagement"),
        ],
    )

    @strawberry.field(
        description=dedent(
            """\
            The object type.

            Always contains the string `org_unit`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Unintentionally exposed implementation detail.
            Provides no value whatsoever.
            """
        ),
    )
    async def type(self, root: OrganisationUnitRead) -> str:
        """Implemented for backwards compatability."""
        return root.type_

    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: OrganisationUnitRead) -> UUID:
        return root.uuid

    @strawberry.field(
        description=dedent(
            """\
            Short unique key.

            Usually set to be set to the key used in external systems.

            Examples:
            * `"CBCM"`
            * `"SPHA"`
            * `"1414"`
            """
        )
    )
    async def user_key(self, root: OrganisationUnitRead) -> str:
        return root.user_key

    @strawberry.field(
        description=dedent(
            """\
            Human readable name of the organisation unit.

            This is the value that should be shown to users in UIs.

            Examples:
            * `"Lunderskov skole"`
            * `"IT-Support"`
            * `"Teknik og Miljø"`
            """
        )
    )
    async def name(self, root: OrganisationUnitRead) -> str:
        return root.name

    @strawberry.field(
        description=dedent(
            """\
            Managerial roles for the organisation unit.

            May be empty in which case managers are usually inherited from parents.
            See the `inherit`-flag for details.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("manager")],
    )
    async def managers(
        self,
        root: OrganisationUnitRead,
        info: Info,
        filter: ManagerFilter | None = None,
        inherit: Annotated[
            bool,
            strawberry.argument(
                description=dedent(
                    """\
                    Whether to inherit managerial roles or not.

                    If managerial roles exist directly on this organisation unit, the flag does nothing and these managerial roles are returned.
                    However if no managerial roles exist directly, and this flag is:
                    * Not set: An empty list is returned.
                    * Is set: The result from calling `managers` with `inherit=True` on the parent of this organistion unit is returned.

                    Calling with `inherit=True` can help ensure that a manager is always found.
                    """
                )
            ),
        ] = False,
    ) -> list["Manager"]:
        if filter is None:
            filter = ManagerFilter()
        filter.org_units = [root.uuid]

        resolver = to_list(seed_resolver(manager_resolver))
        result = await resolver(root=root, info=info, filter=filter)
        if result:
            return result  # type: ignore
        if not inherit:
            return []
        parent = await OrganisationUnit.parent(root=root, info=info)  # type: ignore
        if parent is None:
            return []
        return await OrganisationUnit.managers(
            self=self, root=parent, info=info, inherit=True
        )

    @strawberry.field(
        description=dedent(
            """\
            Owner roles for the organisation unit.

            May be empty in which case owners are usually inherited from parents.
            See the `inherit`-flag for details.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("owner")],
    )
    async def owners(
        self,
        root: OrganisationUnitRead,
        info: Info,
        filter: OwnerFilter | None = None,
        inherit: Annotated[
            bool,
            strawberry.argument(
                description=dedent(
                    """\
                    Whether to inherit owner roles or not.

                    If owner roles exist directly on this organisaion unit, the flag does nothing and these owner roles are returned.
                    However if no owner roles exist directly, and this flag is:
                    * Not set: An empty list is returned.
                    * Is set: The result from calling `owners` with `inherit=True` on the parent of this organistion unit is returned.

                    Calling with `inherit=True` can help ensure that an owner is always found.
                    """
                )
            ),
        ] = False,
    ) -> list["Owner"]:
        # TODO: Move inherit to resolver, like `manager_resolver`
        if filter is None:
            filter = OwnerFilter()
        filter.org_units = [root.uuid]

        resolver = to_list(seed_resolver(owner_resolver))
        result = await resolver(root=root, info=info, filter=filter)
        if result:
            return result  # type: ignore
        if not inherit:
            return []
        parent = await OrganisationUnit.parent(root=root, info=info)  # type: ignore
        if parent is None:
            return []
        return await OrganisationUnit.owners(
            self=self, root=parent, info=info, inherit=True
        )

    addresses: list[LazyAddress] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                address_resolver,
                {"org_units": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            Addresses for the organisation unit.

            Commonly contain addresses such as, their:
            * Location
            * Contact phone number
            * Contact email
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("address")],
    )

    leaves: list[LazyLeave] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                leave_resolver,
                {"org_units": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            Connection to employees leaves of absence relevant for the organisation unit.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("leave")],
    )

    associations: list[LazyAssociation] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                association_resolver,
                {"org_units": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            Associations for the organistion unit.

            May be an empty list if the organistion unit is purely hierarchical.
            This situation may occur especially in the middle or the organisation tree.
            """
        ),
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("association"),
        ],
    )

    itusers: list[LazyITUser] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                it_user_resolver,
                {"org_units": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            IT (service) accounts.

            May be an empty list if the organistion unit does not have any IT (service) accounts whatsoever.
            This situation may occur especially in the middle or the organisation tree.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("ituser")],
    )

    kles: list[LazyKLE] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                kle_resolver,
                {"org_units": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            KLE responsibilities for the organisation unit.

            Can help out with regards to GDPR by identifying which organisational units operate with sensitive tasks.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("kle")],
    )

    related_units: list[LazyRelatedUnit] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                related_unit_resolver,
                {"org_units": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            Related units for the organisational unit.
            """
        ),
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("related_unit"),
        ],
    )

    @strawberry.field(
        description="UUID of the parent organisation unit.",
        deprecation_reason=gen_uuid_field_deprecation("org_unit_hierarchy_model"),
    )
    async def org_unit_hierarchy(self, root: OrganisationUnitRead) -> UUID | None:
        return root.org_unit_hierarchy

    @strawberry.field(
        description="UUID of the parent organisation unit.",
        deprecation_reason=gen_uuid_field_deprecation("parent"),
    )
    async def parent_uuid(self, root: OrganisationUnitRead) -> UUID | None:
        return root.parent_uuid

    @strawberry.field(
        description="UUID of the organisation unit type.",
        deprecation_reason=gen_uuid_field_deprecation("unit_type"),
    )
    async def unit_type_uuid(self, root: OrganisationUnitRead) -> UUID | None:
        return root.unit_type_uuid

    @strawberry.field(
        description="UUID of the organisation unit level.",
        deprecation_reason=gen_uuid_field_deprecation("org_unit_level"),
    )
    async def org_unit_level_uuid(self, root: OrganisationUnitRead) -> UUID | None:
        return root.org_unit_level_uuid

    @strawberry.field(
        description="UUID of the time planning object.",
        deprecation_reason=gen_uuid_field_deprecation("time_planning"),
    )
    async def time_planning_uuid(self, root: OrganisationUnitRead) -> UUID | None:
        return root.time_planning_uuid

    validity: Validity = strawberry.auto

    # VALIDITY HACKS
    # see deprecation_reason's below

    @strawberry.field(
        description=dedent(
            """\
            Same as ancestors(), but with HACKs to enable validities.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
        deprecation_reason=dedent(
            """\
            Should only be used to query ancestors when validity dates have been specified, "
            "ex from_date & to_date."
            "Will be removed when sub-query date handling is implemented.
            """
        ),
    )
    async def ancestors_validity(
        self, root: OrganisationUnitRead, info: Info
    ) -> list[LazyOrganisationUnit]:
        parents = await validity_sub_query_hack(
            root.validity,
            OrganisationUnitRead,
            get_handler_for_type("org_unit"),
            {"uuid": uuid2list(root.parent_uuid)},
        )

        parent = max(
            parents,
            key=lambda ppm: ppm.validity.from_date,
            default=None,
        )

        if parent is None:
            return []

        parent_ancestors = await OrganisationUnit.ancestors_validity(self=self, root=parent, info=info)  # type: ignore
        return [parent] + parent_ancestors

    @strawberry.field(
        description=dedent(
            """\
            Same as associations(), but with HACKs to enable validities.
            """
        ),
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("association"),
        ],
        deprecation_reason=dedent(
            """\
            Should only be used to query associations when validity dates have been specified, "
            "ex from_date & to_date."
            "Will be removed when sub-query date handling is implemented.
            """
        ),
    )
    async def associations_validity(
        self, root: OrganisationUnitRead, info: Info
    ) -> list[LazyAssociation]:
        return await validity_sub_query_hack(
            root.validity,
            AssociationRead,
            get_handler_for_type("association"),
            {"tilknyttedeenheder": uuid2list(root.uuid)},
        )

    @strawberry.field(
        description=dedent(
            """\
            Same as addresses(), but with HACKs to enable validities.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("address")],
        deprecation_reason=dedent(
            """\
            Should only be used to query addresses when validity dates have been specified, "
            "ex from_date & to_date."
            "Will be removed when sub-query date handling is implemented.
            """
        ),
    )
    async def addresses_validity(
        self, root: OrganisationUnitRead, info: Info
    ) -> list[LazyAddress]:
        return await validity_sub_query_hack(
            root.validity,
            AddressRead,
            get_handler_for_type("address"),
            {"tilknyttedeenheder": uuid2list(root.uuid)},
        )

    @strawberry.field(
        description=dedent(
            """\
            Same as itusers(), but with HACKs to enable validities.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("ituser")],
        deprecation_reason=dedent(
            """\
            Should only be used to query itusers when validity dates have been specified, "
            "ex from_date & to_date."
            "Will be removed when sub-query date handling is implemented.
            """
        ),
    )
    async def itusers_validity(
        self, root: OrganisationUnitRead, info: Info
    ) -> list[LazyITUser]:
        return await validity_sub_query_hack(
            root.validity,
            ITUserRead,
            get_handler_for_type("it"),
            {"tilknyttedeenheder": uuid2list(root.uuid)},
        )


async def manager_resolver(
    info: Info,
    filter: ManagerFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve managers."""
    if filter is None:
        filter = ManagerFilter()

    await registration_filter(info, filter)

    kwargs = {}
    if filter.employee is not None or filter.employees is not None:
        kwargs["tilknyttedebrugere"] = await get_employee_uuids(info, filter)
    if filter.org_units is not None or filter.org_unit is not None:
        kwargs["tilknyttedeenheder"] = await get_org_unit_uuids(info, filter)
    if filter.responsibility is not None:
        class_filter = filter.responsibility or ClassFilter()
        kwargs["opgaver"] = await filter2uuids_func(class_resolver, info, class_filter)

    return await generic_resolver(
        ManagerRead,
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
        **kwargs,
    )


class GraphQLSchema(NextGraphQLVersion.schema):  # type: ignore
    @strawberry.field(
        description=dedent(
            """\
            Managerial roles for the organisation unit.

            May be empty in which case managers are usually inherited from parents.
            See the `inherit`-flag for details.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("manager")],
    )
    async def managers(
        self,
        root: OrganisationUnitRead,
        info: Info,
        filter: ManagerFilter | None = None,
        inherit: Annotated[
            bool,
            strawberry.argument(
                description=dedent(
                    """\
                    Whether to inherit managerial roles or not.

                    If managerial roles exist directly on this organisation unit, the flag does nothing and these managerial roles are returned.
                    However if no managerial roles exist directly, and this flag is:
                    * Not set: An empty list is returned.
                    * Is set: The result from calling `managers` with `inherit=True` on the parent of this organistion unit is returned.

                    Calling with `inherit=True` can help ensure that a manager is always found.
                    """
                )
            ),
        ] = False,
    ) -> list["Manager"]:
        if filter is None:
            filter = ManagerFilter()
        filter.org_units = [root.uuid]

        resolver = to_list(seed_resolver(manager_resolver))
        result = await resolver(root=root, info=info, filter=filter)
        if result:
            return result  # type: ignore
        if not inherit:
            return []
        parent = await OrganisationUnit.parent(root=root, info=info)  # type: ignore
        if parent is None:
            return []
        return await OrganisationUnit.managers(
            self=self, root=parent, info=info, inherit=True
        )


class GraphQLVersion(NextGraphQLVersion):
    """GraphQL Version 22."""

    version = 22
    schema = GraphQLSchema
