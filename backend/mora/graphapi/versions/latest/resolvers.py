# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import asyncio
import re
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from functools import lru_cache
from textwrap import dedent
from typing import Annotated
from typing import Any
from typing import cast as tcast
from uuid import UUID

import strawberry
from more_itertools import flatten
from more_itertools import unique_everseen
from pydantic import ValidationError
from sqlalchemy import and_
from sqlalchemy import between
from sqlalchemy import cast
from sqlalchemy import ColumnElement
from sqlalchemy import distinct
from sqlalchemy import exists
from sqlalchemy import func
from sqlalchemy import Select
from sqlalchemy import select
from starlette_context import context
from strawberry import UNSET
from strawberry.dataloader import DataLoader
from strawberry.types import Info
from strawberry.types.unset import UnsetType

from ...middleware import with_graphql_dates
from .filters import AddressFilter
from .filters import AssociationFilter
from .filters import BaseFilter
from .filters import ClassFilter
from .filters import EmployeeFilter
from .filters import EngagementFilter
from .filters import FacetFilter
from .filters import ITSystemFilter
from .filters import ITUserFilter
from .filters import KLEFilter
from .filters import LeaveFilter
from .filters import ManagerFilter
from .filters import OrganisationUnitFilter
from .filters import OwnerFilter
from .filters import RelatedUnitFilter
from .filters import RoleBindingFilter
from .graphql_utils import LoadKey
from .models import AddressRead
from .models import ClassRead
from .models import FacetRead
from .models import RoleBindingRead
from .paged import CursorType
from .paged import LimitType
from .resolver_map import resolver_map
from .validity import OpenValidityModel
from mora.audit import audit_log
from mora.db import HasValidity
from mora.db import LivscyklusKode
from mora.db import OrganisationEnhedAttrEgenskaber
from mora.db import OrganisationEnhedRegistrering
from mora.db import OrganisationEnhedRelation
from mora.db import OrganisationEnhedRelationKode
from mora.db import OrganisationEnhedTilsGyldighed
from mora.graphapi.gmodels.mo import EmployeeRead
from mora.graphapi.gmodels.mo import OrganisationUnitRead
from mora.graphapi.gmodels.mo.details import AssociationRead
from mora.graphapi.gmodels.mo.details import EngagementRead
from mora.graphapi.gmodels.mo.details import ITSystemRead
from mora.graphapi.gmodels.mo.details import ITUserRead
from mora.graphapi.gmodels.mo.details import KLERead
from mora.graphapi.gmodels.mo.details import LeaveRead
from mora.graphapi.gmodels.mo.details import ManagerRead
from mora.graphapi.gmodels.mo.details import OwnerRead
from mora.graphapi.gmodels.mo.details import RelatedUnitRead
from mora.service.autocomplete.employees import search_employees
from mora.service.autocomplete.orgunits import search_orgunits


async def filter2uuids_func(
    resolver_func: Callable,
    info: Info,
    filter: BaseFilter,
    mapper: Callable[[Any], list[UUID]] | None = None,
) -> list[UUID]:
    """Resolve into a list of UUIDs with the given filter.

    Args:
        resolver: The resolver used to resolve filters to UUIDs.
        info: The strawberry execution context.
        filter: Filter instance passed to the resolver.
        mapper: Mapping function from resolver return to UUIDs.

    Returns:
        A list of UUIDs.
    """
    mapper = mapper or (lambda objects: list(objects.keys()))

    # The current resolver implementation disallows combining UUIDs with other filters.
    # As the UUIDs returned from this function are only used for further filtering,
    # we can simply return them as-is, bypassing another lookup.
    # This is purely a performance optimization
    if filter.uuids is not None:
        return filter.uuids

    uuids = mapper(await resolver_func(info, filter=filter))
    if uuids:
        return uuids

    # If the user key(s) were not in found in LoRa, we would return an empty list here.
    # Unfortunately, filtering a key on an empty list in LoRa is equivalent to _not
    # filtering on that key at all_. This is obviously very confusing to anyone who has
    # ever used SQL, but we are too scared to change the behaviour. Instead, to
    # circumvent this issue, we send a UUID which we know (hope) is never present.
    return [UUID("00000000-baad-1dea-ca11-fa11fa11c0de")]


def extend_uuids(output_filter: BaseFilter, input: list[UUID] | None) -> None:
    if input is None:
        return
    output_filter.uuids = output_filter.uuids or []
    output_filter.uuids.extend(input)


def extend_user_keys(output_filter: BaseFilter, input: list[str] | None) -> None:
    if input is None:
        return
    output_filter.user_keys = output_filter.user_keys or []
    output_filter.user_keys.extend(input)


async def get_employee_uuids(info: Info, filter: Any) -> list[UUID]:
    employee_filter = filter.employee or EmployeeFilter()
    # Handle deprecated filter
    extend_uuids(employee_filter, filter.employees)
    return await filter2uuids_func(employee_resolver, info, employee_filter)


async def get_engagement_uuids(info: Info, filter: Any) -> list[UUID]:
    engagement_filter = filter.engagement or EngagementFilter()
    # Handle deprecated filter
    extend_uuids(engagement_filter, filter.engagements)
    return await filter2uuids_func(engagement_resolver, info, engagement_filter)


async def get_org_unit_uuids(info: Info, filter: Any) -> list[UUID]:
    org_unit_filter = filter.org_unit or OrganisationUnitFilter()
    # Handle deprecated filter
    extend_uuids(org_unit_filter, filter.org_units)
    return await filter2uuids_func(organisation_unit_resolver, info, org_unit_filter)


def to_similar(keys: list[str]) -> str:
    # We need to explicitly use a 'SIMILAR TO' search in LoRa, as the default is
    # to 'AND' filters of the same name, e.g. 'http://lora?bvn=x&bvn=y' means
    # "bvn is x AND Y", which is never true. Ideally, we'd use a different query
    # parameter key for these queries - such as '&bvn~=foo' - but unfortunately
    # such keys are hard-coded in a LOT of different places throughout LoRa.
    # For this reason, it is easier to pass the sentinel in the VALUE at this
    # point in time.
    # Additionally, the values are regex-escaped since the joined string will be
    # interpreted as one big regular expression in LoRa's SQL.
    use_is_similar_sentinel = "|LORA-PLEASE-USE-IS-SIMILAR|"
    escaped_keys = (re.escape(k) for k in keys)
    return use_is_similar_sentinel + "|".join(escaped_keys)


async def registration_filter(info: Info, filter: Any) -> None:
    if filter.registration is None:
        return

    from .registration import registration_resolver

    uuids = await filter2uuids_func(
        registration_resolver,
        info,
        filter.registration,
        lambda objects: [x.uuid for x in objects],
    )
    extend_uuids(filter, uuids)


async def facet_resolver(
    info: Info,
    filter: FacetFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve facets."""

    async def _get_parent_uuids(info: Info, filter: FacetFilter) -> list[UUID]:
        facet_filter = filter.parent or FacetFilter()
        # Handle deprecated filter
        extend_uuids(facet_filter, filter.parents)
        extend_user_keys(facet_filter, filter.parent_user_keys)
        return await filter2uuids_func(facet_resolver, info, facet_filter)

    if filter is None:
        filter = FacetFilter()

    await registration_filter(info, filter)

    kwargs = {}
    if (
        filter.parents is not None
        or filter.parent_user_keys is not None
        or filter.parent is not None
    ):
        kwargs["facettilhoerer"] = await _get_parent_uuids(info, filter)

    if info.context["version"] <= 19:
        filter = BaseFilter(  # type: ignore[assignment]
            uuids=filter.uuids,
            user_keys=filter.user_keys,
            from_date=None,  # from -inf
            to_date=None,  # to inf
        )

    return await generic_resolver(
        FacetRead,
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
        **kwargs,
    )


async def class_resolver(
    info: Info,
    filter: ClassFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve classes."""

    async def _get_facet_uuids(info: Info, filter: ClassFilter) -> list[UUID]:
        facet_filter = filter.facet or FacetFilter()
        # Handle deprecated filter
        extend_uuids(facet_filter, filter.facets)
        extend_user_keys(facet_filter, filter.facet_user_keys)
        return await filter2uuids_func(facet_resolver, info, facet_filter)

    async def _get_parent_uuids(info: Info, filter: ClassFilter) -> list[UUID]:
        class_filter = filter.parent or ClassFilter()
        # Handle deprecated filter
        extend_uuids(class_filter, filter.parents)
        extend_user_keys(class_filter, filter.parent_user_keys)
        return await filter2uuids_func(class_resolver, info, class_filter)

    if filter is None:
        filter = ClassFilter()

    await registration_filter(info, filter)

    kwargs: dict[str, Any] = {}
    if (
        filter.facets is not None
        or filter.facet_user_keys is not None
        or filter.facet is not None
    ):
        kwargs["facet"] = await _get_facet_uuids(info, filter)
    if (
        filter.parents is not None
        or filter.parent_user_keys is not None
        or filter.parent is not None
    ):
        kwargs["overordnetklasse"] = await _get_parent_uuids(info, filter)
    if filter.it_system is not None:
        kwargs["mapninger"] = await filter2uuids_func(
            it_system_resolver, info, filter.it_system
        )
    if filter.scope is not None:
        kwargs["omfang"] = to_similar(filter.scope)

    return await generic_resolver(
        ClassRead,
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
        **kwargs,
    )


async def address_resolver(
    info: Info,
    filter: AddressFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve addresses."""

    async def _get_address_type_uuids(info: Info, filter: AddressFilter) -> list[UUID]:
        class_filter = filter.address_type or ClassFilter()
        # Handle deprecated filter
        extend_uuids(class_filter, filter.address_types)
        extend_user_keys(class_filter, filter.address_type_user_keys)
        return await filter2uuids_func(class_resolver, info, class_filter)

    if filter is None:
        filter = AddressFilter()

    await registration_filter(info, filter)

    kwargs = {}
    if filter.employee is not None or filter.employees is not None:
        kwargs["tilknyttedebrugere"] = await get_employee_uuids(info, filter)
    if filter.org_units is not None or filter.org_unit is not None:
        kwargs["tilknyttedeenheder"] = await get_org_unit_uuids(info, filter)
    if (
        filter.address_types is not None
        or filter.address_type_user_keys is not None
        or filter.address_type is not None
    ):
        kwargs["organisatoriskfunktionstype"] = await _get_address_type_uuids(
            info, filter
        )
    if filter.visibility is not None:
        class_filter = filter.visibility or ClassFilter()
        # rel_type "opgaver" with objekt_type "synlighed" in mox
        # TODO: Support finding entries with visibility=None
        kwargs["opgaver"] = await filter2uuids_func(class_resolver, info, class_filter)

    tilknyttedefunktioner = []
    if filter.engagements is not None or filter.engagement is not None:
        tilknyttedefunktioner.extend(await get_engagement_uuids(info, filter))
    if filter.ituser is not None:
        tilknyttedefunktioner.extend(
            await filter2uuids_func(it_user_resolver, info, filter.ituser)
        )
    if tilknyttedefunktioner:
        kwargs["tilknyttedefunktioner"] = tilknyttedefunktioner

    return await generic_resolver(
        AddressRead,
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
        **kwargs,
    )


async def association_resolver(
    info: Info,
    filter: AssociationFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve associations."""

    async def _get_association_type_uuids(
        info: Info, filter: AssociationFilter
    ) -> list[UUID]:
        class_filter = filter.association_type or ClassFilter()
        # Handle deprecated filter
        extend_uuids(class_filter, filter.association_types)
        extend_user_keys(class_filter, filter.association_type_user_keys)
        return await filter2uuids_func(class_resolver, info, class_filter)

    if filter is None:
        filter = AssociationFilter()

    await registration_filter(info, filter)

    kwargs = {}
    if filter.employee is not None or filter.employees is not None:
        kwargs["tilknyttedebrugere"] = await get_employee_uuids(info, filter)
    if filter.org_units is not None or filter.org_unit is not None:
        kwargs["tilknyttedeenheder"] = await get_org_unit_uuids(info, filter)
    if (
        filter.association_types is not None
        or filter.association_type_user_keys is not None
        or filter.association_type is not None
    ):
        kwargs["organisatoriskfunktionstype"] = await _get_association_type_uuids(
            info, filter
        )

    associations = await generic_resolver(
        AssociationRead,
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
        **kwargs,
    )

    if filter.it_association is not None:
        filtered_data = {}
        for uuid, association_fields in associations.items():
            if filter.it_association:
                filtered_associations = [
                    association
                    for association in association_fields
                    if association.it_user_uuid is not None
                ]
            else:
                filtered_associations = [
                    association
                    for association in association_fields
                    if association.it_user_uuid is None
                ]
            if filtered_associations:
                filtered_data[uuid] = filtered_associations
        associations = filtered_data

    return associations


async def employee_resolver(
    info: Info,
    filter: EmployeeFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve employees."""
    if filter is None:
        filter = EmployeeFilter()

    await registration_filter(info, filter)

    if filter.query:
        if filter.uuids:
            raise ValueError("Cannot supply both filter.uuids and filter.query")
        filter.uuids = await search_employees(info.context["session"], filter.query)

    kwargs = {}
    if filter.cpr_numbers is not None:
        kwargs["tilknyttedepersoner"] = [
            f"urn:dk:cpr:person:{c}" for c in filter.cpr_numbers
        ]

    return await generic_resolver(
        EmployeeRead,
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
        **kwargs,
    )


async def engagement_resolver(
    info: Info,
    filter: EngagementFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve engagements."""
    if filter is None:
        filter = EngagementFilter()

    await registration_filter(info, filter)

    kwargs = {}
    if filter.employee is not None or filter.employees is not None:
        kwargs["tilknyttedebrugere"] = await get_employee_uuids(info, filter)
    if filter.org_units is not None or filter.org_unit is not None:
        kwargs["tilknyttedeenheder"] = await get_org_unit_uuids(info, filter)
    if filter.job_function is not None:
        class_filter = filter.job_function or ClassFilter()
        kwargs["opgaver"] = await filter2uuids_func(class_resolver, info, class_filter)

    return await generic_resolver(
        EngagementRead,
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
        **kwargs,
    )


async def manager_resolver(
    info: Info,
    filter: ManagerFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
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
        combined_results = defaultdict(list)

        if len(kwargs["tilknyttedeenheder"]) > 1:
            for org_unit in kwargs["tilknyttedeenheder"]:
                manager_result = await manager_resolver(
                    info, filter=ManagerFilter(org_units=[org_unit]), inherit=True
                )
                if manager_result:
                    for uuid, managers in manager_result.items():
                        combined_results[uuid].extend(managers)

        if combined_results:
            return combined_results
    if filter.responsibility is not None:
        class_filter = filter.responsibility or ClassFilter()
        kwargs["opgaver"] = await filter2uuids_func(class_resolver, info, class_filter)
    result = await generic_resolver(
        ManagerRead,
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
        **kwargs,
    )
    if result or not inherit:
        return result

    org_units = await organisation_unit_resolver(
        info, OrganisationUnitFilter(uuids=kwargs["tilknyttedeenheder"])
    )
    if not org_units:
        return []
    org_unit_as_list = list(flatten(org_units.values()))
    new_org_units = [org_unit.parent_uuid for org_unit in org_unit_as_list]
    return await manager_resolver(
        info, filter=ManagerFilter(org_units=new_org_units), inherit=True
    )


async def owner_resolver(
    info: Info,
    filter: OwnerFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve owners."""
    if filter is None:
        filter = OwnerFilter()

    # TODO: Owner filter

    kwargs = {}
    if filter.employee is not None or filter.employees is not None:
        kwargs["tilknyttedebrugere"] = await get_employee_uuids(info, filter)
    if filter.org_units is not None or filter.org_unit is not None:
        kwargs["tilknyttedeenheder"] = await get_org_unit_uuids(info, filter)
    if filter.owner is not None:
        kwargs["tilknyttedepersoner"] = await filter2uuids_func(
            employee_resolver, info, filter.owner
        )

    return await generic_resolver(
        OwnerRead,
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
        **kwargs,
    )


async def organisation_unit_resolver_query(
    info: Info,
    filter: OrganisationUnitFilter,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Select:
    # TODO: this function should not be an awaitable

    await registration_filter(info, filter)

    async def _get_parent_uuids() -> list[UUID] | Select:
        org_unit_filter = filter.parent or OrganisationUnitFilter()
        # Handle deprecated filter
        # parents vs parent values
        #       | UNSET | None    | xs
        # UNSET | noop  | root    | xs
        # None  | root  | root    | root+xs
        # ys    | ys    | root+ys | xs+ys
        #
        # The above assignment handles all parent=ys cases
        # Thus we only need to check for parents=xs and Nones

        # The root unit isn't really an org unit in the database, so we can't
        # craft a query which will fetch it. We assume the user didn't supply
        # any other filters if they're looking for the root unit and return its
        # UUID directly.
        root_org: UUID = (await info.context["org_loader"].load(0)).uuid
        if filter.parents is None or filter.parent is None:
            return [root_org]
        if filter.parents is not UNSET and root_org in filter.parents:
            if filter.parents != [root_org]:
                raise ValueError("Cannot filter root org unit with other org units")
            return [root_org]
        if org_unit_filter.uuids is not None and root_org in org_unit_filter.uuids:
            if org_unit_filter.uuids != [root_org]:
                raise ValueError("Cannot filter root org unit with other org units")
            return [root_org]
        if filter.parents is not UNSET:
            extend_uuids(org_unit_filter, filter.parents)
        return await organisation_unit_resolver_query(
            info=info,
            filter=org_unit_filter,
        )

    async def _get_hierarchy_uuids() -> list[UUID]:
        class_filter = filter.hierarchy or ClassFilter()
        # Handle deprecated filter
        extend_uuids(class_filter, filter.hierarchies)
        return await filter2uuids_func(class_resolver, info, class_filter)

    def _registrering() -> ColumnElement:
        return and_(
            OrganisationEnhedRegistrering.lifecycle != cast("Slettet", LivscyklusKode),
            between(
                cursor.registration_time if cursor is not None else func.now(),
                OrganisationEnhedRegistrering.registreringstid_start,
                OrganisationEnhedRegistrering.registreringstid_slut,
            ),
        )

    def _gyldighed() -> ColumnElement:
        return OrganisationEnhedRegistrering.id.in_(
            select(
                OrganisationEnhedTilsGyldighed.organisationenhed_registrering_id
            ).where(
                OrganisationEnhedTilsGyldighed.gyldighed == "Aktiv",
                _virkning(OrganisationEnhedTilsGyldighed),
            )
        )

    def _virkning(cls: type[HasValidity]) -> ColumnElement:
        start, end = get_sqlalchemy_date_interval(filter.from_date, filter.to_date)
        return and_(cls.virkning_start <= end, cls.virkning_slut > start)

    query = (
        select(
            distinct(OrganisationEnhedRegistrering.organisationenhed_id),
        )
        .where(
            _registrering(),
            _gyldighed(),
        )
        .order_by(
            OrganisationEnhedRegistrering.organisationenhed_id,
        )
    )

    if filter.engagement is not None:
        # TODO: This should be reimplemented in SQL; #60285
        # NOTE: Local import to avoid cyclic references
        from .schema import Response

        engagement_uuids = await engagement_resolver(info, filter.engagement)
        engagement_responses = [
            Response[EngagementRead](uuid=uuid) for uuid in engagement_uuids
        ]
        # NOTE: We have to set start != UNSET to invoke the new temporality behavior
        # TODO: Remove this code when the new temporality behavior is the default
        start = unset2date(filter.engagement.from_date)
        end = filter.engagement.to_date

        engagement_validities = await asyncio.gather(
            *[
                response.validities(root=response, info=info, start=start, end=end)
                for response in engagement_responses
            ]
        )
        org_unit_uuids = {
            engagement_validity.org_unit_uuid
            for engagement_validity in flatten(engagement_validities)
        }
        extend_uuids(filter, list(org_unit_uuids))

    # UUIDs
    if filter.uuids is not None:
        query = query.where(
            OrganisationEnhedRegistrering.organisationenhed_id.in_(filter.uuids)
        )

    # User keys
    if filter.user_keys is not None:
        query = query.where(
            OrganisationEnhedRegistrering.id.in_(
                select(
                    OrganisationEnhedAttrEgenskaber.organisationenhed_registrering_id
                ).where(
                    OrganisationEnhedAttrEgenskaber.brugervendtnoegle.in_(
                        filter.user_keys
                    ),
                    _virkning(OrganisationEnhedAttrEgenskaber),
                )
            )
        )

    # Name
    if filter.names is not UNSET and filter.names is not None:
        query = query.where(
            OrganisationEnhedRegistrering.id.in_(
                select(
                    OrganisationEnhedAttrEgenskaber.organisationenhed_registrering_id
                ).where(
                    OrganisationEnhedAttrEgenskaber.enhedsnavn.in_(filter.names),
                    _virkning(OrganisationEnhedAttrEgenskaber),
                )
            )
        )

    # Parents
    if filter.parent is not UNSET or filter.parents is not UNSET:
        parent_uuids = await _get_parent_uuids()
        query = query.where(
            OrganisationEnhedRegistrering.id.in_(
                select(
                    OrganisationEnhedRelation.organisationenhed_registrering_id
                ).where(
                    OrganisationEnhedRelation.rel_type
                    == cast("overordnet", OrganisationEnhedRelationKode),
                    OrganisationEnhedRelation.rel_maal_uuid.in_(parent_uuids),
                    _virkning(OrganisationEnhedRelation),
                )
            )
        )

    # Hierarchies
    if filter.hierarchy is not None or filter.hierarchies is not None:
        # TODO: _get_hierarchy_uuids should not be an awaitable
        hierarchy_uuids = await _get_hierarchy_uuids()
        query = query.where(
            OrganisationEnhedRegistrering.id.in_(
                select(
                    OrganisationEnhedRelation.organisationenhed_registrering_id
                ).where(
                    OrganisationEnhedRelation.rel_type
                    == cast("opmærkning", OrganisationEnhedRelationKode),
                    OrganisationEnhedRelation.rel_maal_uuid.in_(hierarchy_uuids),
                    _virkning(OrganisationEnhedRelation),
                )
            )
        )

    # Descendant
    if filter.descendant is not UNSET or filter.subtree is not UNSET:
        # Find all matching children and then recursively find their parents.
        if filter.descendant is not UNSET and filter.subtree is not UNSET:
            raise ValueError("Cannot use both `descendant` and `subtree` filter")
        org_unit_filter = (
            filter.descendant or filter.subtree or OrganisationUnitFilter()
        )
        base_leafs = await organisation_unit_resolver_query(
            info=info,
            filter=org_unit_filter,
        )
        leafs = (
            select(
                OrganisationEnhedRegistrering.organisationenhed_id,
            )
            .where(OrganisationEnhedRegistrering.organisationenhed_id.in_(base_leafs))
            .cte("descendant_cte", recursive=True)
        )
        parents = (
            select(
                OrganisationEnhedRelation.rel_maal_uuid,
            )
            .join(
                OrganisationEnhedRegistrering,
            )
            .where(
                _registrering(),
            )
            .join(
                leafs,
                and_(
                    OrganisationEnhedRelation.rel_type
                    == cast("overordnet", OrganisationEnhedRelationKode),
                    OrganisationEnhedRegistrering.organisationenhed_id
                    == leafs.c.organisationenhed_id,
                    _virkning(OrganisationEnhedRelation),
                ),
            )
        )
        ancestors = leafs.union(parents)
        query = query.where(
            OrganisationEnhedRegistrering.organisationenhed_id.in_(
                select(ancestors.c.organisationenhed_id)
            )
        )

    # Ancestor
    if filter.ancestor is not UNSET:
        # Find all matching parents and then recursively find their children.
        org_unit_filter = filter.ancestor or OrganisationUnitFilter()
        base_query = await organisation_unit_resolver_query(
            info=info,
            filter=org_unit_filter,
        )
        base = (
            select(
                OrganisationEnhedRegistrering.organisationenhed_id,
            )
            .where(OrganisationEnhedRegistrering.organisationenhed_id.in_(base_query))
            .cte("ancestor_cte", recursive=True)
        )
        children = (
            select(
                OrganisationEnhedRegistrering.organisationenhed_id,
            )
            .join(
                OrganisationEnhedRelation,
            )
            .where(
                _registrering(),
                _virkning(OrganisationEnhedRelation),
            )
            .join(
                base,
                and_(
                    OrganisationEnhedRelation.rel_type
                    == cast("overordnet", OrganisationEnhedRelationKode),
                    OrganisationEnhedRelation.rel_maal_uuid
                    == base.c.organisationenhed_id,
                ),
            )
        )
        descendants = base.union(children)
        query = query.where(
            OrganisationEnhedRegistrering.organisationenhed_id.in_(
                select(descendants.c.organisationenhed_id)
            )
        )

    # Pagination. Must be done here since the generic_resolver (lora) does not support
    # filtering on UUIDs and limit/cursor at the same time.
    if limit is not None:
        query = query.limit(limit)
    if cursor is not None:
        query = query.offset(cursor.offset)

    return query


async def organisation_unit_resolver(
    info: Info,
    filter: OrganisationUnitFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve organisation units."""
    if filter is None:
        filter = OrganisationUnitFilter()

    query = await organisation_unit_resolver_query(
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
    )

    # Execute
    session = info.context["session"]
    result = await session.execute(query)
    uuids = [row[0] for row in result]

    # See lora.py:fetch()'s is_paged
    is_paged = limit != 0 and cursor is not None and cursor.offset > 0
    if not uuids and is_paged:
        # There may be multiple LoRa fetches in one GraphQL request, so this
        # cannot be refactored into always overwriting the value.
        context["lora_page_out_of_range"] = True

    # Query search
    if filter.query:
        if limit is not None or cursor is not None:
            raise ValueError("The query filter does not work with limit/cursor.")
        query_uuids = await search_orgunits(session, filter.query)
        uuids = list(sorted(set(uuids).intersection(query_uuids)))

    audit_log(
        session,
        "filter_orgunits",
        "OrganisationEnhed",
        {
            "filter": filter,
            "limit": limit,
            "cursor": cursor,
        },
        uuids,
    )

    return await generic_resolver(
        OrganisationUnitRead,
        info=info,
        filter=BaseFilter(
            uuids=uuids,
            from_date=filter.from_date,
            to_date=filter.to_date,
        ),
    )


async def organisation_unit_has_children(
    info: Info,
    filter: OrganisationUnitFilter | None,
) -> bool:
    """Resolve whether an organisation unit has children."""
    assert filter is not None  # cannot be None, but signature required for seeding
    query = await organisation_unit_resolver_query(info=info, filter=filter)
    session = info.context["session"]
    return await session.scalar(select(exists(query)))


async def organisation_unit_child_count(
    info: Info,
    filter: OrganisationUnitFilter | None,
) -> int:
    """Resolve the number of children of an organisation unit."""
    assert filter is not None  # cannot be None, but signature required for seeding
    query = await organisation_unit_resolver_query(info=info, filter=filter)
    session = info.context["session"]
    return await session.scalar(select(func.count()).select_from(query.subquery()))


async def it_system_resolver(
    info: Info,
    filter: ITSystemFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    if filter is None:
        filter = ITSystemFilter()

    await registration_filter(info, filter)

    return await generic_resolver(
        ITSystemRead,
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
    )


async def it_user_resolver(
    info: Info,
    filter: ITUserFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve it-users."""

    async def _get_itsystem_uuids(info: Info, filter: ITUserFilter) -> list[UUID]:
        itsystem_filter = filter.itsystem or ITSystemFilter()
        # Handle deprecated filter
        extend_uuids(itsystem_filter, filter.itsystem_uuids)
        return await filter2uuids_func(it_system_resolver, info, itsystem_filter)

    if filter is None:
        filter = ITUserFilter()

    await registration_filter(info, filter)

    kwargs: dict[str, Any] = {}
    if filter.employee is not None or filter.employees is not None:
        kwargs["tilknyttedebrugere"] = await get_employee_uuids(info, filter)
    if filter.org_units is not None or filter.org_unit is not None:
        kwargs["tilknyttedeenheder"] = await get_org_unit_uuids(info, filter)
    if filter.itsystem_uuids is not None or filter.itsystem is not None:
        kwargs["tilknyttedeitsystemer"] = await _get_itsystem_uuids(info, filter)
    if filter.engagement is not None:
        kwargs["tilknyttedefunktioner"] = await filter2uuids_func(
            engagement_resolver, info, filter.engagement
        )
    if filter.external_ids is not None:
        # Early return on empty external_id list
        if not filter.external_ids:
            return dict()
        kwargs["udvidelse_1"] = to_similar(filter.external_ids)

    return await generic_resolver(
        ITUserRead,
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
        **kwargs,
    )


async def kle_resolver(
    info: Info,
    filter: KLEFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve kle."""
    if filter is None:
        filter = KLEFilter()

    await registration_filter(info, filter)

    kwargs = {}
    if filter.org_units is not None or filter.org_unit is not None:
        kwargs["tilknyttedeenheder"] = await get_org_unit_uuids(info, filter)

    return await generic_resolver(
        KLERead,
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
        **kwargs,
    )


async def leave_resolver(
    info: Info,
    filter: LeaveFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve leaves."""
    if filter is None:
        filter = LeaveFilter()

    await registration_filter(info, filter)

    kwargs = {}
    if filter.employee is not None or filter.employees is not None:
        kwargs["tilknyttedebrugere"] = await get_employee_uuids(info, filter)
    if filter.org_units is not None or filter.org_unit is not None:
        kwargs["tilknyttedeenheder"] = await get_org_unit_uuids(info, filter)

    return await generic_resolver(
        LeaveRead,
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
        **kwargs,
    )


# type: ignore[no-untyped-def,override]
async def get_by_uuid(
    dataloader: DataLoader, keys: list[LoadKey]
) -> dict[UUID, dict[str, Any]]:
    deduplicated_keys = list(unique_everseen(keys))
    responses = await dataloader.load_many(deduplicated_keys)
    # Filter empty objects, see: https://redmine.magenta-aps.dk/issues/51523.
    return {
        key.uuid: objects
        for key, objects in zip(deduplicated_keys, responses)
        if objects != []
    }


async def generic_resolver(
    model: Any,
    # Ordinary
    info: Info,
    filter: BaseFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
    **kwargs: Any,
) -> Any:
    """The internal resolve interface, allowing for kwargs."""
    # Filter
    if filter is None:
        filter = BaseFilter()

    # Dates
    dates = get_date_interval(filter.from_date, filter.to_date)
    # UUIDs
    if filter.uuids is not None:
        if limit is not None or cursor is not None:
            raise ValueError("Cannot filter 'uuid' with 'limit' or 'cursor'")
        # Early return on empty UUID list
        if not filter.uuids:
            return dict()
        resolver_name = resolver_map[model]["loader"]
        return await get_by_uuid(
            dataloader=info.context[resolver_name],
            keys=[
                LoadKey(uuid, dates.from_date, dates.to_date) for uuid in filter.uuids
            ],
        )

    # User keys
    if filter.user_keys is not None:
        # Early return on empty user-key list
        if not filter.user_keys:
            return dict()
        kwargs["bvn"] = to_similar(filter.user_keys)

    # Pagination
    if limit is not None:
        kwargs["maximalantalresultater"] = limit
    if cursor is not None:
        kwargs["foersteresultat"] = cursor.offset
        kwargs["registreringstid"] = str(cursor.registration_time)

    resolver_name = resolver_map[model]["getter"]
    with with_graphql_dates(dates):
        return await info.context[resolver_name](**kwargs)


async def related_unit_resolver(
    info: Info,
    filter: RelatedUnitFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve related units."""
    if filter is None:
        filter = RelatedUnitFilter()

    # TODO: Related unit filter

    kwargs = {}
    if filter.org_units is not None or filter.org_unit is not None:
        kwargs["tilknyttedeenheder"] = await get_org_unit_uuids(info, filter)

    return await generic_resolver(
        RelatedUnitRead,
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
        **kwargs,
    )


async def rolebinding_resolver(
    info: Info,
    filter: RoleBindingFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve roles."""
    if filter is None:
        filter = RoleBindingFilter()

    await registration_filter(info, filter)

    kwargs = {}
    if filter.org_units is not None or filter.org_unit is not None:
        kwargs["tilknyttedeenheder"] = await get_org_unit_uuids(info, filter)
    if filter.ituser is not None:
        kwargs["tilknyttedefunktioner"] = await filter2uuids_func(
            it_user_resolver, info, filter.ituser
        )

    return await generic_resolver(
        RoleBindingRead,
        info=info,
        filter=filter,
        limit=limit,
        cursor=cursor,
        **kwargs,
    )


@lru_cache(maxsize=128)
def _get_open_validity(
    from_date: datetime | None, to_date: datetime | None
) -> OpenValidityModel:
    try:
        return OpenValidityModel(from_date=from_date, to_date=to_date)
    except ValidationError as v_error:
        # Pydantic errors are ugly in GraphQL, so we get the msg part only
        message = ", ".join([err["msg"] for err in v_error.errors()])
        raise ValueError(message)


def unset2date(dt: datetime | UnsetType | None) -> datetime | None:
    """Convert a potentially unset datetime to a non-unset datetime.

    If the input has UNSET as a value, the current time in utc will be returned.

    Args:
        dt: A potentially unset or null datetime.

    Returns:
        A potentially null datetime.
    """
    if dt is UNSET:
        return datetime.now(tz=timezone.utc)
    return tcast(datetime | None, dt)


def get_date_interval(
    from_date: datetime | UnsetType | None = UNSET,
    to_date: datetime | UnsetType | None = UNSET,
) -> OpenValidityModel:
    """Get the date interval for GraphQL queries to support bitemporal lookups.

    Args:
        from_date: The lower bound of the request interval
        to_date: The upper bound of the request interval

    Raises:
        ValueError: If lower bound is none and upper bound is unset
        ValueError: If the interval is invalid, e.g. lower > upper
    """
    from_date = unset2date(from_date)
    if to_date is UNSET:
        if from_date is None:
            raise ValueError(
                "Cannot infer UNSET to_date from interval starting at -infinity"
            )
        to_date = from_date + timedelta(milliseconds=1)
    return _get_open_validity(from_date, to_date)


def get_sqlalchemy_date_interval(
    from_date: datetime | None = UNSET, to_date: datetime | None = UNSET
) -> tuple[datetime, datetime]:
    """Get the date interval for SQLAlchemy where-clauses to support bitemporal lookups."""
    dates = get_date_interval(from_date, to_date)
    return (
        dates.from_date or datetime.min,
        dates.to_date or datetime.max,
    )
