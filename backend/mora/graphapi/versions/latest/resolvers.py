# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import re
from collections.abc import Callable
from collections.abc import Iterable
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from functools import lru_cache
from typing import Any
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import and_
from sqlalchemy import between
from sqlalchemy import cast
from sqlalchemy import ColumnElement
from sqlalchemy import distinct
from sqlalchemy import func
from sqlalchemy import select
from starlette_context import context
from strawberry import UNSET
from strawberry.dataloader import DataLoader
from strawberry.types import Info

from ...middleware import set_graphql_dates
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
from .filters import RoleFilter
from .models import ClassRead
from .models import FacetRead
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
from mora.service.autocomplete.employees import search_employees
from mora.service.autocomplete.orgunits import search_orgunits
from ramodels.mo import EmployeeRead
from ramodels.mo import OrganisationUnitRead
from ramodels.mo.details import AddressRead
from ramodels.mo.details import AssociationRead
from ramodels.mo.details import EngagementRead
from ramodels.mo.details import ITSystemRead
from ramodels.mo.details import ITUserRead
from ramodels.mo.details import KLERead
from ramodels.mo.details import LeaveRead
from ramodels.mo.details import ManagerRead
from ramodels.mo.details import OwnerRead
from ramodels.mo.details import RelatedUnitRead
from ramodels.mo.details import RoleRead


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
        kwargs["omfang"] = filter.scope

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
    if filter.engagements is not None or filter.engagement is not None:
        kwargs["tilknyttedefunktioner"] = await get_engagement_uuids(info, filter)
    if (
        filter.address_types is not None
        or filter.address_type_user_keys is not None
        or filter.address_type is not None
    ):
        kwargs["organisatoriskfunktionstype"] = await _get_address_type_uuids(
            info, filter
        )

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


async def organisation_unit_resolver(
    info: Info,
    filter: OrganisationUnitFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve organisation units."""
    if filter is None:
        filter = OrganisationUnitFilter()

    await registration_filter(info, filter)

    async def _get_parent_uuids() -> list[UUID]:
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
        if filter.parents is None or filter.parent is None:
            org = await info.context["org_loader"].load(0)
            extend_uuids(org_unit_filter, [org.uuid])
        if filter.parents is not UNSET:
            extend_uuids(org_unit_filter, filter.parents)
        return await filter2uuids_func(
            organisation_unit_resolver, info, org_unit_filter
        )

    async def _get_hierarchy_uuids() -> list[UUID]:
        class_filter = filter.hierarchy or ClassFilter()
        # Handle deprecated filter
        extend_uuids(class_filter, filter.hierarchies)
        return await filter2uuids_func(class_resolver, info, class_filter)

    async def _get_subtree_uuids() -> list[UUID]:
        org_unit_filter = filter.subtree or OrganisationUnitFilter()
        return await filter2uuids_func(
            organisation_unit_resolver, info, org_unit_filter
        )

    def _virkning(cls: type[HasValidity]) -> Iterable[ColumnElement]:
        if filter.from_date is not None:
            yield cls.virkning_slut >= (
                func.now() if filter.from_date is UNSET else filter.from_date
            )
        if filter.to_date is not None:
            yield cls.virkning_start <= (
                func.now() if filter.to_date is UNSET else filter.to_date
            )

    query = (
        select(
            distinct(OrganisationEnhedRegistrering.organisationenhed_id),
        )
        .where(
            OrganisationEnhedRegistrering.lifecycle != cast("Slettet", LivscyklusKode),
            between(
                cursor.registration_time if cursor is not None else func.now(),
                OrganisationEnhedRegistrering.registreringstid_start,
                OrganisationEnhedRegistrering.registreringstid_slut,
            ),
        )
        .order_by(OrganisationEnhedRegistrering.organisationenhed_id)
    )

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
                    *_virkning(OrganisationEnhedAttrEgenskaber),
                )
            )
        )

    # Parents
    if filter.parent is not UNSET or filter.parents is not UNSET:
        # TODO: _get_parent_uuids should not be an awaitable
        parent_uuids = await _get_parent_uuids()
        query = query.where(
            OrganisationEnhedRegistrering.id.in_(
                select(
                    OrganisationEnhedRelation.organisationenhed_registrering_id
                ).where(
                    OrganisationEnhedRelation.rel_type
                    == cast("overordnet", OrganisationEnhedRelationKode),
                    OrganisationEnhedRelation.rel_maal_uuid.in_(parent_uuids),
                    *_virkning(OrganisationEnhedRelation),
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
                    *_virkning(OrganisationEnhedRelation),
                )
            )
        )

    # Subtree
    if filter.subtree is not UNSET:
        # The subtree filter finds subtrees which has at least one org unit matching
        # the given filter. In other words, find all the matching children leafs, and
        # then recursively find their ancestors.
        # TODO: _get_subtree_uuids should not be an awaitable
        base_leafs = await _get_subtree_uuids()
        leafs = (
            select(
                OrganisationEnhedRegistrering.organisationenhed_id,
            )
            .where(OrganisationEnhedRegistrering.organisationenhed_id.in_(base_leafs))
            .cte("cte", recursive=True)
        )
        parents = (
            select(
                OrganisationEnhedRelation.rel_maal_uuid,
            )
            .join(OrganisationEnhedRegistrering)
            .join(
                leafs,
                and_(
                    OrganisationEnhedRelation.rel_type
                    == cast("overordnet", OrganisationEnhedRelationKode),
                    OrganisationEnhedRegistrering.organisationenhed_id
                    == leafs.c.organisationenhed_id,
                ),
            )
        )
        ancestors = leafs.union(parents)
        query = query.where(
            OrganisationEnhedRegistrering.organisationenhed_id.in_(
                select(ancestors.c.organisationenhed_id)
            )
        )

    # Pagination. Must be done here since the generic_resolver (lora) does not support
    # filtering on UUIDs and limit/cursor at the same time.
    if limit is not None:
        query = query.limit(limit)
    if cursor is not None:
        query = query.offset(cursor.offset)

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

    kwargs = {}
    if filter.employee is not None or filter.employees is not None:
        kwargs["tilknyttedebrugere"] = await get_employee_uuids(info, filter)
    if filter.org_units is not None or filter.org_unit is not None:
        kwargs["tilknyttedeenheder"] = await get_org_unit_uuids(info, filter)
    if filter.itsystem_uuids is not None or filter.itsystem is not None:
        kwargs["tilknyttedeitsystemer"] = await _get_itsystem_uuids(info, filter)

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
    dataloader: DataLoader, uuids: list[UUID]
) -> dict[UUID, dict[str, Any]]:
    deduplicated_uuids = list(set(uuids))
    responses = await dataloader.load_many(deduplicated_uuids)
    # Filter empty objects, see: https://redmine.magenta-aps.dk/issues/51523.
    return {
        uuid: objects
        for uuid, objects in zip(deduplicated_uuids, responses)
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
    set_graphql_dates(dates)

    # UUIDs
    if filter.uuids is not None:
        if limit is not None or cursor is not None:
            raise ValueError("Cannot filter 'uuid' with 'limit' or 'cursor'")
        # Early return on empty UUID list
        if not filter.uuids:
            return dict()
        resolver_name = resolver_map[model]["loader"]
        return await get_by_uuid(info.context[resolver_name], filter.uuids)

    # User keys
    if filter.user_keys is not None:
        # Early return on empty user-key list
        if not filter.user_keys:
            return dict()
        # We need to explicitly use a 'SIMILAR TO' search in LoRa, as the default is
        # to 'AND' filters of the same name, i.e. 'http://lora?bvn=x&bvn=y' means
        # "bvn is x AND Y", which is never true. Ideally, we'd use a different query
        # parameter key for these queries - such as '&bvn~=foo' - but unfortunately
        # such keys are hard-coded in a LOT of different places throughout LoRa.
        # For this reason, it is easier to pass the sentinel in the VALUE at this
        # point in time.
        # Additionally, the values are regex-escaped since the joined string will be
        # interpreted as one big regular expression in LoRa's SQL.
        use_is_similar_sentinel = "|LORA-PLEASE-USE-IS-SIMILAR|"
        escaped_user_keys = (re.escape(k) for k in filter.user_keys)
        kwargs["bvn"] = use_is_similar_sentinel + "|".join(escaped_user_keys)

    # Pagination
    if limit is not None:
        kwargs["maximalantalresultater"] = limit
    if cursor is not None:
        kwargs["foersteresultat"] = cursor.offset
        kwargs["registreringstid"] = str(cursor.registration_time)

    resolver_name = resolver_map[model]["getter"]
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


async def role_resolver(
    info: Info,
    filter: RoleFilter | None = None,
    limit: LimitType = None,
    cursor: CursorType = None,
) -> Any:
    """Resolve roles."""
    if filter is None:
        filter = RoleFilter()

    await registration_filter(info, filter)

    kwargs = {}
    if filter.employee is not None or filter.employees is not None:
        kwargs["tilknyttedebrugere"] = await get_employee_uuids(info, filter)
    if filter.org_units is not None or filter.org_unit is not None:
        kwargs["tilknyttedeenheder"] = await get_org_unit_uuids(info, filter)

    return await generic_resolver(
        RoleRead,
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


def get_date_interval(
    from_date: datetime | None = UNSET, to_date: datetime | None = UNSET
) -> OpenValidityModel:
    """Get the date interval for GraphQL queries to support bitemporal lookups.

    Args:
        from_date: The lower bound of the request interval
        to_date: The upper bound of the request interval

    Raises:
        ValueError: If lower bound is none and upper bound is unset
        ValueError: If the interval is invalid, e.g. lower > upper
    """
    if from_date is UNSET:
        from_date = datetime.now(tz=timezone.utc)
    if to_date is UNSET:
        if from_date is None:
            raise ValueError(
                "Cannot infer UNSET to_date from interval starting at -infinity"
            )
        to_date = from_date + timedelta(milliseconds=1)
    return _get_open_validity(from_date, to_date)
