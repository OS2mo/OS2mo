# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from datetime import datetime
from functools import partial
from textwrap import dedent
from uuid import UUID

import strawberry
from more_itertools import bucket
from ra_utils.apply import apply
from sqlalchemy import column
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker as sqla_sessionmaker
from starlette_context import context
from strawberry.dataloader import DataLoader
from strawberry.types import Info

from ..latest.filters import gen_filter_string
from ..latest.filters import gen_filter_table
from .resolvers import CursorType
from .resolvers import get_date_interval
from .resolvers import LimitType
from .resolvers import PagedResolver
from mora.audit import audit_log
from mora.db import AuditLogOperation as AuditLogOperation
from mora.db import AuditLogRead as AuditLogRead


def get_audit_loaders(sessionmaker: sqla_sessionmaker) -> dict[str, DataLoader]:
    """Return dataloaders required for auditing functionality.

    Args:
        sessionmaker: The sessionmaker to run queries on.

    Returns:
        A dictionary of loaders required for auditing functionality.
    """
    return {
        "audit_read_loader": DataLoader(
            load_fn=partial(audit_read_loader, sessionmaker)
        )
    }


async def audit_read_loader(
    sessionmaker: sqla_sessionmaker, keys: list[UUID]
) -> list[list[UUID]]:
    """Load UUIDs registered as read for the given operation.

    Args:
        sessionmaker: The sessionmaker to run queries on.
        keys: List of operation UUIDs to lookup read UUIDs for.

    Returns:
        A list containing a sublist for each UUID in keys.
        Each sublist containing the UUIDs read by the operation.
    """
    query = select(AuditLogRead.operation_id, AuditLogRead.uuid).where(
        AuditLogRead.operation_id.in_(keys)
    )
    session = sessionmaker()
    async with session.begin():
        result = list(await session.execute(query))
        buckets = bucket(result, apply(lambda operation_id, _: operation_id))
        return [[uuid for _, uuid in buckets[key]] for key in keys]


@strawberry.type(
    description=dedent(
        """\
        AuditLog entry.

        Mostly useful for auditing purposes seeing when data-reads were done and by whom.
        """
    )
)
# Intentionally not including operation and arguments from the underlying table
# Once LoRa's API and the Service API has been removed, we may want to log the GraphQL query
class AuditLog:
    id: UUID = strawberry.field(
        description=dedent(
            """\
            UUID of the audit entry itself.
            """
        )
    )

    time: datetime = strawberry.field(
        description=dedent(
            """\
        When the read occured.

        Examples:
        * `"1970-01-01T00:00:00.000000+00:00"`
        * `"2019-12-18T12:55:15.348614+00:00"`
        """
        )
    )

    actor: UUID = strawberry.field(
        description=dedent(
            """\
        UUID of the actor (integration or user) who changed the data.

        Note:
        Currently mostly returns `"42c432e8-9c4a-11e6-9f62-873cf34a735f"`.
        Will eventually contain for the UUID of the integration or user who mutated data, based on the JWT token.
        """
        )
    )

    # Name of the entity model
    model: str = strawberry.field(
        description=dedent(
            """\
        Model of the modified entity.

        Examples:
        * `"class"`
        * `"employee"`
        * `"org_unit"`
        """
        )
    )

    # UUID of the modified entity
    @strawberry.field(
        description=dedent(
            """\
        UUIDs of entities that were read.
        """
        )
    )
    async def uuids(self, info: Info) -> list[UUID]:
        return await info.context["audit_read_loader"].load(self.id)


@strawberry.input(description="Audit log filter.")
class AuditLogFilter:
    ids: list[UUID] | None = strawberry.field(
        default=None, description=gen_filter_string("ID", "ids")
    )

    uuids: list[UUID] | None = strawberry.field(
        default=None, description=gen_filter_string("UUID", "uuids")
    )

    actors: list[UUID] | None = strawberry.field(
        default=None,
        description=dedent(
            """\
            Filter audit events by their reading actor.

            Can be used to select all data read by a particular user or integration.
            """
        )
        + gen_filter_table("actors"),
    )

    models: list[str] | None = strawberry.field(
        default=None,
        description=dedent(
            """\
            Filter audit events by their model type.

            Can be used to select all reads for a data type.
            """
        )
        + gen_filter_table("models"),
    )

    start: datetime | None = strawberry.field(
        default=None,
        description="Limit the elements returned by their starting validity.",
    )
    end: datetime | None = strawberry.field(
        default=None,
        description="Limit the elements returned by their ending validity.",
    )


class AuditLogResolver(PagedResolver):
    # TODO: Implement using a dataloader
    async def resolve(  # type: ignore[override]
        self,
        info: Info,
        filter: AuditLogFilter | None = None,
        limit: LimitType = None,
        cursor: CursorType = None,
    ) -> list[AuditLog]:
        if filter is None:
            filter = AuditLogFilter()

        query = select(AuditLogOperation)
        if filter.ids is not None:
            query = query.where(AuditLogOperation.id.in_(filter.ids))

        if filter.uuids is not None:
            subquery = select(AuditLogRead.operation_id).filter(
                AuditLogRead.uuid.in_(filter.uuids)
            )
            query = query.where(AuditLogOperation.id.in_(subquery))

        if filter.actors is not None:
            query = query.where(AuditLogOperation.actor.in_(filter.actors))

        if filter.models is not None:
            query = query.where(AuditLogOperation.model.in_(filter.models))

        if filter.start is not None or filter.end is not None:
            dates = get_date_interval(filter.start, filter.end)
            query = query.where(
                column("time").between(
                    dates.from_date or datetime(1, 1, 1),
                    dates.to_date or datetime(9999, 12, 31),
                )
            )

        # Order by UUID so the order of pagination is well-defined
        query = query.order_by(column("id"))
        if limit is not None:
            # Fetch one extra element to see if there is another page
            query = query.limit(limit + 1)
        query = query.offset(cursor or 0)

        session = info.context["sessionmaker"]()
        async with session.begin():
            result = list(await session.scalars(query))
            audit_log(
                session,
                "resolve_auditlog",
                "AuditLog",
                {
                    "limit": limit,
                    "cursor": cursor,
                    "uuids": filter.uuids,
                    "actors": filter.actors,
                    "models": filter.models,
                    "start": filter.start,
                    "end": filter.end,
                },
                [auditlog.id for auditlog in result],
            )

            if limit is not None:
                # Not enough results == no more pages
                if len(result) <= limit:
                    context["lora_page_out_of_range"] = True
                # Strip the extra element that was only used for page-checking
                elif len(result) == limit + 1:
                    result = result[:-1]

            return [
                AuditLog(
                    id=auditlog.id,
                    time=auditlog.time,
                    actor=auditlog.actor,
                    model=auditlog.model,
                )
                for auditlog in result
            ]
