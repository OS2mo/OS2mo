# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
"""Strawberry types describing the MO graph."""
import json
import re
from base64 import b64encode
from collections.abc import Callable
from datetime import date
from datetime import datetime
from datetime import time
from functools import partial
from functools import wraps
from itertools import chain
from textwrap import dedent
from typing import Annotated
from typing import Any
from typing import cast
from typing import Generic
from typing import get_args
from typing import TypeVar
from urllib.parse import urlparse
from uuid import UUID

import strawberry
from fastapi.encoders import jsonable_encoder
from more_itertools import one
from more_itertools import only
from pydantic import parse_obj_as
from starlette_context import context
from strawberry import UNSET
from strawberry.types import Info

from .filters import ITUserFilter
from .filters import OwnerFilter
from .graphql_utils import LoadKey
from .health import health_map
from .models import AddressRead
from .models import ClassRead
from .models import FacetRead
from .models import FileStore
from .models import OwnerInferencePriority
from .models import RoleBindingRead
from .permissions import gen_read_permission
from .permissions import IsAuthenticatedPermission
from .registration import Registration
from .registration import registration_resolver
from .resolver_map import resolver_map
from .resolvers import address_resolver
from .resolvers import association_resolver
from .resolvers import class_resolver
from .resolvers import employee_resolver
from .resolvers import engagement_resolver
from .resolvers import facet_resolver
from .resolvers import it_system_resolver
from .resolvers import it_user_resolver
from .resolvers import kle_resolver
from .resolvers import leave_resolver
from .resolvers import manager_resolver
from .resolvers import organisation_unit_child_count
from .resolvers import organisation_unit_has_children
from .resolvers import organisation_unit_resolver
from .resolvers import owner_resolver
from .resolvers import related_unit_resolver
from .resolvers import rolebinding_resolver
from .seed_resolver import seed_resolver
from .types import CPRType
from .validity import OpenValidity
from .validity import Validity
from mora import common
from mora import config
from mora import db
from mora.common import _create_graphql_connector
from mora.graphapi.gmodels.mo import EmployeeRead
from mora.graphapi.gmodels.mo import OpenValidity as RAMOpenValidity
from mora.graphapi.gmodels.mo import OrganisationRead
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
from mora.graphapi.middleware import with_graphql_dates
from mora.graphapi.versions.latest.readers import _extract_search_params
from mora.handler.reading import get_handler_for_type
from mora.handler.reading import ReadingHandler
from mora.service.address_handler import dar
from mora.service.address_handler import multifield_text
from mora.service.facet import is_class_uuid_primary
from mora.util import NEGATIVE_INFINITY
from mora.util import now
from mora.util import POSITIVE_INFINITY

# TODO: Remove RAModels dependency, be purely Strawberry models
# TODO: Deprecate all _uuid / _uuids relation fields in favor of relation objects
# TODO: Remove resolver filter parameters for single-object UUID-selected fields?
# TODO: Document everything fields on org-units


MOObject = TypeVar("MOObject")
R = TypeVar("R")


def raise_force_none_return_if_uuid_none(
    root: Any, get_uuid: Callable[[Any], UUID | None]
) -> list[UUID]:
    """Raise ForceNoneReturnError if uuid is None, a list with the uuid otherwise.

    Args:
        root: The root object from which the UUID will be extracted.
        get_uuid: Extractor function used to extract a UUID from root.

    Raises:
        ForceNonReturnError: If the extracted uuid is None.

    Returns:
        A list containing the UUID if the extracted uuid is not None.
    """
    uuid = get_uuid(root)
    if uuid is None:
        raise ForceNoneReturnError
    return uuid2list(uuid)


class ForceNoneReturnError(Exception):
    """Error to be raised to forcefully return None from decorated function.

    Note: The function that should forcefully return None must be decorated with
          `force_none_return_wrapper`.
    """

    pass


def force_none_return_wrapper(func: Callable) -> Callable:
    """Decorate a function to react to ForceNonReturnError.

    Args:
        func: The function to be decorated.

    Returns:
        A decorated function that returns None whenever ForceNonReturnError is raised.
    """

    @wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> R | None:
        try:
            return await func(*args, **kwargs)
        except ForceNoneReturnError:
            return None

    return wrapper


def result_translation(mapper: Callable) -> Callable:
    def wrapper(resolver_func: Callable) -> Callable:
        @wraps(resolver_func)
        async def mapped_resolver(*args: Any, **kwargs: Any) -> Any:
            result = await resolver_func(*args, **kwargs)
            return mapper(result)

        return mapped_resolver

    return wrapper


to_list = result_translation(
    lambda result: list(chain.from_iterable(result.values())),
)
to_only = result_translation(
    lambda result: only(chain.from_iterable(result.values())),
)
to_one = result_translation(
    lambda result: one(chain.from_iterable(result.values())),
)


def uuid2list(uuid: UUID | None) -> list[UUID]:
    """Convert an optional uuid to a list.

    Args:
        uuid: Optional uuid to wrap in a list.

    Return:
        Empty list if uuid was none, single element list containing the uuid otherwise.
    """
    if uuid is None:
        return []
    return [uuid]


def model2name(model: Any) -> Any:
    mapping = {
        ClassRead: "class",
        EmployeeRead: "employee",
        FacetRead: "facet",
        OrganisationUnitRead: "org_unit",
        AddressRead: "address",
        AssociationRead: "association",
        EngagementRead: "engagement",
        ITSystemRead: "itsystem",
        ITUserRead: "ituser",
        KLERead: "kle",
        LeaveRead: "leave",
        RoleBindingRead: "rolebinding",
        ManagerRead: "manager",
    }
    return mapping[model]


@strawberry.type(
    description=dedent(
        """\
    Top-level container for (bi)-temporal and actual state data access.

    Contains a UUID uniquely denoting the bitemporal object.

    Contains three different object temporality axis:

    | entrypoint      | temporal axis | validity time | assertion time |
    |-----------------|---------------|---------------|----------------|
    | `current`       | actual state  | current       | current        |
    | `objects`       | temporal      | varying       | current        |
    | `registrations` | bitemporal    | varying       | varying        |

    The argument for having three different entrypoints into the data is limiting complexity according to use-case.

    That is, if a certain integration or UI only needs, say, actual state data, the complexities of the bitemporal data modelling is unwanted complexity, and as such, better left out.
    """
    )
)
class Response(Generic[MOObject]):
    uuid: UUID = strawberry.field(description="UUID of the bitemporal object")

    # Object cache is a temporary workaround ensuring that current resolvers keep
    # working as-is while also allowing for lazy resolution based entirely on the UUID.
    object_cache: strawberry.Private[list[MOObject]] = UNSET

    @strawberry.field(
        description=dedent(
            """\
            Actual / current state entrypoint.

            Returns the state of the object at current validity and current assertion time.

            A single object is returned as only one validity can be active at a given assertion time.

            Note:
            This the entrypoint is appropriate to use for actual-state integrations and UIs.
            """
        ),
        permission_classes=[IsAuthenticatedPermission],
    )
    async def current(
        self, root: "Response", info: Info, at: datetime | None = UNSET
    ) -> MOObject | None:
        def active_now(obj: Any) -> bool:
            """Predicate on whether the object is active right now.

            Args:
                obj: The object to test.

            Returns:
                True if the object is active right now, False otherwise.
            """
            if not hasattr(obj, "validity"):
                return True

            from_date = obj.validity.from_date or NEGATIVE_INFINITY
            to_date = obj.validity.to_date or POSITIVE_INFINITY

            # TODO: This should just be a normal datetime compare, but due to legacy systems,
            #       ex dipex, we must use .date() to compare dates instead of datetimes.
            #       Remove when legacy systems handle datetimes properly.
            return from_date.date() <= now().date() <= to_date.date()

        def activity_tuple(obj: Any) -> datetime:
            if not hasattr(obj, "validity"):
                return datetime.min
            if obj.validity.to_date is None:
                return datetime.max
            return obj.validity.to_date

        if at:
            objects = await Response.validities(self, root, info, at, UNSET)
            return only(objects)

        # TODO: This should really do its own instantaneous query to find whatever is
        #       active right now, regardless of the values in objects.
        objects = await Response.validities(self, root, info)
        objects_active_now = filter(active_now, objects)

        # HACK: Due to legacy systems, ex dipex, we must use .date() to compare dates instead of datetimes.
        #       because of this, if we update entities on the same date shortly after each other,
        #       we may end up with multiple entities which are "active now", where only one is expected.
        #       To handle this, we first try to find an entity which is active now and has no end date.
        #       If we cannot find such an entity, we find the entity with largest to_date
        return max(objects_active_now, key=activity_tuple, default=None)

    @strawberry.field(
        description=dedent(
            """\
            Temporal state entrypoint.

            Returns the state of the object at varying validities and current assertion time.

            A list of objects are returned as only many different validity intervals can be active at a given assertion time.

            Note:
            This the entrypoint should be used for temporal integrations and UIs.
            For actual-state integrations, please consider using `current` instead.
            """
        ),
        permission_classes=[IsAuthenticatedPermission],
        deprecation_reason=dedent(
            """
            Will be removed in a future version of GraphQL.
            Use validities instead.
            """
        ),
    )
    async def objects(
        self,
        root: "Response",
        info: Info,
        start: datetime | None = UNSET,
        end: datetime | None = UNSET,
    ) -> list[MOObject]:
        objects = await Response.validities(self, root, info, start, end)
        return objects

    @strawberry.field(
        description=dedent(
            """\
            Temporal state entrypoint.

            Returns the state of the object at varying validities and current assertion time.

            A list of objects are returned as only many different validity intervals can be active at a given assertion time.

            Note:
            This the entrypoint should be used for temporal integrations and UIs.
            For actual-state integrations, please consider using `current` instead.
            """
        ),
        permission_classes=[IsAuthenticatedPermission],
    )
    async def validities(
        self,
        root: "Response",
        info: Info,
        start: datetime | None = UNSET,
        end: datetime | None = UNSET,
    ) -> list[MOObject]:
        if start is UNSET and end is UNSET and root.object_cache != UNSET:
            return root.object_cache
        # If the object cache has not been filled we must resolve objects using the uuid
        resolver = resolver_map[response2model(root)]["loader"]
        dataloader = info.context[resolver]
        return await dataloader.load(LoadKey(root.uuid, start, end))

    # TODO: Implement using a dataloader
    registrations: list[Registration] = strawberry.field(
        description=dedent(
            """\
            Bitemporal state entrypoint.

            Returns the state of the object at varying validities and varying assertion times.

            A list of bitemporal container objects are returned, each containing many different validity intervals.

            Note:
            This the entrypoint should only be used for bitemporal integrations and UIs, such as for auditing purposes.
            For temporal integration, please consider using `objects` instead.
            For actual-state integrations, please consider using `current` instead.

            **Warning**:
            This entrypoint should **not** be used to implement event-driven integrations.
            Such integration should rather utilize the AMQP-based event-system.
            """
        ),
        permission_classes=[IsAuthenticatedPermission],
        resolver=seed_resolver(
            registration_resolver,
            {
                "uuids": lambda root: uuid2list(root.uuid),
                "models": lambda root: [model2name(response2model(root))],
            },
        ),
    )


def response2model(response: Response[MOObject]) -> MOObject:
    if not hasattr(response, "__orig_class__"):
        raise ValueError(
            "Please ensure that `Response` is always instantiated with a type parameter, such as Response[Address](...) instead of Response(...)"
        )
    model = get_args(response.__orig_class__)[0]
    return model


LazySchema = strawberry.lazy(".schema")

LazyAddress = Annotated["Address", LazySchema]
LazyAssociation = Annotated["Association", LazySchema]
LazyClass = Annotated["Class", LazySchema]
LazyEmployee = Annotated["Employee", LazySchema]
LazyEngagement = Annotated["Engagement", LazySchema]
LazyFacet = Annotated["Facet", LazySchema]
LazyITSystem = Annotated["ITSystem", LazySchema]
LazyITUser = Annotated["ITUser", LazySchema]
LazyKLE = Annotated["KLE", LazySchema]
LazyLeave = Annotated["Leave", LazySchema]
LazyManager = Annotated["Manager", LazySchema]
LazyOwner = Annotated["Owner", LazySchema]
LazyOrganisationUnit = Annotated["OrganisationUnit", LazySchema]
LazyRelatedUnit = Annotated["RelatedUnit", LazySchema]
LazyRoleBinding = Annotated["RoleBinding", LazySchema]


def gen_uuid_field_deprecation(field: str) -> str:
    """Generate a deprecation warning for `_uuid` fields.

    Args:
        field: Name of the field that has the `_uuid` ending.

    Returns:
        Deprecation message explaining how to fetch the field in the future.
    """
    return dedent(
        f"""\
        Will be removed in a future version of GraphQL.
        Use `{field} {{uuid}}` instead.
        """
    )


# TODO: Remove list and make optional instead all the places this is used
list_to_optional_field_warning = dedent(
    """\

    **Warning**:
    This field will probably become an optional entity instead of a list in the future.
    """
)


async def validity_sub_query_hack(
    root_validity: RAMOpenValidity,
    item_type: type[Any],
    item_reading_handler: ReadingHandler,
    item_lora_query_args: dict,
) -> list[Any]:
    # Custom Lora-GraphQL connector - created in order to control dates in sub-queries/recursions
    if root_validity.to_date:
        # FYI: This is needed when ex root.validity.to_date == item.validity.from_date
        # If we just use "root_validity.to_date" where ex time is "00:00:00",
        # LoRa will return no results, since it needs the time to be "23:59:59" to be inclusive.
        root_validity = RAMOpenValidity(
            from_date=root_validity.from_date,
            to_date=datetime.combine(root_validity.to_date.date(), time.max),
        )

    with with_graphql_dates(root_validity):
        c = _create_graphql_connector()

    # potential items
    item_potentials = await item_reading_handler.get(
        c=c,
        search_fields=_extract_search_params(query_args=item_lora_query_args),
    )
    item_potentials_models = parse_obj_as(list[item_type], item_potentials)  # type: ignore

    # Filter out items where to_date is before root_validity.from_date
    item_potentials_models = list(
        filter(
            lambda ipm: (  # type: ignore
                root_validity.from_date is None  # type: ignore
                or ipm.validity.to_date is None  # type: ignore
                or ipm.validity.to_date  # type: ignore
                >= root_validity.from_date  # type: ignore
            ),
            item_potentials_models,
        )
    )

    # Filter out items where from_date is after root_validity.to_date
    item_potentials_models = list(
        filter(
            lambda ipm: (  # type: ignore
                root_validity.to_date is None  # type: ignore
                or ipm.validity.from_date is None  # type: ignore
                or ipm.validity.from_date  # type: ignore
                <= root_validity.to_date  # type: ignore
            ),
            item_potentials_models,
        )
    )

    # Go through models versions and if there are multiple with the same UUID,
    # use the one with the earliest from_date
    items_final: list[item_type] = []  # type: ignore
    for item in item_potentials_models:
        existing_item = next(
            (i for i in items_final if i.uuid == item.uuid),  # type: ignore
            None,
        )
        if existing_item is None:
            items_final.append(item)
        else:
            # Handle the case where either from_date could be None
            if existing_item.validity.from_date is None or (
                item.validity.from_date is not None
                and item.validity.from_date  # type: ignore
                < existing_item.validity.from_date  # type: ignore
            ):
                items_final.remove(existing_item)
                items_final.append(item)

    return items_final


# Address
# -------


@strawberry.interface
class ResolvedAddress:
    value: str


@strawberry.type
class DefaultAddress(ResolvedAddress):
    pass


@strawberry.type
class MultifieldAddress(ResolvedAddress):
    value2: str

    @strawberry.field
    async def name(self, root: "MultifieldAddress") -> str:
        return multifield_text.name(root.value, root.value2)


def extract_field(field: str) -> Any:
    @strawberry.field
    async def extractor(self: Any, root: "DARAddress") -> Any:
        dar_response = await root.resolve_dar(root)
        return dar_response[field]

    return extractor


@strawberry.type
class DARAddress(ResolvedAddress):
    # Lookup the UUID in DAR, cached via the dataloader
    async def resolve_dar(self, root: "DARAddress") -> dict[str, Any]:
        dar_loader = context["dar_loader"]
        return await dar_loader.load(UUID(root.value))

    # Unstructured fields, provided and computed
    description: str = extract_field("betegnelse")

    @strawberry.field
    async def name(self, root: "DARAddress") -> str:
        dar_response = await root.resolve_dar(root)
        return dar.name_from_dar_object(dar_response)

    # Structured fields
    road_code: int = extract_field("vejkode")
    road_name: str = extract_field("vejnavn")
    house_number: str = extract_field("husnr")
    floor: str | None = extract_field("etage")
    door: str | None = extract_field("dør")
    zip_code: str = extract_field("postnr")
    zip_code_name: str = extract_field("postnrnavn")
    municipality_code: str = extract_field("kommunekode")

    # Global position
    longitude: float = extract_field("x")
    latitude: float = extract_field("y")

    # Links
    @strawberry.field
    async def href(self, root: "DARAddress") -> str:
        dar_response = await root.resolve_dar(root)
        href = dar_response["href"]
        return urlparse(href)._replace(scheme="https").geturl()

    @strawberry.field
    async def streetmap_href(self, root: "DARAddress") -> str | None:
        dar_response = await root.resolve_dar(root)
        return dar.open_street_map_href_from_dar_object(dar_response)


@strawberry.experimental.pydantic.type(
    model=AddressRead,
    description=dedent(
        """\
        Address information for either an employee or organisational unit
        """
    ),
)
class Address:
    address_type: LazyClass = strawberry.field(
        resolver=to_one(
            seed_resolver(
                class_resolver, {"uuids": lambda root: [root.address_type_uuid]}
            )
        ),
        description=dedent(
            """\
            The address category or type.

            In OS2mo addresses can be of a variety of different types:
            * Phone numbers
            * Addresses
            * Registration numbers
            * Card codes

            This field is what encodes the type of an address.

            Examples of user-keys:
            * `"EmailUnit"`
            * `"p-nummer"`
            * `"PhoneEmployee"`
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    visibility: LazyClass | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                class_resolver, {"uuids": lambda root: uuid2list(root.visibility_uuid)}
            )
        ),
        description=dedent(
            """\
            Determines who can see the address and how it is exported.

            In OS2mo addresses can be of a variety of privacy classes.
            For instance OS2mo may contain a list of phone numbers for an employee;
            * A private mobile phone number
            * An internal work mobile phone number
            * A shared external phone number

            This field is what encodes the privacy class of an address.
            Thereby stating who should be allowed to see what addresses.

            Examples of user-keys:
            * `null`: Undetermined / non-classified.
            * `"Secret"`: Should be treated carefully and perhaps not be exported.
            * `"Internal"` Should be treated carefully but perhaps exposed to an internal intranet.
            * `"External"`: Can probably be exposed to the internet
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    employee: list[LazyEmployee] | None = strawberry.field(
        resolver=force_none_return_wrapper(
            to_list(
                seed_resolver(
                    employee_resolver,
                    {
                        "uuids": partial(
                            raise_force_none_return_if_uuid_none,
                            get_uuid=lambda root: root.employee_uuid,
                        )
                    },
                )
            ),
        ),
        description=dedent(
            """\
            Connected employee.

            Note:
            This field is mutually exclusive with the `org_unit` field.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("employee")],
        deprecation_reason="Use 'person' instead. Will be removed in a future version of OS2mo.",
    )

    person: list[LazyEmployee] | None = strawberry.field(
        resolver=force_none_return_wrapper(
            to_list(
                seed_resolver(
                    employee_resolver,
                    {
                        "uuids": partial(
                            raise_force_none_return_if_uuid_none,
                            get_uuid=lambda root: root.employee_uuid,
                        )
                    },
                )
            ),
        ),
        description=dedent(
            """\
            Connected person.

            Note:
            This field is mutually exclusive with the `org_unit` field.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("employee")],
    )

    org_unit: list[LazyOrganisationUnit] | None = strawberry.field(
        resolver=force_none_return_wrapper(
            to_list(
                seed_resolver(
                    organisation_unit_resolver,
                    {
                        "uuids": partial(
                            raise_force_none_return_if_uuid_none,
                            get_uuid=lambda root: root.org_unit_uuid,
                        )
                    },
                )
            ),
        ),
        description=dedent(
            """\
            Connected organisation unit.

            Note:
            This field is mutually exclusive with the `employee` field.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
    )

    engagement: list[LazyEngagement] | None = strawberry.field(
        resolver=force_none_return_wrapper(
            to_list(
                seed_resolver(
                    engagement_resolver,
                    {
                        "uuids": partial(
                            raise_force_none_return_if_uuid_none,
                            get_uuid=lambda root: root.engagement_uuid,
                        )
                    },
                )
            )
        ),
        description=dedent(
            """\
            Connected engagement.

            Note:
            This field is **not** mutually exclusive with neither the `employee` nor the `org_unit` field.
            """
        ),
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("engagement"),
        ],
    )

    ituser: list[LazyITUser] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                it_user_resolver, {"uuids": lambda root: uuid2list(root.it_user_uuid)}
            )
        ),
        description="Connected IT-user.\n",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("ituser")],
    )

    @strawberry.field(
        description=dedent(
            """\
        Human readable name of the address.

        Name is *usually* equal to `value`, but may differ if `value` is not human readable.
        This may for instance be the case for `DAR` addresses, where the value is the DAR UUID, while the name is a human readable address.

        This is the value that should be shown to users in UIs.

        Examples:
        * `"Vifdam 20, 1. th, 6000 Kolding"`
        * `"25052943"`
        * `"info@magenta.dk"`
        * `"Building 11"`

        Note:
        Requesting this field may incur a performance penalty as the returned value may be dynamically resolved from the `value`-field.
        """
        )
    )
    async def name(self, root: AddressRead, info: Info) -> str | None:
        address_type = await Address.address_type(root=root, info=info)  # type: ignore[operator]

        if address_type.scope == "MULTIFIELD_TEXT":
            return multifield_text.name(root.value, root.value2)

        if address_type.scope == "DAR":
            dar_loader = context["dar_loader"]
            address_object = await dar_loader.load(UUID(root.value))
            return dar.name_from_dar_object(address_object)

        return root.value

    @strawberry.field
    async def resolve(self, root: AddressRead, info: Info) -> ResolvedAddress:
        address_type = await Address.address_type(root=root, info=info)  # type: ignore[operator]

        if address_type.scope == "MULTIFIELD_TEXT":
            return MultifieldAddress(value=root.value, value2=root.value2)  # type: ignore

        if address_type.scope == "DAR":
            return DARAddress(value=root.value)  # type: ignore

        return DefaultAddress(value=root.value)  # type: ignore

    @strawberry.field(
        description=dedent(
            """\
        Hypertext Reference of the address.

        The `href` field makes a hyperlink from the address value, such that the link can be included in user interfaces.

        Examples:
        * `null`: For non-hyperlinkable addresses.
        * `"tel:88888888"`: For phone numbers.
        * `"mailto:info@magenta.dk"`: For email addresses.
        * `"https://www.openstreetmap.org/?mlon=11&mlat=56"`: For postal addresses, locations, etc

        Note:
        Requesting this field may incur a performance penalty as the returned value may be dynamically resolved from the `value`-field.

        """
        )
    )
    async def href(self, root: AddressRead, info: Info) -> str | None:
        address_type = await Address.address_type(root=root, info=info)  # type: ignore[operator]

        if address_type.scope == "PHONE":
            return f"tel:{root.value}"

        if address_type.scope == "EMAIL":
            return f"mailto:{root.value}"

        if address_type.scope == "DAR":
            dar_loader = context["dar_loader"]
            address_object = await dar_loader.load(UUID(root.value))
            if address_object is None:
                return None
            return dar.open_street_map_href_from_dar_object(address_object)

        return None

    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: AddressRead) -> UUID:
        return root.uuid

    @strawberry.field(
        description=dedent(
            """\
            Short unique key.

            Usually set to the `value` provided on object creation.
            May also be set to the key used in external systems.

            Examples:
            * `"25052943"`
            * `"info@magenta.dk"`
            * `"Building 11"`
            """
        )
    )
    async def user_key(self, root: AddressRead) -> str:
        return root.user_key

    @strawberry.field(
        description=dedent(
            """\
            The object type.

            Always contains the string `address`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Unintentionally exposed implementation detail.
            Provides no value whatsoever.
            """
        ),
    )
    async def type(self, root: AddressRead) -> str:
        """Implemented for backwards compatability."""
        return root.type_

    @strawberry.field(
        description="UUID of the address type class.",
        deprecation_reason=gen_uuid_field_deprecation("address_type"),
    )
    async def address_type_uuid(self, root: AddressRead) -> UUID:
        return root.address_type_uuid

    @strawberry.field(
        description="UUID of the employee related to the address.",
        deprecation_reason=gen_uuid_field_deprecation("employee"),
    )
    async def employee_uuid(self, root: AddressRead) -> UUID | None:
        return root.employee_uuid

    @strawberry.field(
        description="UUID of the organisation unit related to the address.",
        deprecation_reason=gen_uuid_field_deprecation("org_unit"),
    )
    async def org_unit_uuid(self, root: AddressRead) -> UUID | None:
        return root.org_unit_uuid

    @strawberry.field(
        description="Optional UUID of an associated engagement.",
        deprecation_reason=gen_uuid_field_deprecation("engagement"),
    )
    async def engagement_uuid(self, root: AddressRead) -> UUID | None:
        return root.engagement_uuid

    @strawberry.field(
        description="UUID of the visibility class of the address.",
        deprecation_reason=gen_uuid_field_deprecation("visibility"),
    )
    async def visibility_uuid(self, root: AddressRead) -> UUID | None:
        return root.visibility_uuid

    @strawberry.field(
        description=dedent(
            """\
            Machine processable value of the address.

            The value of the address, which may or may not be fit for human consumption.
            If an address for human consumption is required, consider using `name` or `href` instead.

            Examples:
            * `"3cb0a0c6-37d0-0e4a-e044-0003ba298018"`
            * `"25052943"`
            * `"info@magenta.dk"`
            * `"Building 11"`
            """
        )
    )
    async def value(self, root: AddressRead) -> str:
        return root.value

    @strawberry.field(
        description=dedent(
            """\
            Optional second machine processable value of the address.

            This value is `null` for most address types, but may be utilized by some address-types for extra information.

            Examples:
            * `null`
            * `"Office 12"`
            * `"+45"`
            """
        )
    )
    async def value2(self, root: AddressRead) -> str | None:
        return root.value2

    validity: Validity = strawberry.auto

    # VALIDITY HACKS

    @strawberry.field(
        description=dedent(
            """\
            Same as address_type, but with HACKs to enable validities.
            """
        ),
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("class"),
        ],
        deprecation_reason=dedent(
            """\
            Should only be used to query address_type when validity dates have been specified, "
            "ex from_date & to_date."
            "Will be removed when sub-query date handling is implemented.
            """
        ),
    )
    async def address_type_validity(self, root: AddressRead) -> LazyClass | None:
        address_types = await validity_sub_query_hack(
            root.validity,
            ClassRead,
            get_handler_for_type("class"),
            {"uuid": uuid2list(root.address_type_uuid)},
        )

        return address_types[0] if address_types else None


# Association
# -----------


@strawberry.experimental.pydantic.type(
    model=AssociationRead,
    description="Connects organisation units and employees",
)
class Association:
    association_type: LazyClass | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                class_resolver,
                {"uuids": lambda root: uuid2list(root.association_type_uuid)},
            )
        ),
        description=dedent(
            """\
            The type of connection that the employee has to the organisation unit.

            Examples:
            * `"Chairman"`
            * `"Leader"`
            * `"Employee"`
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    dynamic_class: LazyClass | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                class_resolver,
                {"uuids": lambda root: uuid2list(root.dynamic_class_uuid)},
            )
        ),
        # TODO: Document this
        # https://git.magenta.dk/rammearkitektur/os2mo/-/merge_requests/1694#note_216859
        description=dedent(
            """\
            List of arbitrary classes.

            The purpose of this field is ill-defined.
            It is currently mainly used for (trade) union specification.
            """
        ),
        deprecation_reason=dedent(
            """\
            Will be removed in a future version of GraphQL.
            Currently no replacement is in place, but specialized fields will probably arive in the future.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    trade_union: LazyClass | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                class_resolver,
                {"uuids": lambda root: uuid2list(root.dynamic_class_uuid)},
            )
        ),
        description=dedent(
            """\
            Marks associations with a trade union
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    primary: LazyClass | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                class_resolver, {"uuids": lambda root: uuid2list(root.primary_uuid)}
            )
        ),
        description=dedent(
            """\
            Marks which association is primary.

            When exporting data from OS2mo to external systems, that only support a single engagement or associations, this field can be used to export the primary one.
            What primarity means is vaguely defined, but usually derived from workload or time-allocation.

            Examples  of user-keys:
            * `"primary"`
            * `"non-primary"`
            * `"explicitly-primary"`

            It is a convention that at most one association for each employee is set as either `primary` or `explicitly-primary`.
            This convention is in place as if more associations are primary, the entire purpose of the field breaks down.
            In the future this convention may become an invariant.

            Note:
            The calculate-primary integration can be used to automatically calculate and update primarity fields.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    employee: list[LazyEmployee] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                employee_resolver, {"uuids": lambda root: uuid2list(root.employee_uuid)}
            )
        ),
        description=dedent(
            """\
            Associated employee.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("employee")],
        deprecation_reason="Use 'person' instead. Will be removed in a future version of OS2mo.",
    )

    person: list[LazyEmployee] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                employee_resolver, {"uuids": lambda root: uuid2list(root.employee_uuid)}
            )
        ),
        description=dedent(
            """\
            Associated person.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("employee")],
    )

    org_unit: list[LazyOrganisationUnit] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                organisation_unit_resolver,
                {"uuids": lambda root: [root.org_unit_uuid]},
            )
        ),
        description=dedent(
            """\
            Associated organisation unit.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
    )

    substitute: list[LazyEmployee] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                employee_resolver,
                {"uuids": lambda root: uuid2list(root.substitute_uuid)},
            )
        ),
        description=dedent(
            """\
            Optional subsitute if `employee` is unavailable.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("employee")],
    )

    job_function: LazyClass | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                class_resolver,
                {"uuids": lambda root: uuid2list(root.job_function_uuid)},
            )
        ),
        description=dedent(
            """\
            The position held by the employee in the organisation unit.

            Examples of user-keys:
            * `"Payroll consultant"`
            * `"Office student"`
            * `"Jurist"`
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    it_user: list[LazyITUser] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                it_user_resolver, {"uuids": lambda root: uuid2list(root.it_user_uuid)}
            )
        ),
        description=dedent(
            """\
            The IT-user utilized by the employee when fulfilling the association responsibilities.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("ituser")],
    )

    @strawberry.field(
        description=dedent(
            """\
            The object type.

            Always contains the string `association`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Unintentionally exposed implementation detail.
            Provides no value whatsoever.
            """
        ),
    )
    async def type(self, root: AssociationRead) -> str:
        """Implemented for backwards compatability."""
        return root.type_

    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: AssociationRead) -> UUID:
        return root.uuid

    @strawberry.field(
        description=dedent(
            """\
            Short unique key.

            Usually set to be set to the key used in external systems.

            Examples:
            * `"1462"`
            * `"XSIMP"`
            """
        )
    )
    async def user_key(self, root: AssociationRead) -> str:
        return root.user_key

    @strawberry.field(
        description="UUID of the dynamically attached class.",
        deprecation_reason=gen_uuid_field_deprecation("dynamic_class"),
    )
    async def dynamic_class_uuid(self, root: AssociationRead) -> UUID | None:
        return root.dynamic_class_uuid

    @strawberry.field(
        description="UUID of the attached trade union.",
        deprecation_reason=gen_uuid_field_deprecation("trade_union"),
    )
    async def trade_union_uuid(self, root: AssociationRead) -> UUID | None:
        return root.dynamic_class_uuid

    @strawberry.field(
        description="UUID of the organisation unit related to the association.",
        deprecation_reason=gen_uuid_field_deprecation("org_unit"),
    )
    async def org_unit_uuid(self, root: AssociationRead) -> UUID:
        return root.org_unit_uuid

    @strawberry.field(
        description="UUID of the employee related to the association.",
        deprecation_reason=gen_uuid_field_deprecation("employee"),
    )
    async def employee_uuid(self, root: AssociationRead) -> UUID | None:
        return root.employee_uuid

    @strawberry.field(
        description="UUID of the association type.",
        deprecation_reason=gen_uuid_field_deprecation("association_type"),
    )
    async def association_type_uuid(self, root: AssociationRead) -> UUID | None:
        return root.association_type_uuid

    @strawberry.field(
        description="UUID of the primary type of the association.",
        deprecation_reason=gen_uuid_field_deprecation("primary"),
    )
    async def primary_uuid(self, root: AssociationRead) -> UUID | None:
        return root.primary_uuid

    @strawberry.field(
        description="UUID of the substitute for the employee in the association.",
        deprecation_reason=gen_uuid_field_deprecation("subsitute"),
    )
    async def substitute_uuid(self, root: AssociationRead) -> UUID | None:
        return root.substitute_uuid

    @strawberry.field(
        description="UUID of a job function class, only defined for 'IT associations.",
        deprecation_reason=gen_uuid_field_deprecation("job_function"),
    )
    async def job_function_uuid(self, root: AssociationRead) -> UUID | None:
        return root.job_function_uuid

    @strawberry.field(
        description="UUID of an 'ITUser' model, only defined for 'IT associations.",
        deprecation_reason=gen_uuid_field_deprecation("it_user"),
    )
    async def it_user_uuid(self, root: AssociationRead) -> UUID | None:
        return root.it_user_uuid

    validity: Validity = strawberry.auto

    # VALIDITY HACKS

    @strawberry.field(
        description=dedent(
            """\
            Same as association_type, but with HACKs to enable validities.
            """
        ),
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("class"),
        ],
        deprecation_reason=dedent(
            """\
            Should only be used to query association_types when validity dates have been specified, "
            "ex from_date & to_date."
            "Will be removed when sub-query date handling is implemented.
            """
        ),
    )
    async def association_type_validity(
        self, root: AssociationRead
    ) -> LazyClass | None:
        association_types = await validity_sub_query_hack(
            root.validity,
            ClassRead,
            get_handler_for_type("class"),
            {"uuid": uuid2list(root.association_type_uuid)},
        )

        return association_types[0] if association_types else None


# Class
# -----


@strawberry.experimental.pydantic.type(
    model=ClassRead,
    description=dedent(
        """\
        A value in the facet sample space.

        Classes can also be thought of as the value component of the facet/class key-value setup.
        """
    ),
)
class Class:
    parent: LazyClass | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                class_resolver, {"uuids": lambda root: uuid2list(root.parent_uuid)}
            )
        ),
        description=dedent(
            """\
            Parent class.

            Almost always `null` as class hierarchies are rare.
            Currently mostly used to describe (trade) union hierachies.

            The inverse operation of `children`.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    children: list[LazyClass] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                class_resolver,
                {"parents": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            Class children.

            Almost always an empty list as class hierarchies are rare.
            Currently mostly used to describe (trade) union hierachies.

            The inverse operation of `parent`.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    facet: LazyFacet = strawberry.field(
        resolver=to_one(
            seed_resolver(facet_resolver, {"uuids": lambda root: [root.facet_uuid]})
        ),
        description=dedent(
            """\
            Facet this class is defined under.

            Examples of user-keys:
            * `"employee_address_type"`
            * `"primary_type"`
            * `"engagement_job_function"`
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("facet")],
    )

    @strawberry.field(
        description=dedent(
            """\
            Facet of this class's upmost parent.

            The result of following `parent` until `parent` becomes `null`, then calling `facet`.

            Almost always the same as `facet` as class hierarchies are rare.
            Currently mostly used to describe (trade) union hierachies.
            """
        ),
        deprecation_reason=dedent(
            """\
            Will be removed in a future version of GraphQL.
            Will either be replaced by client-side recursion, an ancestor field or a recursive schema directive.
            For now client-side recursion is the preferred replacement.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("facet")],
    )
    async def top_level_facet(self, root: ClassRead, info: Info) -> LazyFacet:
        if root.parent_uuid is None:
            return await Class.facet(root=root, info=info)  # type: ignore[operator]
        parent_node = await Class.parent(root=root, info=info)  # type: ignore[operator,misc]
        return await Class.top_level_facet(self=self, root=parent_node, info=info)

    it_system: LazyITSystem | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                it_system_resolver,
                {"uuids": lambda root: uuid2list(root.it_system_uuid)},
            )
        ),
        description=dedent(
            """\
            The IT-System associated with the class.

            This is intended to be used for (IT) roles.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("itsystem")],
    )

    @strawberry.field(
        description=dedent(
            """\
            Full name of the class, exactly the same as `name`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Will be removed in a future version of GraphQL.
            Returns exactly the same as `name`, use that instead.
            """
        ),
    )
    async def full_name(self, root: ClassRead) -> str:
        return root.name

    @strawberry.field(
        description=dedent(
            """\
            The object type.

            Always contains the string `class`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Unintentionally exposed implementation detail.
            Provides no value whatsoever.
            """
        ),
    )
    async def type(self, root: ClassRead) -> str:
        """Implemented for backwards compatability."""
        return root.type_

    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: ClassRead) -> UUID:
        return root.uuid

    @strawberry.field(
        description=dedent(
            """\
            Short unique key.

            Usually set to the `name` provided on object creation.
            May also be set to the key used in external systems or a system-name.

            Usually also used as the machine "value" for the class.

            Examples:
            * `"primary"`
            * `"PhoneEmployee"`
            * `"Jurist"`
            * `"X-418"`
            """
        )
    )
    async def user_key(self, root: ClassRead) -> str:
        return root.user_key

    @strawberry.field(
        description=dedent(
            """\
            Human readable name of the class.

            This is the value that should be shown to users in UIs.

            Examples:
            * `"Primary"`
            * `"Phone number"`
            * `"Jurist"`
            * `"Paragraph 11 Hire"`
            """
        )
    )
    async def name(self, root: ClassRead) -> str:
        return root.name

    @strawberry.field(
        description=dedent(
            """\
            Scope of the class.

            The scope of the class describes the kind of values that can be contained when using the class.
            It has different implications depending on the associated facet.

            Below is a non-exhaustive list of scope values for a non-exhaustive list of facets:

            Facet `visibility`; scope controls visibility classes:
            * `"PUBLIC"`: The entity can be shared publicly.
            * `"SECRET"`: The entity should not be shared publicly.

            Facet `primary_type`; scope controls how primary the class is:
            * `"0"`: Not primary.
            * `"3000"`: Primary.
            * `"5000"`: Explicitly primary / override.

            A lot of facets; scope controls input-validation:
            * `"TEXT"`: The input can be any text string.
            * `"PHONE"`: The input must match OS2mo's phone number regex.
            * `"PNUMBER"`: The input must match OS2mo's p-number regex.
            * `"EMAIL"`: The input must match OS2mo's email regex.
            * `"DAR"`: The input must be a DAR UUID.
            """
        )
    )
    async def scope(self, root: ClassRead) -> str | None:
        return root.scope

    @strawberry.field(
        description=dedent(
            """\
            Published state of the class object.

            Whether the class is published or not, aka. if it should be shown.

            Examples:
            * `"Publiceret"`
            * `"IkkePubliceret"`
            * `"Normal"`

            Note:
            Return change may change to an enum in the future.

            May eventually be superseeded by validities on classes.
            """
        )
    )
    # TODO: Change to returning an enum instead, remove optional
    async def published(self, root: ClassRead) -> str | None:
        return root.published

    @strawberry.field(
        description=dedent(
            """\
            Example usage.

            Almost always `null`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Will be removed in a future version of GraphQL.
            This field is almost never used, and serves no real purpose.
            May be reintroduced in the future if the demand for it increases.
            """
        ),
    )
    async def example(self, root: ClassRead) -> str | None:
        return root.example

    # TODO: Document this better
    owner: UUID | None = strawberry.auto

    @strawberry.field(
        description="UUID of the related facet.",
        deprecation_reason=gen_uuid_field_deprecation("facet"),
    )
    async def facet_uuid(self, root: ClassRead) -> UUID:
        return root.facet_uuid

    @strawberry.field(
        description="UUID of the related organisation.",
        deprecation_reason=dedent(
            """\
            The root organisation concept will be removed in a future version of OS2mo.
            """
        ),
    )
    async def org_uuid(self, root: ClassRead) -> UUID:
        return root.org_uuid

    @strawberry.field(
        description="UUID of the employee related to the address.",
        deprecation_reason=gen_uuid_field_deprecation("parent"),
    )
    async def parent_uuid(self, root: ClassRead) -> UUID | None:
        return root.parent_uuid

    @strawberry.field(
        description="The IT-System associated with the class.",
        deprecation_reason=gen_uuid_field_deprecation("it_system"),
    )
    async def it_system_uuid(self, root: ClassRead) -> UUID | None:
        return root.it_system_uuid

    validity: OpenValidity = strawberry.auto


# Employee
# --------


@strawberry.experimental.pydantic.type(
    model=EmployeeRead,
    description="Employee/identity specific information",
)
class Employee:
    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: EmployeeRead) -> UUID:
        return root.uuid

    @strawberry.field(
        description=dedent(
            """\
            Short unique key.

            Usually set to be set to the key used in external systems.

            Defaults to the `uuid` generated on object creation.

            Examples:
            * `"1462"`
            * `"XSIMP"`
            """
        )
    )
    async def user_key(self, root: EmployeeRead) -> str:
        return root.user_key

    engagements: list[LazyEngagement] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                engagement_resolver,
                {"employees": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            Engagements for the employee.

            May be an empty list if the employee is not employeed.
            """
        ),
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("engagement"),
        ],
    )

    manager_roles: list[LazyManager] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                manager_resolver,
                {"employees": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            Managerial roles for the employee.

            Usually an empty list as most employees are not managers.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("manager")],
    )

    addresses: list[LazyAddress] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                address_resolver,
                {"employees": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            Addresses for the employee.

            Commonly contain addresses such as, their:
            * Work location
            * Office number
            * Work phone number
            * Work email
            * Personal phone number
            * Personal email
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("address")],
    )

    leaves: list[LazyLeave] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                leave_resolver,
                {"employees": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            Leaves of absence for the employee.

            Usually empty as most employees are not on leaves of absence.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("leave")],
    )

    associations: list[LazyAssociation] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                association_resolver,
                {"employees": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            Associations for the employee.

            May be an empty list if the employee is not associated with projects, etc.
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
                {"employees": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            IT accounts for the employee.

            May be an empty list if the employee does not have any IT-access whatsoever.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("ituser")],
    )

    @strawberry.field(
        description=dedent(
            """\
            The object type.

            Always contains the string `employee`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Unintentionally exposed implementation detail.
            Provides no value whatsoever.
            """
        ),
    )
    async def type(self, root: EmployeeRead) -> str:
        """Implemented for backwards compatability."""
        return root.type_

    # TODO: Document this
    cpr_no: CPRType | None = strawberry.field(
        deprecation_reason="Use 'cpr_number' instead. Will be removed in a future version of OS2mo."
    )

    @strawberry.field(description="CPR number of the employee.")
    async def cpr_number(self, root: EmployeeRead) -> CPRType | None:
        return cast(CPRType | None, root.cpr_no)

    # TODO: Document this
    seniority: date | None = strawberry.auto

    # TODO: Deprecate this?
    @strawberry.field(description="Full name of the employee")
    async def name(self, root: EmployeeRead) -> str:
        return f"{root.givenname} {root.surname}".strip()

    givenname: str = strawberry.field(
        deprecation_reason="Use 'given_name' instead. Will be removed in a future version of OS2mo."
    )

    @strawberry.field(description="Given name of the employee.")
    async def given_name(self, root: EmployeeRead) -> str:
        return root.givenname

    surname: str = strawberry.auto

    # TODO: Deprecate this?
    @strawberry.field(description="Full nickname of the employee")
    async def nickname(self, root: EmployeeRead) -> str:
        return f"{root.nickname_givenname} {root.nickname_surname}".strip()

    nickname_givenname: str | None = strawberry.field(
        deprecation_reason="Use 'nickname_given_name' instead. Will be removed in a future version of OS2mo."
    )

    @strawberry.field(description="Given name part of nickname of the employee.")
    async def nickname_given_name(self, root: EmployeeRead) -> str | None:
        return root.nickname_givenname

    nickname_surname: str | None = strawberry.auto

    validity: OpenValidity = strawberry.auto

    # VALIDITY HACKS

    @strawberry.field(
        description=dedent(
            """\
            Same as engagements(), but with HACKs to enable validities.
            """
        ),
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("engagement"),
        ],
        deprecation_reason=dedent(
            """\
            Should only be used to query engagements when validity dates have been specified, "
            "ex from_date & to_date."
            "Will be removed when sub-query date handling is implemented.
            """
        ),
    )
    async def engagements_validity(
        self, root: EmployeeRead, info: Info
    ) -> list[LazyEngagement]:
        return await validity_sub_query_hack(
            root.validity,
            EngagementRead,
            get_handler_for_type("engagement"),
            {"tilknyttedebrugere": uuid2list(root.uuid)},
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
        self, root: EmployeeRead, info: Info
    ) -> list[LazyAddress]:
        return await validity_sub_query_hack(
            root.validity,
            AddressRead,
            get_handler_for_type("address"),
            {"tilknyttedebrugere": uuid2list(root.uuid)},
        )

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
        self, root: EmployeeRead, info: Info
    ) -> list[LazyAssociation]:
        return await validity_sub_query_hack(
            root.validity,
            AssociationRead,
            get_handler_for_type("association"),
            {"tilknyttedebrugere": uuid2list(root.uuid)},
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
        self, root: EmployeeRead, info: Info
    ) -> list[LazyITUser]:
        return await validity_sub_query_hack(
            root.validity,
            ITUserRead,
            get_handler_for_type("it"),
            {"tilknyttedebrugere": uuid2list(root.uuid)},
        )


# Engagement
# ----------


@strawberry.experimental.pydantic.type(
    model=EngagementRead,
    description="Employee engagement in an organisation unit",
)
class Engagement:
    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: EngagementRead) -> UUID:
        return root.uuid

    @strawberry.field(
        description=dedent(
            """\
            Short unique key.

            Usually set to the `id` used in external systems.

            Examples:
            * `"11009"`
            * `"02782"`
            """
        )
    )
    async def user_key(self, root: EngagementRead) -> str:
        return root.user_key

    engagement_type: LazyClass = strawberry.field(
        resolver=to_one(
            seed_resolver(
                class_resolver,
                {"uuids": lambda root: [root.engagement_type_uuid]},
            )
        ),
        description=dedent(
            """\
            Describes the employee's affiliation to an organisation unit

            Examples:
            * `"Employed"`
            * `"Social worker"`
            * `"Employee (hourly wage)"`
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    job_function: LazyClass = strawberry.field(
        resolver=to_one(
            seed_resolver(
                class_resolver,
                {"uuids": lambda root: [root.job_function_uuid]},
            )
        ),
        description=dedent(
            """\
            Describes the position of the employee in the organisation unit

            Examples:
            * `"Payroll consultant"`
            * `"Office student"`
            * `"Jurist"`
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    primary: LazyClass | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                class_resolver, {"uuids": lambda root: uuid2list(root.primary_uuid)}
            )
        ),
        description=dedent(
            """\
            Marks which engagement is primary.

            When exporting data from OS2mo to external systems, that only support a single engagement or associations, this field can be used to export the primary one.
            What primarity means is vaguely defined, but usually derived from workload or time-allocation.

            Examples  of user-keys:
            * `"primary"`
            * `"non-primary"`
            * `"explicitly-primary"`

            It is a convention that at most one engagement for each employee is set as either `primary` or `explicitly-primary`.
            This convention is in place as if more engagements are primary, the entire purpose of the field breaks down.
            In the future this convention may become an invariant.

            Note:
            The calculate-primary integration can be used to automatically calculate and update primarity fields.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    @strawberry.field(
        description=dedent(
            """\
        Whether this engagement is the primary engagement.

        Checks if the `primary` field contains either a class with user-key: `"primary"` or `"explicitly-primary"`.
        """
        )
    )
    async def is_primary(self, root: EngagementRead, info: Info) -> bool:
        if not root.primary_uuid:
            return False
        # TODO: Eliminate is_class_uuid_primary lookup by using the above resolver
        #       Then utilize is_class_primary as result_translation
        return await is_class_uuid_primary(str(root.primary_uuid))

    leave: LazyLeave | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                leave_resolver, {"uuids": lambda root: uuid2list(root.leave_uuid)}
            )
        ),
        description="Related leave",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("leave")],
    )

    employee: list[LazyEmployee] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                employee_resolver, {"uuids": lambda root: uuid2list(root.employee_uuid)}
            )
        ),
        description=dedent(
            """\
            The employee fulfilling the engagement.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("employee")],
        deprecation_reason="Use 'person' instead. Will be removed in a future version of OS2mo.",
    )

    person: list[LazyEmployee] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                employee_resolver, {"uuids": lambda root: uuid2list(root.employee_uuid)}
            )
        ),
        description=dedent(
            """\
            The person fulfilling the engagement.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("employee")],
    )

    org_unit: list[LazyOrganisationUnit] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                organisation_unit_resolver,
                {"uuids": lambda root: uuid2list(root.org_unit_uuid)},
            )
        ),
        description=dedent(
            """\
            The organisation unit where the engagement is being fulfilled.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
    )

    @strawberry.field(
        description=dedent(
            """\
            The object type.

            Always contains the string `engagement`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Unintentionally exposed implementation detail.
            Provides no value whatsoever.
            """
        ),
    )
    async def type(self, root: EngagementRead) -> str:
        """Implemented for backwards compatability."""
        return root.type_

    @strawberry.field(
        description="UUID of the engagement type class.",
        deprecation_reason=gen_uuid_field_deprecation("engagement_type"),
    )
    async def engagement_type_uuid(self, root: EngagementRead) -> UUID:
        return root.engagement_type_uuid

    @strawberry.field(
        description="UUID of the employee related to the engagement.",
        deprecation_reason=gen_uuid_field_deprecation("employee"),
    )
    async def employee_uuid(self, root: EngagementRead) -> UUID:
        return root.employee_uuid

    @strawberry.field(
        description="UUID of the organisation unit related to the engagement.",
        deprecation_reason=gen_uuid_field_deprecation("org_unit"),
    )
    async def org_unit_uuid(self, root: EngagementRead) -> UUID:
        return root.org_unit_uuid

    @strawberry.field(
        description="UUID of the job function class.",
        deprecation_reason=gen_uuid_field_deprecation("job_function"),
    )
    async def job_function_uuid(self, root: EngagementRead) -> UUID:
        return root.job_function_uuid

    @strawberry.field(
        description="UUID of the leave related to the engagement.",
        deprecation_reason=gen_uuid_field_deprecation("leave"),
    )
    async def leave_uuid(self, root: EngagementRead) -> UUID | None:
        return root.leave_uuid

    @strawberry.field(
        description="UUID of the primary klasse of the engagement.",
        deprecation_reason=gen_uuid_field_deprecation("primary"),
    )
    async def primary_uuid(self, root: EngagementRead) -> UUID | None:
        return root.primary_uuid

    # TODO: Document this
    fraction: int | None = strawberry.auto

    # TODO: Make structured model for these?
    extension_1: str | None = strawberry.auto
    extension_2: str | None = strawberry.auto
    extension_3: str | None = strawberry.auto
    extension_4: str | None = strawberry.auto
    extension_5: str | None = strawberry.auto
    extension_6: str | None = strawberry.auto
    extension_7: str | None = strawberry.auto
    extension_8: str | None = strawberry.auto
    extension_9: str | None = strawberry.auto
    extension_10: str | None = strawberry.auto

    validity: Validity = strawberry.auto

    # VALIDITY HACKS

    @strawberry.field(
        description=dedent(
            """\
            Same as engagement_type, but with HACKs to enable validities.
            """
        ),
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("class"),
        ],
        deprecation_reason=dedent(
            """\
            Should only be used to query engagement_type when validity dates have been specified, "
            "ex from_date & to_date."
            "Will be removed when sub-query date handling is implemented.
            """
        ),
    )
    async def engagement_type_validity(self, root: EngagementRead) -> LazyClass | None:
        engagement_types = await validity_sub_query_hack(
            root.validity,
            ClassRead,
            get_handler_for_type("class"),
            {"uuid": uuid2list(root.engagement_type_uuid)},
        )

        return engagement_types[0] if engagement_types else None


# Facet
# -----


@strawberry.experimental.pydantic.type(
    model=FacetRead,
    description="The key component of the class/facet choice setup",
)
class Facet:
    classes: list[LazyClass] = strawberry.field(
        resolver=to_list(
            seed_resolver(class_resolver, {"facets": lambda root: [root.uuid]})
        ),
        description="Associated classes",
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    parent: LazyFacet | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                facet_resolver, {"uuids": lambda root: uuid2list(root.parent_uuid)}
            )
        ),
        description=dedent(
            """\
            Parent facet.

            Almost always `null` as facet hierarchies are rare.
            Currently mostly used to describe (trade) union hierachies.

            The inverse operation of `children`.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("facet")],
    )

    children: list[LazyFacet] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                facet_resolver,
                {"parents": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            Facet children.

            Almost always an empty list as facet hierarchies are rare.
            Currently mostly used to describe (trade) union hierachies.

            The inverse operation of `parent`.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("facet")],
    )

    @strawberry.field(
        description=dedent(
            """\
            The object type.

            Always contains the string `facet`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Unintentionally exposed implementation detail.
            Provides no value whatsoever.
            """
        ),
    )
    async def type(self, root: FacetRead) -> str:
        """Implemented for backwards compatability."""
        return root.type_

    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: FacetRead) -> UUID:
        return root.uuid

    # TODO: Document this
    user_key: str = strawberry.auto

    @strawberry.field(
        description=dedent(
            """\
            Published state of the facet object.

            Whether the facet is published or not, aka. if it should be shown.

            Examples:
            * `"Publiceret"`
            * `"IkkePubliceret"`
            * `"Normal"`

            Note:
            Return change may change to an enum in the future.

            May eventually be superseeded by validities on facets.
            """
        )
    )
    # TODO: Change to returning an enum instead, remove optional
    async def published(self, root: FacetRead) -> str | None:
        return root.published

    @strawberry.field(
        description="UUID of the related organisation.",
        deprecation_reason=dedent(
            """\
            The root organisation concept will be removed in a future version of OS2mo.
            """
        ),
    )
    async def org_uuid(self, root: ClassRead) -> UUID:
        return root.org_uuid

    @strawberry.field(
        description="UUID of the parent facet.",
        deprecation_reason=gen_uuid_field_deprecation("parent"),
    )
    async def parent_uuid(self, root: FacetRead) -> UUID | None:
        return root.parent_uuid

    @strawberry.field(
        description=dedent(
            """\
            Description of the facet object.

            Almost always `""`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Will be removed in a future version of GraphQL.
            This field is almost never used, and serves no real purpose.
            May be reintroduced in the future if the demand for it increases.
            """
        ),
    )
    async def description(self, root: FacetRead) -> str | None:
        return root.description

    validity: OpenValidity = strawberry.auto


# IT
# --


@strawberry.experimental.pydantic.type(
    model=ITSystemRead,
    description="Systems that IT users are connected to",
)
class ITSystem:
    # TODO: Allow querying all accounts

    @strawberry.field(
        description=dedent(
            """\
            The object type.

            Always contains the string `itsystem`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Unintentionally exposed implementation detail.
            Provides no value whatsoever.
            """
        ),
    )
    async def type(self, root: ITSystemRead) -> str:
        """Implemented for backwards compatability."""
        return root.type_

    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: ITSystemRead) -> UUID:
        return root.uuid

    @strawberry.field(
        description=dedent(
            """\
        Human readable name of the itsystem.

        This is the value that should be shown to users in UIs.

        Examples:
        * `"SAP"`
        * `"Active Directory"`
        * `"SD UUID"`
        """
        )
    )
    async def name(self, root: ITSystemRead) -> str:
        return root.name

    @strawberry.field(
        description=dedent(
            """\
            Short unique key.

            Usually set to be set to the key used in external systems.

            Examples:
            * `"sap_user_uuid"`
            * `"ad_guid"`
            * `"sd_employee_uuid"`
            """
        )
    )
    async def user_key(self, root: ITSystemRead) -> str:
        return root.user_key

    # TODO: Document this
    system_type: str | None = strawberry.auto

    validity: OpenValidity = strawberry.auto


@strawberry.experimental.pydantic.type(
    model=ITUserRead,
    description=dedent(
        """\
        User information related to IT systems.

        This is commonly used to map out IT accounts or IT service accounts.
        It is however also used to hold IT system specific identifiers for correlation purposes.
        """
    ),
)
class ITUser:
    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: ITUserRead) -> UUID:
        return root.uuid

    @strawberry.field(
        description=dedent(
            """\
            Short unique key.

            Usually set to the key used in external systems.

            Examples:
            * `"KarK"`
            * `"AnkS"`
            * `"XSIMP"`
            * `"04184cb6-a5de-47e6-8a08-03cae9ee4c54"`
            """
        )
    )
    async def user_key(self, root: ITUserRead) -> str:
        return root.user_key

    @strawberry.field(description="ID of the user account in the external system.")
    async def external_id(self, root: ITUserRead) -> str | None:
        return root.external_id

    employee: list[LazyEmployee] | None = strawberry.field(
        resolver=force_none_return_wrapper(
            to_list(
                seed_resolver(
                    employee_resolver,
                    {
                        "uuids": partial(
                            raise_force_none_return_if_uuid_none,
                            get_uuid=lambda root: root.employee_uuid,
                        )
                    },
                )
            ),
        ),
        description=dedent(
            """\
            Employee using the IT account.

            Note:
            This field is mutually exclusive with the `org_unit` field.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("employee")],
        deprecation_reason="Use 'person' instead. Will be removed in a future version of OS2mo.",
    )

    person: list[LazyEmployee] | None = strawberry.field(
        resolver=force_none_return_wrapper(
            to_list(
                seed_resolver(
                    employee_resolver,
                    {
                        "uuids": partial(
                            raise_force_none_return_if_uuid_none,
                            get_uuid=lambda root: root.employee_uuid,
                        )
                    },
                )
            ),
        ),
        description=dedent(
            """\
            Person using the IT account.

            Note:
            This field is mutually exclusive with the `org_unit` field.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("employee")],
    )

    org_unit: list[LazyOrganisationUnit] | None = strawberry.field(
        resolver=force_none_return_wrapper(
            to_list(
                seed_resolver(
                    organisation_unit_resolver,
                    {
                        "uuids": partial(
                            raise_force_none_return_if_uuid_none,
                            get_uuid=lambda root: root.org_unit_uuid,
                        )
                    },
                )
            ),
        ),
        description=dedent(
            """\
            Organisation unit using the IT account.

            This is mostly set for service accounts.

            Note:
            This field is mutually exclusive with the `org_unit` field.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
    )

    engagement: list[LazyEngagement] | None = strawberry.field(
        resolver=force_none_return_wrapper(
            to_list(
                seed_resolver(
                    engagement_resolver,
                    {
                        "uuids": partial(
                            raise_force_none_return_if_uuid_none,
                            get_uuid=lambda root: root.engagement_uuid,
                        )
                    },
                )
            ),
        ),
        description=dedent(
            """\
            Engagement scoping of the account.

            A person may have multiple IT accounts with each account being relevant for only a single engagement.
            This field allows scoping IT accounts such that it is obvious which engagement has given which it-access.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("engagement"),
        ],
    )

    addresses: list[LazyAddress] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                address_resolver,
                {"ituser": lambda root: ITUserFilter(uuids=[root.uuid])},
            )
        ),
        description=dedent(
            """\
            Addresses connected with the IT-user.

            Commonly contain addresses such as:
            * Email
            * AD GUID
            * FK-org UUID
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("address")],
    )

    itsystem: LazyITSystem = strawberry.field(
        resolver=to_one(
            seed_resolver(
                it_system_resolver, {"uuids": lambda root: [root.itsystem_uuid]}
            )
        ),
        description=dedent(
            """\
            ITSystem this account is for.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("itsystem")],
    )

    rolebindings: list[LazyRoleBinding] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                rolebinding_resolver,
                {"ituser": lambda root: ITUserFilter(uuids=[root.uuid])},
            )
        ),
        description="Rolebindings this IT User has in the connected IT system.",
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("rolebinding"),
        ],
    )

    primary: LazyClass | None = strawberry.field(
        resolver=to_only(
            seed_resolver(
                class_resolver, {"uuids": lambda root: uuid2list(root.primary_uuid)}
            )
        ),
        description=dedent(
            """\
            Marks which IT account is primary.

            When exporting data from OS2mo to external systems, that only support a single IT account, this field can be used to export the primary one.
            What primarity means is vaguely defined, but usually derived from workload or time-allocation.

            Examples  of user-keys:
            * `"primary"`
            * `"non-primary"`
            * `"explicitly-primary"`

            It is a convention that at most one IT account for each employee / employee+engagement is set as either `primary` or `explicitly-primary`.
            This convention is in place as if more IT accounts are primary, the entire purpose of the field breaks down.
            In the future this convention may become an invariant.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    @strawberry.field(
        description=dedent(
            """\
            The object type.

            Always contains the string `it`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Unintentionally exposed implementation detail.
            Provides no value whatsoever.
            """
        ),
    )
    async def type(self, root: ITUserRead) -> str:
        """Implemented for backwards compatability."""
        return root.type_

    @strawberry.field(
        description="UUID of the ITSystem related to the user.",
        deprecation_reason=gen_uuid_field_deprecation("itsystem"),
    )
    async def itsystem_uuid(self, root: ITUserRead) -> UUID:
        return root.itsystem_uuid

    @strawberry.field(
        description="UUID of the employee related to the user.",
        deprecation_reason=gen_uuid_field_deprecation("employee"),
    )
    async def employee_uuid(self, root: ITUserRead) -> UUID | None:
        return root.employee_uuid

    @strawberry.field(
        description="UUID of the organisation unit related to the user.",
        deprecation_reason=gen_uuid_field_deprecation("org_unit"),
    )
    async def org_unit_uuid(self, root: ITUserRead) -> UUID | None:
        return root.org_unit_uuid

    @strawberry.field(
        description="UUID of the engagement related to the user.",
        deprecation_reason=gen_uuid_field_deprecation("engagement"),
    )
    async def engagement_uuid(self, root: ITUserRead) -> UUID | None:
        return root.engagement_uuid

    @strawberry.field(
        description="UUID of the primary klasse of the user.",
        deprecation_reason=gen_uuid_field_deprecation("primary"),
    )
    async def primary_uuid(self, root: ITUserRead) -> UUID | None:
        return root.primary_uuid

    validity: Validity = strawberry.auto

    # VALIDITY HACKS

    @strawberry.field(
        description=dedent(
            """\
            Same as itsystem, but with HACKs to enable validities.
            """
        ),
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("class"),
        ],
        deprecation_reason=dedent(
            """\
            Should only be used to query itsystem when validity dates have been specified, "
            "ex from_date & to_date."
            "Will be removed when sub-query date handling is implemented.
            """
        ),
    )
    async def itsystem_validity(self, root: ITUserRead) -> LazyITSystem:
        itsystems = await validity_sub_query_hack(
            root.validity,
            ITSystemRead,
            get_handler_for_type("itsystem"),
            {"uuid": uuid2list(root.itsystem_uuid)},
        )

        return itsystems[0]


# KLE
# ---


@strawberry.experimental.pydantic.type(
    model=KLERead,
    description=dedent(
        """\
        KLE responsibility mapping.

        KLE stands for "Kommunernes Landsforenings Emnesystematik" which is a municipality taxonomy for mapping out municipality tasks.

        In OS2mo KLE responsibilities can be mapped to organisation units to signify that a given organisational unit operates within certain municipality tasks.
        Adding KLE responsibilities to organisational units can help out with regards to GDPR by identifying which organisational units operate with sensitive tasks.

        The KLE numbers themselves are dot seperated structured numbers alike this:
        * `"00.75.00"`: General data exchanges
        * `"21.02.05"`: Library study cafes
        * `"32.15.08"`: Alimony

        The first number specifies the main-group, such as:
        * `"00"`: Municipality operations (Kommunens styrelse)
        * `"21"`: Libraries
        * `"31"`: Monetary benefits

        The second number specifies the group, such as (for libraries):
        * `"02"`: On-site usage
        * `"05"`: AV Materials
        * `"20"`: Online services

        The third and final number specifies the topic, such as (for library on-site usage):
        * `"00"`: General usage
        * `"05"`: Study cafes
        * `"10"`: Study centers

        Some KLE ranges are pre-reserved by The National Association of Municipalities (Kommunernes Landsforenings), however outside of these pre-reserved ranges municipalies are allowed to add their own local numbers.
        Specifically no main-groups can be added, only groups and topics, both above 79.

        For more details see: https://www.kle-online.dk
        """
    ),
)
class KLE:
    kle_number: LazyClass = strawberry.field(
        resolver=to_one(
            seed_resolver(
                class_resolver, {"uuids": lambda root: [root.kle_number_uuid]}
            )
        ),
        description=dedent(
            """\
            The KLE number specifies the responsibility.

            For more details read the `KLE` description.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    kle_aspects: list[LazyClass] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                class_resolver,
                {"uuids": lambda root: root.kle_aspect_uuids or []},
            )
        ),
        description=dedent(
            """\
            KLE Aspects.

            The KLE aspect describes the kind of relationship the organisation unit has with the responsibility given by the KLE number.

            Examples of user-keys:
            * `"Insight"`
            * `"Executive"`
            * `"Responsible"`
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    org_unit: list[LazyOrganisationUnit] = strawberry.field(
        resolver=force_none_return_wrapper(
            to_list(
                seed_resolver(
                    organisation_unit_resolver,
                    {
                        "uuids": partial(
                            raise_force_none_return_if_uuid_none,
                            get_uuid=lambda root: root.org_unit_uuid,
                        )
                    },
                )
            ),
        ),
        description=dedent(
            """\
            The organisation unit the responsibility is mapped to.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
    )

    @strawberry.field(
        description=dedent(
            """\
            The object type.

            Always contains the string `kle`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Unintentionally exposed implementation detail.
            Provides no value whatsoever.
            """
        ),
    )
    async def type(self, root: KLERead) -> str:
        """Implemented for backwards compatability."""
        return root.type_

    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: KLERead) -> UUID:
        return root.uuid

    @strawberry.field(
        description=dedent(
            """\
            Short unique key.

            Usually set to be set to the kle number itself.

            Examples:
            * `"00.75.00"`
            * `"21.02.05"`
            * `"32.15.08"`
            """
        )
    )
    async def user_key(self, root: KLERead) -> str:
        return root.user_key

    @strawberry.field(
        description="UUID of the KLE number.",
        deprecation_reason=gen_uuid_field_deprecation("kle_number"),
    )
    async def kle_number_uuid(self, root: KLERead) -> UUID:
        return root.kle_number_uuid

    @strawberry.field(
        description="List of UUIDs of the KLE aspect.",
        deprecation_reason=gen_uuid_field_deprecation("kle_aspects"),
    )
    async def kle_aspect_uuids(self, root: KLERead) -> list[UUID]:
        return root.kle_aspect_uuids

    @strawberry.field(
        description="UUID of the organisation unit related to the KLE.",
        deprecation_reason=gen_uuid_field_deprecation("org_unit"),
    )
    async def org_unit_uuid(self, root: KLERead) -> UUID:
        return root.org_unit_uuid

    validity: Validity = strawberry.auto


# Leave
# -----


@strawberry.experimental.pydantic.type(
    model=LeaveRead,
    description=dedent(
        """\
        A leave of absence for an employee.

        Can be everything from a pregnancy or maternity leave to a furlough or a garden leave.
        The `leave_type` can be used to determine the type of leave in question.
        """
    ),
)
class Leave:
    leave_type: LazyClass = strawberry.field(
        resolver=to_one(
            seed_resolver(
                class_resolver, {"uuids": lambda root: [root.leave_type_uuid]}
            )
        ),
        description=dedent(
            """\
            The kind of leave of absence.

            Examples:
            * `"Maternity leave"`
            * `"Parental leave"`
            * `"Furlough"`
            * `"Garden Leave"`
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    employee: list[LazyEmployee] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                employee_resolver, {"uuids": lambda root: uuid2list(root.employee_uuid)}
            )
        ),
        description=dedent(
            """\
            The absent employee.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("employee")],
        deprecation_reason="Use 'person' instead. Will be removed in a future version of OS2mo.",
    )

    person: list[LazyEmployee] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                employee_resolver, {"uuids": lambda root: uuid2list(root.employee_uuid)}
            )
        ),
        description=dedent(
            """\
            The absent person.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("employee")],
    )

    engagement: LazyEngagement = strawberry.field(
        resolver=to_only(
            seed_resolver(
                engagement_resolver,
                {"uuids": lambda root: [root.engagement_uuid]},
            )
        ),
        description=dedent(
            """\
            The engagement the employee is absent from.
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

            Always contains the string `leave`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Unintentionally exposed implementation detail.
            Provides no value whatsoever.
            """
        ),
    )
    async def type(self, root: LeaveRead) -> str:
        """Implemented for backwards compatability."""
        return root.type_

    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: LeaveRead) -> UUID:
        return root.uuid

    # TODO: Document this
    user_key: str = strawberry.auto

    @strawberry.field(
        description="UUID of the KLE number.",
        deprecation_reason=gen_uuid_field_deprecation("leave_type"),
    )
    async def leave_type_uuid(self, root: LeaveRead) -> UUID:
        return root.leave_type_uuid

    @strawberry.field(
        description="UUID of the KLE number.",
        deprecation_reason=gen_uuid_field_deprecation("employee"),
    )
    async def employee_uuid(self, root: LeaveRead) -> UUID:
        return root.employee_uuid

    @strawberry.field(
        description="UUID of the KLE number.",
        deprecation_reason=gen_uuid_field_deprecation("engagement"),
    )
    async def engagement_uuid(self, root: LeaveRead) -> UUID:
        return root.engagement_uuid

    validity: Validity = strawberry.auto


# Manager
# -------


@strawberry.experimental.pydantic.type(
    model=ManagerRead,
    description=dedent(
        """\
        Managers of organisation units and their connected identities.
        """
    ),
)
class Manager:
    manager_type: LazyClass = strawberry.field(
        resolver=to_one(
            seed_resolver(
                class_resolver,
                {"uuids": lambda root: uuid2list(root.manager_type_uuid)},
            )
        ),
        description=dedent(
            """\
            Title of the manager.

            Examples:
            * `"Director"`
            * `"Area manager"`
            * `"Center manager"`
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    manager_level: LazyClass = strawberry.field(
        resolver=to_one(
            seed_resolver(
                class_resolver,
                {"uuids": lambda root: uuid2list(root.manager_level_uuid)},
            )
        ),
        # TODO: Check production system values
        description=dedent(
            """\
            Hierarchical level of the manager.

            Examples:
            * `"Level 1"`
            * `"Level 2"`
            * `"Level 3"`
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    responsibilities: list[LazyClass] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                class_resolver,
                {"uuids": lambda root: root.responsibility_uuids or []},
            )
        ),
        description=dedent(
            """\
            Responsibilities that the manager takes care of.

            Examples:
            * `["Responsible for buildings and areas"]`
            * `["Responsible for buildings and areas", "Staff: Sick leave"]`
            * `[]`
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    employee: list[LazyEmployee] | None = strawberry.field(
        resolver=force_none_return_wrapper(
            to_list(
                seed_resolver(
                    employee_resolver,
                    {
                        "uuids": partial(
                            raise_force_none_return_if_uuid_none,
                            get_uuid=lambda root: root.employee_uuid,
                        )
                    },
                )
            ),
        ),
        description=dedent(
            """\
            Employee fulfilling the managerial position.

            May be empty in which case the managerial position is unfilfilled (vacant).
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("employee")],
        deprecation_reason="Use 'person' instead. Will be removed in a future version of OS2mo.",
    )

    person: list[LazyEmployee] | None = strawberry.field(
        resolver=force_none_return_wrapper(
            to_list(
                seed_resolver(
                    employee_resolver,
                    {
                        "uuids": partial(
                            raise_force_none_return_if_uuid_none,
                            get_uuid=lambda root: root.employee_uuid,
                        )
                    },
                )
            ),
        ),
        description=dedent(
            """\
            Person fulfilling the managerial position.

            May be empty in which case the managerial position is unfilfilled (vacant).
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("employee")],
    )

    org_unit: list[LazyOrganisationUnit] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                organisation_unit_resolver,
                {"uuids": lambda root: [root.org_unit_uuid]},
            )
        ),
        description=dedent(
            """\
            Organisation unit being managed.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
    )

    @strawberry.field(
        description=dedent(
            """\
            The object type.

            Always contains the string `manager`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Unintentionally exposed implementation detail.
            Provides no value whatsoever.
            """
        ),
    )
    async def type(self, root: ManagerRead) -> str:
        """Implemented for backwards compatability."""
        return root.type_

    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: ManagerRead) -> UUID:
        return root.uuid

    # TODO: Document this
    user_key: str = strawberry.auto

    @strawberry.field(
        description="UUID of the organisation unit related to the manager.",
        deprecation_reason=gen_uuid_field_deprecation("org_unit"),
    )
    async def org_unit_uuid(self, root: ManagerRead) -> UUID:
        return root.org_unit_uuid

    @strawberry.field(
        description="UUID of the employee related to the manager.",
        deprecation_reason=gen_uuid_field_deprecation("employee"),
    )
    async def employee_uuid(self, root: ManagerRead) -> UUID | None:
        return root.employee_uuid

    @strawberry.field(
        description="UUID of the manager type.",
        deprecation_reason=gen_uuid_field_deprecation("manager_type"),
    )
    async def manager_type_uuid(self, root: ManagerRead) -> UUID | None:
        return root.manager_type_uuid

    @strawberry.field(
        description="UUID of the manager level.",
        deprecation_reason=gen_uuid_field_deprecation("manager_level"),
    )
    async def manager_level_uuid(self, root: ManagerRead) -> UUID | None:
        return root.manager_level_uuid

    @strawberry.field(
        description="List of UUID's of the responsibilities.",
        deprecation_reason=gen_uuid_field_deprecation("responsibilities"),
    )
    async def responsibility_uuids(self, root: ManagerRead) -> list[UUID] | None:
        return root.responsibility_uuids

    validity: Validity = strawberry.auto


@strawberry.experimental.pydantic.type(
    model=OwnerRead,
    description=dedent(
        """
        Owner of organisation units/employees and their connected identities.
        """
    ),
)
class Owner:
    @strawberry.field(
        description=dedent(
            """
            The object type.

            Always contains the string `owner`.
            """
        ),
        deprecation_reason=dedent(
            """
            Unintentionally exposed implementation detail.
            Provides no value whatsoever.
            """
        ),
    )
    async def type(self, root: OwnerRead) -> str:
        """Implemented for backwards compatability."""
        return root.type_

    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: OwnerRead) -> UUID:
        return root.uuid

    # TODO: Document this
    user_key: str = strawberry.auto

    org_unit: list[LazyOrganisationUnit] | None = strawberry.field(
        resolver=force_none_return_wrapper(
            to_list(
                seed_resolver(
                    organisation_unit_resolver,
                    {
                        "uuids": partial(
                            raise_force_none_return_if_uuid_none,
                            get_uuid=lambda root: root.org_unit_uuid,
                        )
                    },
                )
            ),
        ),
        description=dedent(
            """\
            The owned organisation unit.

            Note:
            This field is mutually exclusive with the `employee` field.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
    )

    @strawberry.field(
        description="UUID of the organisation unit related to the owner.",
        deprecation_reason=gen_uuid_field_deprecation("org_unit"),
    )
    async def org_unit_uuid(self, root: OwnerRead) -> UUID | None:
        return root.org_unit_uuid

    person: list[LazyEmployee] | None = strawberry.field(
        resolver=force_none_return_wrapper(
            to_list(
                seed_resolver(
                    employee_resolver,
                    {
                        "uuids": partial(
                            raise_force_none_return_if_uuid_none,
                            get_uuid=lambda root: root.employee_uuid,
                        )
                    },
                )
            ),
        ),
        description=dedent(
            """\
            The owned person.

            Note:
            This field is mutually exclusive with the `org_unit` field.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("employee")],
    )

    @strawberry.field(
        description="UUID of the employee related to the owner.",
        deprecation_reason=gen_uuid_field_deprecation("employee"),
    )
    async def employee_uuid(self, root: OwnerRead) -> UUID | None:
        return root.employee_uuid

    owner: list[LazyEmployee] | None = strawberry.field(
        resolver=force_none_return_wrapper(
            to_list(
                seed_resolver(
                    employee_resolver,
                    {
                        "uuids": partial(
                            raise_force_none_return_if_uuid_none,
                            get_uuid=lambda root: root.owner_uuid,
                        )
                    },
                )
            ),
        ),
        description=dedent(
            """\
        Owner of the connected person or organisation unit.
        """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("owner")],
    )

    @strawberry.field(
        description="UUID of the owner.",
        deprecation_reason=gen_uuid_field_deprecation("owner"),
    )
    async def owner_uuid(self, root: OwnerRead) -> UUID | None:
        return root.owner_uuid

    owner_inference_priority: OwnerInferencePriority | None = strawberry.field(
        description=dedent(
            """\
        Inference priority, if set: `engagement_priority` or `association_priority`
        """
        )
    )

    validity: Validity = strawberry.auto


# Organisation
# ------------


MUNICIPALITY_CODE_PATTERN = re.compile(r"urn:dk:kommune:(\d+)")


@strawberry.type(description="Root organisation - one and only one of these can exist")
class Organisation:
    # TODO: Eliminate the OrganisationRead model from here. Use self instead.

    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: OrganisationRead) -> UUID:
        return root.uuid

    @strawberry.field(
        description=dedent(
            """\
            Short unique key.

            Examples:
            * `root`
            * `0751` (municipality code)
            * `3b866d97-0b1f-48e0-8078-686d96f430b3` (copied entity UUID)
            * `Kolding Kommune` (municipality name)
            * `Magenta ApS` (company name)
            """
        )
    )
    async def user_key(self, root: OrganisationRead) -> str:
        return root.user_key

    @strawberry.field(
        description=dedent(
            """\
            Name of the organisation.

            Examples:
            * `root`
            * `Kolding Kommune` (or similar municipality name)
            * `Magenta ApS` (or similar company name)
            """
        )
    )
    async def name(self, root: OrganisationRead) -> str:
        return root.name

    @strawberry.field(
        description=dedent(
            """\
            The object type.

            Always contains the string `organisation`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Unintentionally exposed implementation detail.
            Provides no value whatsoever.
            """
        ),
    )
    async def type(self, root: OrganisationRead) -> str:
        """Implemented for backwards compatability."""
        return root.type_

    @strawberry.field(
        description=dedent(
            """\
            The municipality code.

            In Denmark; a 3 digit number uniquely identifying a municipality.
            Generally used to map the Local administrative units (LAU) of the
            Nomenclature of Territorial Units for Statistics (NUTS) standard.

            A list of all danish municipality codes can be found here:
            * https://danmarksadresser.dk/adressedata/kodelister/kommunekodeliste

            Examples:
            * `null` (unset)
            * `101` (Copenhagen)
            * `461` (Odense)
            * `751` (Aarhus)
            """
        )
    )
    async def municipality_code(self, root: OrganisationRead) -> int | None:
        """Get the municipality code for the organisation unit (if any).

        Returns:
            The municipality code, if any is found.
        """
        org = await common.get_connector().organisation.get(root.uuid)
        if org is None:
            return None
        authorities = org.get("relationer", {}).get("myndighed", [])
        for authority in authorities:
            m = MUNICIPALITY_CODE_PATTERN.fullmatch(authority.get("urn"))
            if m:
                return int(m.group(1))
        return None


# Organisation Unit
# -----------------


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

    managers: list[LazyManager] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                manager_resolver,
                {"org_units": lambda root: [root.uuid]},
            )
        ),
        description=dedent(
            """\
            Managerial roles for the organisation unit.

            May be empty in which case managers are usually inherited from parents.
            See the `inherit`-flag for details.
            """
        ),
        permission_classes=[
            IsAuthenticatedPermission,
            gen_read_permission("manager"),
        ],
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


# Related Unit
# ------------


@strawberry.experimental.pydantic.type(
    model=RelatedUnitRead,
    description="An organisation unit relation mapping",
)
class RelatedUnit:
    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: RelatedUnitRead) -> UUID:
        return root.uuid

    @strawberry.field(
        description=dedent(
            """\
        User-key of the entity.

        Usually constructed from the user-keys of our organisation units at creation time.

        Examples:
        * `"Administrative <-> Payroll"`
        * `"IT-Support <-> IT-Support`
        * `"Majora School <-> Alias School"`
        """
        )
    )
    async def user_key(self, root: RelatedUnitRead) -> str:
        return root.user_key

    @strawberry.field(
        description=dedent(
            """\
            The object type.

            Always contains the string `related_units`.
            """
        ),
        deprecation_reason=dedent(
            """\
            Unintentionally exposed implementation detail.
            Provides no value whatsoever.
            """
        ),
    )
    async def type(self, root: RelatedUnitRead) -> str:
        """Implemented for backwards compatability."""
        return root.type_

    org_units: list[LazyOrganisationUnit] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                organisation_unit_resolver,
                {"uuids": lambda root: root.org_unit_uuids or []},
            )
        ),
        description=dedent(
            """\
            Related organisation units.

            Examples of user-keys:
            * `["Administrative", "Payroll"]`
            * `["IT-Support", "IT-Support]`
            * `["Majora School", "Alias School"]`

            Note:
            The result list should always be of length 2, corresponding to the elements of the bijection.
            """
        ),
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
    )

    @strawberry.field(
        description="UUIDs of the related organisation units.",
        deprecation_reason=gen_uuid_field_deprecation("org_units"),
    )
    async def org_unit_uuids(self, root: RelatedUnitRead) -> list[UUID]:
        return root.org_unit_uuids

    validity: Validity = strawberry.auto


# Role
# ----
@strawberry.experimental.pydantic.type(
    model=RoleBindingRead,
    description="The role a person has within an organisation unit",
)
class RoleBinding:
    @strawberry.field(description="UUID of the entity")
    async def uuid(self, root: RoleBindingRead) -> UUID:
        return root.uuid

    # TODO: Document this
    user_key: str = strawberry.auto

    role: list[LazyClass] = strawberry.field(
        resolver=to_list(
            seed_resolver(class_resolver, {"uuids": lambda root: [root.role]})
        ),
        description=dedent(
            """\
            The role that is being fulfilled.

            Examples of user-keys:
            * `"AD Read"`
            * `"AD Write"`
            * `"SAP Admin"`
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("class")],
    )

    ituser: list[LazyITUser] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                it_user_resolver, {"uuids": lambda root: uuid2list(root.it_user_uuid)}
            )
        ),
        description="The IT-user that should be granted this role\n"
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("ituser")],
    )

    org_unit: list[LazyOrganisationUnit] = strawberry.field(
        resolver=to_list(
            seed_resolver(
                organisation_unit_resolver,
                {"uuids": lambda root: [root.org_unit_uuid]},
            )
        ),
        description=dedent(
            """\
            The organisational unit in which the role is being fulfilled.
            """
        )
        + list_to_optional_field_warning,
        permission_classes=[IsAuthenticatedPermission, gen_read_permission("org_unit")],
    )

    validity: Validity = strawberry.auto


# Version
# -------
@strawberry.type(description="MO and DIPEX versions")
class Version:
    @strawberry.field(
        description=dedent(
            """\
            OS2mo Version.

            Contains a [semantic version](https://semver.org/) on released versions of OS2mo.
            Contains the string `HEAD` on development builds of OS2mo.

            Examples:
            * `HEAD`
            * `22.2.6`
            * `21.0.0`
            """
        )
    )
    async def mo_version(self) -> str | None:
        """Get the mo version.

        Returns:
            The version.
        """
        return config.get_settings().commit_tag

    @strawberry.field(
        description=dedent(
            """\
            OS2mo commit hash.

            Contains a git hash on released versions of OS2mo.
            Contains the empty string on development builds of OS2mo.

            Examples:
            * `""`
            * `880bd2009baccbdf795a8cef3b5b32b42c91c51b`
            * `b29e45449a857cf78725eff10c5856075417ea51`
            """
        )
    )
    async def mo_hash(self) -> str | None:
        """Get the mo commit hash.

        Returns:
            The commit hash.
        """
        return config.get_settings().commit_sha

    @strawberry.field(
        description="LoRa version. Returns the exact same as `mo_version`.",
        deprecation_reason="MO and LoRa are shipped and versioned together",
    )
    async def lora_version(self) -> str | None:
        """Get the lora version.

        Returns:
            The version.
        """
        return config.get_settings().commit_tag

    @strawberry.field(
        description=dedent(
            """\
            DIPEX version.

            Contains a [semantic version](https://semver.org/) if configured.
            Contains the `null` on development builds of OS2mo.

            Examples:
            * `null`
            * `4.34.1`
            * `4.28.0`
            """
        )
    )
    async def dipex_version(self) -> str | None:
        return config.get_settings().confdb_dipex_version__do_not_use


@strawberry.type(description="Status on whether a specific subsystem is working")
class Health:
    identifier: str = strawberry.field(
        description=dedent(
            """\
        Healthcheck identifier.

        Examples:
        * `"dataset"`
        * `"dar"`
        * `"amqp"`
        """
        )
    )

    @strawberry.field(
        description=dedent(
            """\
        Healthcheck status.

        Returns:
        * `true` if the healthcheck passed
        * `false` if the healthcheck failed
        * `null` if the healthcheck is irrelevant (submodule not loaded, etc)

        Note:
        Querying the healthcheck status executes the underlying healthcheck directly.
        Excessively querying this endpoint may have performance implications.
        """
        )
    )
    async def status(self) -> bool | None:
        return await health_map[self.identifier]()


# File
# ----
@strawberry.type(description="A stored file available for download.")
class File:
    file_store: FileStore = strawberry.field(
        description=dedent(
            """\
        The store the file is in.

        The FileStore type lists all possible enum values.
    """
        )
    )

    file_name: str = strawberry.field(
        description=dedent(
            """\
        Name of the file.

        Examples:
        * `"report.odt"`
        * `"result.csv"`
        """
        )
    )

    @strawberry.field(
        description=dedent(
            """\
        The textual contents of the file.

        Examples:
        * A csv-file:
        ```
        Year,Model,Make
        1997,Ford,E350
        2000,Mercury,Cougar
        ...
        ```
        * A textual report:
        ```
        Status of this Memo

        This document specifies an Internet standards track
        ...
        ```

        Note:
        This should only be used for text files formats such as `.txt` or `.csv`.
        For binary formats please use `base64_contents` instead.
        """
        )
    )
    async def text_contents(self, info: Info) -> str:
        session = info.context["session"]
        content = await db.files.read(session, self.file_store, self.file_name)
        return content.decode("utf-8")

    @strawberry.field(
        description=dedent(
            """\
        The base64 encoded contents of the file.

        Examples:
        * A text file:
        ```
        TW96aWxsYSBQdWJsaWMgTGljZW5zZSBWZXJzaW9uIDIuMAo
        ...
        ```
        * A binary file:
        ```
        f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAoF5GAAAA
        ...
        ```

        Note:
        While this works for binary and text files alike, it may be preferable to use `text_contents` for text files.
        """
        )
    )
    async def base64_contents(self, info: Info) -> str:
        session = info.context["session"]
        content = await db.files.read(session, self.file_store, self.file_name)
        data = b64encode(content)
        return data.decode("ascii")


# Configuration
# -------------
@strawberry.type(description="A configuration setting.")
class Configuration:
    def get_settings_value(self) -> Any:
        """Get the settings value.

        Args:
            key: The settings key.

        Returns:
            The settings value.
        """
        return getattr(config.get_settings(), self.key)

    key: str = strawberry.field(
        description=dedent(
            """\
        The unique settings identifier.

        Examples:
        * `commit_tag`
        * `environment`
        * `confdb_show_roles`
        """
        )
    )

    @strawberry.field(
        description=dedent(
            """\
        JSONified settings value.

        Examples:
        * `"true"`
        * `"\\"\\""`
        * `"null"`
        * `"[]"`
        """
        )
    )
    def jsonified_value(self) -> str:
        """Get the jsonified value.

        Returns:
            The value.
        """
        return json.dumps(jsonable_encoder(self.get_settings_value()))

    @strawberry.field(
        description=dedent(
            """\
        Stringified settings value.

        Examples:
        * `"True"`
        * `""`
        * `"None"`
        * `"[]"`
        """
        )
    )
    def stringified_value(self) -> str:
        """Get the stringified value.

        Returns:
            The value.
        """
        return str(self.get_settings_value())
