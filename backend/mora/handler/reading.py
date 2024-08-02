# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import abc
from asyncio import create_task
from asyncio import gather
from collections.abc import Iterable
from inspect import isawaitable
from typing import Any

from structlog import get_logger

from .. import exceptions
from .. import mapping
from .. import util
from ..lora import Connector

logger = get_logger()

READING_HANDLERS = {}


def register(object_type):
    def decorator(cls):
        READING_HANDLERS[object_type] = cls
        return cls

    return decorator


def get_handler_for_type(object_type) -> "ReadingHandler":
    try:
        return READING_HANDLERS[object_type]
    except LookupError:
        exceptions.ErrorCodes.E_UNKNOWN_ROLE_TYPE(type=object_type)


class ReadingHandler:
    is_reg_valid = util.is_reg_valid

    @classmethod
    @abc.abstractmethod
    async def get(
        cls,
        c,
        search_fields,
        flat: bool = False,
    ) -> list[dict]:
        """
        Read a list of objects based on the given search parameters

        :param c: A LoRa connector
        :param search_fields: A dict containing search parameters
        """
        pass

    @classmethod
    @abc.abstractmethod
    async def get_from_type(cls, c, type, obj_uuid):
        """
        Read a list of objects related to a certain object

        :param c: A LoRa connector
        :param type: Either 'e' or 'ou' depending on if related to an
            employee or orgunit

        :param obj_uuid: The UUID of the related employee/orgunit
        """
        pass

    @classmethod
    @abc.abstractmethod
    async def _get_effects(cls, c, obj, **params):
        """
        Chunk a LoRa object up into effects

        :param c: A LoRa connector
        :param obj: An object to be chunked
        :param params: Additional parameters to be sent along to a LoRa
            chunking function
        """
        pass

    @classmethod
    @abc.abstractmethod
    async def _get_mo_object_from_effect(
        cls, effect, start, end, obj_id, flat: bool = False
    ):
        """
        Convert an effect to a MO object

        :param effect: An effect to be convertd
        :param start: The start date for the effect
        :param end: The end date for the effect
        :param obj_id: The UUID of the object in LoRa the effect originates
            from
        """
        pass

    @classmethod
    async def __async_get_mo_object_from_effect(
        cls, c, function_id, function_obj, flat: bool = False
    ) -> list[Any]:
        """
        just a wrapper that makes calls in parallel. Not encapsulating / motivated by
        business logic
        :param c: A LoRa connector
        :param function_id: UUID from object_tuple
        :param function_id: object from object_tuple
        :return: List of whatever this returns get_mo_object_from_effect
        """
        return await gather(
            *[
                create_task(
                    cls._get_mo_object_from_effect(
                        effect, start, end, function_id, flat
                    )
                )
                for start, end, effect in (await cls._get_effects(c, function_obj))
                if cls.is_reg_valid(effect)
            ]
        )

    @classmethod
    async def _get_obj_effects(
        cls,
        c: Connector,
        object_tuples: Iterable[tuple[str, dict[Any, Any]]],
        flat: bool = False,
    ) -> list[dict[Any, Any]]:
        """
        Convert a list of LoRa objects into a list of MO objects

        :param c: A LoRa connector
        :param object_tuples: An iterable of (UUID, object) tuples
        """
        # flatten a bunch of nested tasks
        objs = [
            x
            for sublist in await gather(
                *[
                    create_task(
                        cls.__async_get_mo_object_from_effect(
                            c, function_id, function_obj, flat
                        )
                    )
                    for function_id, function_obj in object_tuples
                ]
            )
            for x in sublist
        ]

        # TODO(#61001): filter objects with zero-length validity since they do not make
        # sense in terms of the business logic. Ideally, we would disallow the creation
        # of these objects in the first place, or - less ideally - filter them directly
        # in the database, but MO and LoRa do not model objects and their datetimes in
        # the same way:
        # MO subtracts ~1 day from the timestamp returned from LoRa in some cases,
        # depending on whether or not it is a 'from' or 'to' date. This logic is too
        # convoluted to reimplement in the database to properly detect MO zero-lengths.
        # Additionally, MO splits a single LoRa object registration into multiple MO
        # object validities. This makes it hard to validate and reason about whether or
        # not a write in MOs GraphQL result in a zero-length validity after it has been
        # converted to a LoRa registration, written to the database, read out, and
        # converted back to MO object validities.
        def is_zero_validity(obj: dict) -> bool:
            try:
                from_ = obj["validity"]["from"]
                to = obj["validity"]["to"]
            except KeyError:
                return False
            # An infinite validity (from=None,to=None) is not zero
            if from_ is None and to is None:
                return False
            return from_ == to

        objs = [o for o in objs if not is_zero_validity(o)]
        return objs


class OrgFunkReadingHandler(ReadingHandler):
    function_key = None

    SEARCH_FIELDS = {"e": "tilknyttedebrugere", "ou": "tilknyttedeenheder"}

    @classmethod
    async def get(
        cls,
        c,
        search_fields,
        flat: bool = False,
    ):
        object_tuples = await cls._get_lora_object(c, search_fields)
        mo_objects = await cls._get_obj_effects(c, object_tuples, flat)

        # Return MO objects early if they are flat
        if flat:
            return mo_objects

        # Mutate objects by awaiting as needed. This delayed evaluation allows bulking.
        for mo_object in mo_objects:
            for key, val in mo_object.items():
                if isawaitable(val):
                    mo_object[key] = await val
        return mo_objects

    @classmethod
    async def get_from_type(cls, c, type, objid):
        """Retrieve a list of MO objects of type 'type' and with object ID
        'objid'.

        :param type: str
        :param objid: UUID
        :return: list of matching MO objects
        """
        return await cls.get(c, cls._get_search_fields(type, objid))

    @classmethod
    async def get_count(cls, c, type, objid):
        """Retrieve the number of valid LoRA objects of type 'type' related to
        object ID 'objid'.

        :param type: str
        :param objid: UUID
        :return: int
        """
        tuple_gen = await cls._get_lora_object(c, cls._get_search_fields(type, objid))
        return len(list(filter(lambda tup: util.is_reg_valid(tup[1]), tuple_gen)))

    @classmethod
    def _get_search_fields(cls, type, objid):
        """Return search fields suitable to retrieve a LoRA object of type
        'type' and with object ID 'objid'.

        :param type: str
        :param objid: UUID
        :return: search fields as dict
        """
        return {cls.SEARCH_FIELDS[type]: objid}

    @classmethod
    async def _get_lora_object(cls, c, search_fields):
        if mapping.UUID in search_fields:
            object_tuples = await c.organisationfunktion.get_all_by_uuid(
                uuids=search_fields[mapping.UUID],
            )
        else:
            object_tuples = await c.organisationfunktion.get_all(
                funktionsnavn=cls.function_key,
                **search_fields,
            )

        return object_tuples

    @classmethod
    async def _get_effects(cls, c, obj, **params):
        relevant = {
            "attributter": (
                "organisationfunktionegenskaber",
                "organisationfunktionudvidelser",
            ),
            "relationer": (
                "opgaver",
                "adresser",
                "organisatoriskfunktionstype",
                "tilknyttedeenheder",
                "tilknyttedeklasser",
                "tilknyttedebrugere",
                "tilknyttedefunktioner",
                "tilknyttedeitsystemer",
                "tilknyttedepersoner",
                "primær",
            ),
            "tilstande": ("organisationfunktiongyldighed",),
        }
        also = {
            "relationer": (
                "tilhoerer",
                "tilknyttedeorganisationer",
            ),
        }

        return await c.organisationfunktion.get_effects(obj, relevant, also, **params)

    @classmethod
    async def _get_mo_object_from_effect(
        cls, effect, start, end, funcid, flat: bool = False
    ) -> dict[str, Any]:
        properties = mapping.ORG_FUNK_EGENSKABER_FIELD(effect)[0]
        user_key = properties["brugervendtnoegle"]

        r = {
            mapping.UUID: funcid,
            mapping.USER_KEY: user_key,
            mapping.VALIDITY: util.get_validity_object(start, end),
        }

        return r
