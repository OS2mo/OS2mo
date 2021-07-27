# SPDX-FileCopyrightText: 2019-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0

import abc
import json
from structlog import get_logger
from asyncio import create_task, gather
from datetime import datetime
from inspect import isawaitable
from typing import Any, Dict, Iterable, List, Optional, Tuple
from functools import partial
from itertools import starmap

from more_itertools import flatten
from more_itertools import ilen
from ra_utils.apply import apply

from .. import exceptions, util
from .. import mapping
from ..lora import Connector

logger = get_logger()

READING_HANDLERS = {}


def register(object_type):
    def decorator(cls):
        READING_HANDLERS[object_type] = cls
        return cls

    return decorator


def get_handler_for_type(object_type) -> 'ReadingHandler':
    try:
        return READING_HANDLERS[object_type]
    except LookupError:
        exceptions.ErrorCodes.E_UNKNOWN_ROLE_TYPE(type=object_type)


class ReadingHandler:

    @classmethod
    @abc.abstractmethod
    async def get(cls, c, search_fields, changed_since: Optional[datetime] = None):
        """
        Read a list of objects based on the given search parameters

        :param c: A LoRa connector
        :param changed_since: Date used to filter registrations from LoRa
        :param search_fields: A dict containing search parameters
        """
        pass

    @classmethod
    @abc.abstractmethod
    async def get_from_type(cls, c, type, obj_uuid,
                            changed_since: Optional[datetime] = None):
        """
        Read a list of objects related to a certain object

        :param c: A LoRa connector
        :param type: Either 'e' or 'ou' depending on if related to an
            employee or orgunit
        :param changed_since: Date used to filter registrations from LoRa

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

    # TODO: Why do subclasses have funcid instead of obj_id?!
    @classmethod
    @abc.abstractmethod
    async def _get_mo_object_from_effect(cls, effect, start, end, obj_id):
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
        cls,
        c: Connector,
        function_id: str,
        function_obj: Any,
    ) -> List[Any]:
        """
        just a wrapper that makes calls in parallel. Not encapsulating / motivated by
        business logic
        :param c: A LoRa connector
        :param function_id: UUID from object_tuple
        :param function_id: object from object_tuple
        :return: List of whatever this returns get_mo_object_from_effect
        """
        effects = await cls._get_effects(c, function_obj)
        effects = filter(
            apply(lambda start, end, effect: util.is_reg_valid(effect)),
            effects
        )
        # TODO: This swapping argument order should be avoidable, if the functions
        #       actually fit together, so they could be chained.
        effects = starmap(lambda start, end, effect: (effect, start, end), effects)
        # TODO: Partial could work here if funcid/obj_id was consistently named
        effects = map(lambda tup: (*tup, function_id), effects)
        tasks = map(create_task, starmap(
            cls._get_mo_object_from_effect, effects
        ))
        return await gather(*tasks)

    @classmethod
    async def _get_obj_effects(
        cls,
        c: Connector,
        object_tuples: Iterable[Tuple[str, Dict[Any, Any]]]
    ) -> List[Dict[Any, Any]]:
        """
        Convert a list of LoRa objects into a list of MO objects

        :param c: A LoRa connector
        :param object_tuples: An iterable of (UUID, object) tuples
        """
        tasks = map(create_task, starmap(
            partial(cls.__async_get_mo_object_from_effect, c),
            object_tuples
        ))
        return list(flatten(await gather(*tasks)))


class OrgFunkReadingHandler(ReadingHandler):
    function_key = None

    SEARCH_FIELDS = {
        'e': 'tilknyttedebrugere',
        'ou': 'tilknyttedeenheder'
    }

    @staticmethod
    async def assign_when_ready(mapping, key, awaitable_value):
        """
        convenient wrapper allowing easy creation of tasks

        :param mapping:
        :param key:
        :param awaitable_value:
        :return:
        """
        mapping[key] = await awaitable_value

    @classmethod
    async def get(cls, c, search_fields, changed_since: Optional[datetime] = None):
        object_tuples = await cls._get_lora_object(c, search_fields,
                                                   changed_since=changed_since)
        object_tuples = list(object_tuples)

        mo_objects = await cls._get_obj_effects(c, object_tuples)
        mo_objects = list(mo_objects)

        # Mutate objects by awaiting as needed. This delayed evaluation allows bulking.
        def generate_awaitables(mo_objects):
            for mo_object in mo_objects:
                for key, val in mo_object.items():
                    if isawaitable(val):
                        yield mo_object, key, val

        # Ensure all async tasks have completed
        awaitables = generate_awaitables(mo_objects)
        awaitables = map(create_task, starmap(cls.assign_when_ready, awaitables))
        await gather(*awaitables)

        return mo_objects

    @classmethod
    async def get_from_type(cls, c, type, objid,
                            changed_since: Optional[datetime] = None):
        """Retrieve a list of MO objects of type 'type' and with object ID
        'objid'.

        :param type: str
        :param objid: UUID
        :param changed_since: Date used to filter registrations from LoRa
        :return: list of matching MO objects
        """
        return await cls.get(c, cls._get_search_fields(type, objid),
                             changed_since=changed_since)

    @classmethod
    async def get_count(cls, c, type, objid):
        """Retrieve the number of valid LoRA objects of type 'type' related to
        object ID 'objid'.

        :param type: str
        :param objid: UUID
        :return: int
        """
        tuple_gen = await cls._get_lora_object(c, cls._get_search_fields(type, objid))
        return ilen(filter(lambda tup: util.is_reg_valid(tup[1]), tuple_gen))

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
    def __function_key_filter(cls, object_tuple: Tuple[str, Dict[Any, Any]]) -> bool:
        """

        :param object_tuple: UUID, object
        :return: whether function key matches class
        """
        _, obj = object_tuple

        field = mapping.ORG_FUNK_EGENSKABER_FIELD(obj)

        if not field:
            return False

        return field[0]['funktionsnavn'] == cls.function_key

    @classmethod
    async def _get_lora_object(cls, c, search_fields,
                               changed_since: Optional[datetime] = None):
        if mapping.UUID in search_fields:
            object_tuples = await c.organisationfunktion.get_all_by_uuid(
                uuids=search_fields[mapping.UUID],
                changed_since=changed_since,
            )
        else:
            object_tuples = await c.organisationfunktion.get_all(
                funktionsnavn=cls.function_key,
                changed_since=changed_since,
                **search_fields,
            )

        return object_tuples

    @classmethod
    async def _get_effects(cls, c, obj, **params):
        relevant = {
            'attributter': (
                'organisationfunktionegenskaber',
                'organisationfunktionudvidelser',
            ),
            'relationer': (
                'opgaver',
                'adresser',
                'organisatoriskfunktionstype',
                'tilknyttedeenheder',
                'tilknyttedeklasser',
                'tilknyttedebrugere',
                'tilknyttedefunktioner',
                'tilknyttedeitsystemer',
                'tilknyttedepersoner',
                'primær',
            ),
            'tilstande': (
                'organisationfunktiongyldighed',
            ),
        }
        also = {
            'relationer': (
                'tilhoerer',
                'tilknyttedeorganisationer',
            ),
        }

        return await c.organisationfunktion.get_effects(
            obj,
            relevant,
            also,
            **params
        )

    @classmethod
    async def _get_mo_object_from_effect(cls, effect, start, end,
                                         funcid) -> Dict[str, Any]:

        properties = mapping.ORG_FUNK_EGENSKABER_FIELD(effect)[0]
        user_key = properties['brugervendtnoegle']

        r = {
            mapping.UUID: funcid,
            mapping.USER_KEY: user_key,
            mapping.VALIDITY: util.get_validity_object(start, end),
        }

        if properties.get('integrationsdata') is not None:
            try:
                r[mapping.INTEGRATION_DATA] = json.loads(
                    properties['integrationsdata'],
                )
            except json.JSONDecodeError:
                logger.warning(
                    'invalid integration data for function',
                    funcid=funcid
                )
                r[mapping.INTEGRATION_DATA] = None

        return r
