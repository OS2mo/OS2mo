# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from datetime import date
from uuid import UUID

from fastapi.encoders import jsonable_encoder
from sqlalchemy import cast
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy.engine.row import Row
from sqlalchemy.ext.asyncio.session import async_sessionmaker
from sqlalchemy.orm import aliased
from sqlalchemy.sql import func
from sqlalchemy.sql import select
from sqlalchemy.sql import union

from mora import config
from mora import util
from mora.audit import audit_log
from mora.db import OrganisationEnhedAttrEgenskaber
from mora.db import OrganisationEnhedRegistrering
from mora.db import OrganisationFunktionAttrEgenskaber
from mora.db import OrganisationFunktionRelation
from mora.db import OrganisationFunktionRelationKode
from mora.graphapi.shim import execute_graphql
from mora.service.autocomplete.shared import get_at_date_sql
from mora.service.autocomplete.shared import get_graphql_equivalent_by_uuid
from mora.service.autocomplete.shared import read_sqlalchemy_result
from mora.service.autocomplete.shared import UUID_SEARCH_MIN_PHRASE_LENGTH
from mora.service.util import handle_gql_error


async def search_orgunits(
    sessionmaker: async_sessionmaker, query: str, at: date | None = None
) -> [Row]:
    at_sql, at_sql_bind_params = get_at_date_sql(at)

    selects = [
        select(cte.c.uuid)
        for cte in (
            _get_cte_orgunit_uuid_hits(query, at_sql),
            _get_cte_orgunit_name_hits(query, at_sql),
            _get_cte_orgunit_addr_hits(query, at_sql),
            _get_cte_orgunit_itsystem_hits(query, at_sql),
        )
    ]
    all_hits = union(*selects).cte()

    query_final = (
        select(
            OrganisationEnhedRegistrering.organisationenhed_id.label("uuid"),
        )
        .where(OrganisationEnhedRegistrering.organisationenhed_id == all_hits.c.uuid)
        .group_by(OrganisationEnhedRegistrering.organisationenhed_id)
    )

    async with sessionmaker() as session:
        async with session.begin():
            # Execute & parse results
            result = read_sqlalchemy_result(
                await session.execute(query_final, {**at_sql_bind_params})
            )
            uuids = [orgunit.uuid for orgunit in result]
            audit_log(
                session,
                "search_orgunits",
                "OrganisationEnhed",
                {"query": query, "at": at},
                uuids,
            )
        return result


async def decorate_orgunit_search_result(
    settings: config.Settings, search_results: [Row], at: date | None
):
    graphql_vars = {"uuids": [str(orgunit.uuid) for orgunit in search_results]}
    if at is not None:
        graphql_vars["from_date"] = at

    from mora.graphapi.versions.v8.version import GraphQLVersion

    orgunit_decorate_query = """
            query OrgUnitDecorate($uuids: [UUID!]) {
                org_units(uuids: $uuids, from_date: null, to_date: null) {
                    objects {
                        uuid

                        current {
                            ...orgunit_details
                        }

                        objects {
                            ...orgunit_details
                        }
                    }
                }
            }

            fragment orgunit_details on OrganisationUnit {
                uuid
                name
                user_key

                validity {
                    from
                    to
                }

                ancestors_validity {
                    name
                }
            }
            """
    if settings.confdb_autocomplete_attrs_orgunit:
        orgunit_decorate_query = """
            query OrgUnitDecorate($uuids: [UUID!]) {
                org_units(uuids: $uuids, from_date: null, to_date: null) {
                    objects {
                        uuid

                        current {
                            ...orgunit_details
                        }

                        objects {
                            ...orgunit_details
                        }
                    }
                }
            }

            fragment orgunit_details on OrganisationUnit {
                uuid
                name
                user_key

                validity {
                    from
                    to
                }

                ancestors_validity {
                    name
                }

                addresses_validity {
                    uuid
                    name
                    address_type {
                        uuid
                        name
                    }
                }

                itusers_validity {
                    uuid
                    user_key
                    itsystem {
                        uuid
                        user_key
                        name
                    }
                }
            }
            """

    response = await execute_graphql(
        orgunit_decorate_query,
        graphql_version=GraphQLVersion,
        variable_values=jsonable_encoder(graphql_vars),
    )
    handle_gql_error(response)

    decorated_result = []
    for idx, orgunit in enumerate(search_results):
        graphql_equivalent = get_graphql_equivalent_by_uuid(
            response.data["org_units"]["objects"], orgunit.uuid, at
        )
        if not graphql_equivalent:
            continue

        decorated_result.append(
            {
                "uuid": orgunit.uuid,
                "name": graphql_equivalent["name"],
                "path": _gql_get_orgunit_path(graphql_equivalent),
                "attrs": _gql_get_orgunit_attrs(settings, graphql_equivalent),
                "validity": graphql_equivalent["validity"],
            }
        )

    return decorated_result


def _gql_get_orgunit_attrs(settings: config.Settings, org_unit_graphql: dict) -> [dict]:
    attrs: [dict] = []
    if "addresses" in org_unit_graphql:
        for addr in org_unit_graphql["addresses"]:
            if (
                UUID(addr["address_type"]["uuid"])
                not in settings.confdb_autocomplete_attrs_orgunit
            ):
                continue

            attrs.append(
                {
                    "uuid": UUID(addr["uuid"]),
                    "value": addr["name"],
                    "title": addr["address_type"]["name"],
                }
            )

    if "itusers" in org_unit_graphql:
        for ituser in org_unit_graphql["itusers"]:
            if (
                UUID(ituser["itsystem"]["uuid"])
                not in settings.confdb_autocomplete_attrs_orgunit
            ):
                continue

            attrs.append(
                {
                    "uuid": UUID(ituser["uuid"]),
                    "value": ituser["user_key"],
                    "title": ituser["itsystem"]["name"],
                }
            )

    return attrs


def _gql_get_orgunit_path(org_unit_graphql: dict):
    if not org_unit_graphql.get("ancestors_validity", []):
        return []

    path = [x["name"] for x in reversed(org_unit_graphql["ancestors_validity"])]
    return path + [org_unit_graphql["name"]]


def _get_cte_orgunit_uuid_hits(query: str, at_sql: str):
    search_phrase = util.query_to_search_phrase(query)
    return (
        select(OrganisationEnhedRegistrering.organisationenhed_id.label("uuid"))
        .join(
            OrganisationEnhedAttrEgenskaber,
            OrganisationEnhedAttrEgenskaber.organisationenhed_registrering_id
            == OrganisationEnhedRegistrering.id,
        )
        .where(
            func.char_length(search_phrase) > UUID_SEARCH_MIN_PHRASE_LENGTH,
            OrganisationEnhedRegistrering.organisationenhed_id != None,  # noqa: E711
            cast(OrganisationEnhedRegistrering.organisationenhed_id, Text).ilike(
                search_phrase
            ),
        )
        .cte()
    )


def _get_cte_orgunit_name_hits(query: str, at_sql: str):
    search_phrase = util.query_to_search_phrase(query)
    return (
        select(OrganisationEnhedRegistrering.organisationenhed_id.label("uuid"))
        .join(
            OrganisationEnhedAttrEgenskaber,
            OrganisationEnhedAttrEgenskaber.organisationenhed_registrering_id
            == OrganisationEnhedRegistrering.id,
        )
        .where(
            OrganisationEnhedRegistrering.organisationenhed_id != None,  # noqa: E711
            (
                OrganisationEnhedAttrEgenskaber.enhedsnavn.ilike(search_phrase)
                | OrganisationEnhedAttrEgenskaber.brugervendtnoegle.ilike(search_phrase)
            ),
        )
        .cte()
    )


def _get_cte_orgunit_addr_hits(query: str, at_sql: str):
    orgfunc_tbl_rels_1 = aliased(OrganisationFunktionRelation)
    orgfunc_tbl_rels_2 = aliased(OrganisationFunktionRelation)

    query = util.urnquote(
        query.lower()
    )  # since we are search through "rel_maal_urn"-cols
    search_phrase = util.query_to_search_phrase(query)

    return (
        select(orgfunc_tbl_rels_1.rel_maal_uuid.label("uuid"))
        .outerjoin(
            orgfunc_tbl_rels_2,
            orgfunc_tbl_rels_2.organisationfunktion_registrering_id
            == orgfunc_tbl_rels_1.organisationfunktion_registrering_id,
        )
        .where(
            orgfunc_tbl_rels_1.rel_maal_uuid != None,  # noqa: E711
            cast(orgfunc_tbl_rels_1.rel_type, String)
            == OrganisationFunktionRelationKode.tilknyttedeenheder,
            cast(orgfunc_tbl_rels_2.rel_type, String)
            == OrganisationFunktionRelationKode.adresser,
            orgfunc_tbl_rels_2.rel_maal_urn.ilike(search_phrase),
        )
        .cte()
    )


def _get_cte_orgunit_itsystem_hits(query: str, at_sql: str):
    search_phrase = util.query_to_search_phrase(query)
    return (
        select(OrganisationFunktionRelation.rel_maal_uuid.label("uuid"))
        .outerjoin(
            OrganisationFunktionAttrEgenskaber,
            OrganisationFunktionAttrEgenskaber.organisationfunktion_registrering_id
            == OrganisationFunktionRelation.organisationfunktion_registrering_id,
        )
        .where(
            OrganisationFunktionRelation.rel_maal_uuid != None,  # noqa: E711
            cast(OrganisationFunktionRelation.rel_type, String)
            == OrganisationFunktionRelationKode.tilknyttedeenheder,
            OrganisationFunktionAttrEgenskaber.funktionsnavn == "IT-system",
            OrganisationFunktionAttrEgenskaber.brugervendtnoegle.ilike(search_phrase),
        )
        .cte()
    )
