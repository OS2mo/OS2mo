# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from collections.abc import Callable

import more_itertools

from mora.app import create_app
from mora.graphapi.main import graphql_versions

doc_endpoints = {
    "/docs",
    "/docs/oauth2-redirect",
    "/openapi.json",
    "/redoc",
}
health_endpoints = {
    "/health/",
    "/health/live",
    "/health/ready",
    "/health/{identifier}",
}
service_api = {
    "/service/c/ancestor-tree",
    "/service/c/{classid}/",
    "/service/c/{classid}/children",
    "/service/configuration",
    "/service/details/create",
    "/service/details/edit",
    "/service/details/terminate",
    "/service/e/autocomplete/",
    "/service/e/cpr_lookup/",
    "/service/e/create",
    "/service/e/{eid}/details/address",
    "/service/e/{id}/",
    "/service/e/{uuid}/terminate",
    "/service/exports/",
    "/service/exports/{file_name}",
    "/service/f/{facet}/",
    "/service/f/{facet}/children",
    "/service/insight",
    "/service/insight/download",
    "/service/insight/files",
    "/service/keycloak.json",
    "/service/navlinks",
    "/service/o/",
    "/service/o/{orgid}/",
    "/service/o/{orgid}/address_autocomplete/",
    "/service/o/{orgid}/e/",
    "/service/o/{orgid}/f/",
    "/service/o/{orgid}/f/{facet}/",
    "/service/o/{orgid}/it/",
    "/service/o/{orgid}/ou/",
    "/service/o/{orgid}/ou/tree",
    "/service/o/{parentid}/children",
    "/service/ou/ancestor-tree",
    "/service/ou/autocomplete/",
    "/service/ou/create",
    "/service/ou/{orgid}/details/address",
    "/service/ou/{origin}/map",
    "/service/ou/{parentid}/children",
    "/service/ou/{unitid}/",
    "/service/ou/{unitid}/configuration",
    "/service/ou/{unitid}/refresh",
    "/service/ou/{uuid}/terminate",
    "/service/token",
    "/service/validate/active-engagements/",
    "/service/validate/address/",
    "/service/validate/candidate-parent-org-unit/",
    "/service/validate/cpr/",
    "/service/validate/employee/",
    "/service/validate/existing-associations/",
    "/service/validate/org-unit/",
    "/service/{rest_of_path:path}",
    "/service/e/{id}/details/association",
    "/service/e/{id}/details/employee",
    "/service/e/{id}/details/engagement",
    "/service/e/{id}/details/engagement_association",
    "/service/e/{id}/details/it",
    "/service/e/{id}/details/kle",
    "/service/e/{id}/details/leave",
    "/service/e/{id}/details/manager",
    "/service/e/{id}/details/org_unit",
    "/service/e/{id}/details/owner",
    "/service/e/{id}/details/related_unit",
    "/service/e/{id}/details/role",
    "/service/ou/{id}/details/association",
    "/service/ou/{id}/details/employee",
    "/service/ou/{id}/details/engagement",
    "/service/ou/{id}/details/engagement_association",
    "/service/ou/{id}/details/it",
    "/service/ou/{id}/details/kle",
    "/service/ou/{id}/details/leave",
    "/service/ou/{id}/details/manager",
    "/service/ou/{id}/details/org_unit",
    "/service/ou/{id}/details/owner",
    "/service/ou/{id}/details/related_unit",
    "/service/ou/{id}/details/role",
    "/service/e/{id}/details/",
    "/service/ou/{id}/details/",
}

graphql_endpoints = set(
    more_itertools.flatten(
        (
            f"/graphql/v{version.version}",
            f"/graphql/v{version.version}/schema.graphql",
        )
        for version in graphql_versions
    )
)


lora_endpoints = {
    "/lora",
}

testing_endpoints = {
    "/testing/amqp/flush",
    "/testing/database/autocommit",
    "/testing/database/commit",
    "/testing/database/rollback",
}

all_endpoints = (
    {
        "",
        "/graphql",
        "/graphql/v{version_number}",
        "/version/",
        "/saml/sso/",
    }
    | lora_endpoints
    | doc_endpoints
    | health_endpoints
    | service_api
    | graphql_endpoints
)


def test_all_endpoints() -> None:
    app = create_app()
    routes = {r.path for r in app.routes} | {""}
    assert routes == all_endpoints


def test_lora_endpoints(set_settings: Callable[..., None]) -> None:
    set_settings(EXPOSE_LORA=False)
    app = create_app()
    routes = {r.path for r in app.routes} | {""}
    assert routes == all_endpoints - lora_endpoints


def test_testing_endpoints(set_settings: Callable[..., None]) -> None:
    set_settings(INSECURE_ENABLE_TESTING_API=True)
    app = create_app()
    routes = {r.path for r in app.routes} | {""}
    assert routes == all_endpoints | testing_endpoints
