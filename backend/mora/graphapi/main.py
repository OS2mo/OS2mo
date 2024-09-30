# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import importlib
import re
from functools import cache
from typing import Any

from fastapi import APIRouter
from fastapi import FastAPI
from fastapi import Request
from fastapi import status
from fastapi.responses import JSONResponse
from fastapi.responses import RedirectResponse
from more_itertools import first
from structlog.stdlib import get_logger

logger = get_logger()

newest = 23


@cache
def load_graphql_version(version_number: int) -> APIRouter:
    """Dynamically import and load the specified GraphQL version.

    Note:
        This function should only ever be called once for each version_number.

    Args:
        version_number: The version number of the GraphQL version to load.

    Returns:
        A FastAPI APIRouter for the given GraphQL version.
    """
    assert version_number >= 1
    assert version_number <= newest

    version = importlib.import_module(
        f"mora.graphapi.versions.v{version_number}.version"
    ).GraphQLVersion
    # TODO: Add deprecation header as per the decision log (link/successor)
    router = version.get_router(is_latest=version_number is newest)
    return router


def setup_graphql(app: FastAPI, min_version: int) -> None:
    """Setup our GraphQL endpoints on FastAPI.

    Note:
        GraphQL version endpoints are dynamically loaded.

    Args:
        app: The FastAPI to load GraphQL endpoints on.
        min_version: The minimum version of GraphQL to support.
    """

    @app.get("/graphql")
    @app.get("/graphql/")
    async def redirect_to_latest_graphiql() -> RedirectResponse:
        """Redirect unversioned GraphiQL so developers can pin to the newest version."""
        return RedirectResponse(f"/graphql/v{newest}")

    versions = range(min_version, newest)
    oldest = first(versions)

    imported: set[int] = set()
    version_regex = re.compile(r"/graphql/v(\d+)")

    @app.middleware("http")
    async def graphql_loader(request: Request, call_next: Any) -> Any:
        graphql_match = version_regex.match(request.url.path)
        if graphql_match is None:
            return await call_next(request)

        version_number = int(graphql_match.group(1))
        if version_number in imported:
            return await call_next(request)

        # Removed GraphQL versions send 410
        if 0 < version_number < oldest:
            return JSONResponse(
                status_code=status.HTTP_410_GONE,
                content={"message": "Removed GraphQL version"},
            )

        # Non-existent GraphQL versions send 404
        if version_number <= 0 or version_number > newest:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"message": "No such GraphQL version"},
            )

        logger.info(
            "Importing GraphQL version", version=version_number, imported=imported
        )
        router = load_graphql_version(version_number)
        app.include_router(prefix=f"/graphql/v{version_number}", router=router)
        imported.add(version_number)

        return await call_next(request)
