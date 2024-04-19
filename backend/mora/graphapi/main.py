# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import importlib
import re
import time
from typing import Any

import structlog
from fastapi import APIRouter
from fastapi import FastAPI
from fastapi import HTTPException
from more_itertools import first
from more_itertools import last
from starlette.requests import Request
from starlette.responses import RedirectResponse


logger = structlog.get_logger()

graphql_versions = list(range(2, 22))
newest = last(graphql_versions)


def load_graphql_version(version_number: int) -> APIRouter:
    """Dynamically import and load the specified GraphQL version.

    Note:
        This function should only ever be called once for each version_number.

    Args:
        version_number: The version number of the GraphQL version to load.

    Returns:
        A FastAPI APIRouter for the given GraphQL version.
    """
    start_time = time.monotonic()
    version = importlib.import_module(
        f"mora.graphapi.versions.v{version_number}.version"
    ).GraphQLVersion
    duration = time.monotonic() - start_time
    logger.info("Imported GraphQL router", version=version_number, duration=duration)

    # TODO: Add deprecation header as per the decision log (link/successor)
    start_time = time.monotonic()
    router = version.get_router(is_latest=version_number is newest)
    duration = time.monotonic() - start_time
    logger.info(
        "Generated GraphQL APIRouter", version=version_number, duration=duration
    )
    return router


def setup_graphql(app: FastAPI) -> None:
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

    oldest = first(graphql_versions)
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
        if 0 < version_number <= oldest:
            raise HTTPException(
                status_code=400, detail={"message": "Removed GraphQL version"}
            )

        # Non-existent GraphQL versions send 404
        if version_number <= 0 or version_number > newest:
            raise HTTPException(
                status_code=404, detail={"message": "No such GraphQL version"}
            )

        logger.info(
            "Importing GraphQL version", version=version_number, imported=imported
        )
        router = load_graphql_version(version_number)
        app.include_router(prefix=f"/graphql/v{version_number}", router=router)
        imported.add(version_number)

        return await call_next(request)
