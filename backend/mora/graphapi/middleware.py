# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
"""Starlette plugins to create context variables that can be used in the service app."""
from collections.abc import AsyncIterator
from collections.abc import Awaitable
from collections.abc import Iterator
from inspect import isasyncgen
from time import monotonic
from typing import Any

from starlette_context import context
from starlette_context import request_cycle_context
from strawberry.extensions import SchemaExtension


_IS_GRAPHQL_MIDDLEWARE_KEY = "is_graphql"


async def is_graphql_context() -> AsyncIterator[None]:
    """Application dependency to create the `is_graphql` context variable.

    The variable is used to control the details level for various entities deep within
    the application without having to pass a details level variable throughout the
    entire callstack.

    The variable is `False` by default as to keep everything unaffected by default,
    and is only switched to `True` when a GraphQL query is being executed. This changed
    is trigger by the Starberry GraphQL extension: StarletteContextExtension.

    After all reading code is implemented using GraphQL / shimming this plugin and the
    corresponding extension can be eliminated.
    """
    data = {**context, _IS_GRAPHQL_MIDDLEWARE_KEY: 0}
    with request_cycle_context(data):
        yield


class StarletteContextExtension(SchemaExtension):
    def on_operation(self) -> Iterator[None]:
        # clear query arguments bypassing the stack
        context["query_args"] = {}
        # Store reference counter, instead of simple boolean, to ensure we do not set
        # is_graphql=False as soon as the first nested schema execution exits.
        context[_IS_GRAPHQL_MIDDLEWARE_KEY] = (
            context.get(_IS_GRAPHQL_MIDDLEWARE_KEY, 0) + 1
        )
        context["starttime"] = context.get("starttime", monotonic())

        yield

        context[_IS_GRAPHQL_MIDDLEWARE_KEY] = (
            context.get(_IS_GRAPHQL_MIDDLEWARE_KEY, 0) - 1
        )
        context["stoptime"] = monotonic()

    # XXX: Required due to trashy test-code in graphapi/test_middleware.py
    # TODO: Cleanup the test and remove this trash
    async def on_execute(self) -> AsyncIterator[None]:
        iter = super().on_execute()
        if isasyncgen(iter):
            async for x in iter:
                yield x
        else:
            # mypy is majorly confused by this horrible code
            for x in iter:  # type: ignore[union-attr]
                yield x

    async def get_results(self) -> dict[str, Any]:
        # TODO: calling super() because of get_context_from_ext()
        results = super().get_results()
        if isinstance(results, Awaitable):
            results = await results

        if context.get("lora_page_out_of_range"):
            results["__page_out_of_range"] = True

        # Includes GraphQL request runtime when the x-request-runtime header is set
        request = self.execution_context.context.get("request")
        if request and request.headers.get("x-request-runtime"):
            results["runtime"] = context["stoptime"] - context["starttime"]

        return results


def is_graphql() -> bool:
    """Determine if we are currently evaluating a GraphQL query."""
    return context.get(_IS_GRAPHQL_MIDDLEWARE_KEY, 0) > 0
