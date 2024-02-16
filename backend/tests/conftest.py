# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import asyncio
import contextvars
import os
import secrets
import traceback
from asyncio import AbstractEventLoopPolicy
from asyncio import DefaultEventLoopPolicy
from asyncio import Task
from collections.abc import AsyncGenerator
from collections.abc import AsyncIterator
from collections.abc import Awaitable
from collections.abc import Callable
from collections.abc import Generator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import partial
from operator import itemgetter
from pathlib import Path
from typing import Any
from typing import Never
from typing import Protocol
from typing import TypeVar
from unittest.mock import AsyncMock
from unittest.mock import patch
from uuid import UUID
from uuid import uuid4

import pytest
import requests
from _pytest.monkeypatch import MonkeyPatch
from fastapi import FastAPI
from fastapi.testclient import TestClient
from hypothesis import settings as h_settings
from hypothesis import strategies as st
from hypothesis import Verbosity
from hypothesis.database import InMemoryExampleDatabase
from more_itertools import last
from more_itertools import one
from pytest_asyncio import is_async_test
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.ext.asyncio import AsyncConnection
from starlette_context import request_cycle_context

from mora import depends
from mora.app import create_app
from mora.auth.keycloak.oidc import auth
from mora.auth.keycloak.oidc import Token
from mora.auth.keycloak.oidc import token_getter
from mora.auth.middleware import fetch_authenticated_user
from mora.config import get_settings
from mora.db import _DB_SESSION_CONTEXT_KEY
from mora.db import create_engine
from mora.graphapi.main import graphql_versions
from mora.graphapi.versions.latest.dataloaders import MOModel
from mora.graphapi.versions.latest.permissions import ALL_PERMISSIONS
from mora.service.org import ConfiguredOrganisation
from mora.testing import copy_database
from mora.testing import drop_database
from mora.testing import superuser_connection
from oio_rest.config import get_settings as lora_get_settings
from oio_rest.config import Settings as LoraSettings
from oio_rest.db.alembic_helpers import run_async_upgrade
from oio_rest.organisation import Organisation
from ramodels.mo import Validity
from tests.hypothesis_utils import validity_model_strat
from tests.util import darmock
from tests.util import load_sample_structures
from tests.util import MockAioresponses

T = TypeVar("T")
YieldFixture = Generator[T, None, None]
AsyncYieldFixture = AsyncGenerator[T, None]


# Configs + fixtures
h_db = InMemoryExampleDatabase()
h_settings.register_profile("ci", max_examples=30, deadline=None, database=h_db)
h_settings.register_profile("dev", max_examples=10, deadline=None, database=h_db)
h_settings.register_profile(
    "debug", max_examples=10, verbosity=Verbosity.verbose, database=h_db
)
h_settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "dev"))


def pytest_collection_modifyitems(items):
    # httpx
    for item in items:
        item.add_marker(pytest.mark.respx(using="httpx"))
    # pytest-asyncio
    # https://pytest-asyncio.readthedocs.io/en/latest/how-to-guides/run_session_tests_in_same_loop.html
    pytest_asyncio_tests = (item for item in items if is_async_test(item))
    session_scope_marker = pytest.mark.asyncio(scope="session")
    for async_test in pytest_asyncio_tests:
        async_test.add_marker(session_scope_marker)


def pytest_runtest_protocol(item) -> None:
    os.environ["TESTING"] = "True"
    os.environ["PYTEST_RUNNING"] = "True"


st.register_type_strategy(Validity, validity_model_strat())


@pytest.fixture(autouse=True)
def clear_configured_organisation():
    ConfiguredOrganisation.clear()


@pytest.fixture
def set_settings(
    monkeypatch: MonkeyPatch,
) -> YieldFixture[Callable[..., None]]:
    """Set settings via kwargs callback."""

    def _inner(**kwargs: Any) -> None:
        for key, value in kwargs.items():
            monkeypatch.setenv(key, value)
        get_settings.cache_clear()

    yield _inner
    get_settings.cache_clear()


@pytest.fixture(scope="session")
def monkeysession(request):
    from pytest import MonkeyPatch

    mpatch = MonkeyPatch()
    yield mpatch
    mpatch.undo()


@pytest.fixture(scope="session")
def set_session_settings(
    monkeysession: MonkeyPatch,
) -> YieldFixture[Callable[..., None]]:
    """Set settings via kwargs callback."""

    def _inner(**kwargs: Any) -> None:
        for key, value in kwargs.items():
            monkeysession.setenv(key, value)
        get_settings.cache_clear()

    yield _inner
    get_settings.cache_clear()


@pytest.fixture(autouse=True, scope="session")
async def mocked_context() -> YieldFixture[None]:
    """
    Testing code that relies on context vars without a full test client / app.
    https://starlette-context.readthedocs.io/en/latest/testing.html
    """
    # NOTE: This fixture MUST be async to ensure the context is propagated correctly
    # to the tests.
    assert asyncio.get_running_loop()
    with request_cycle_context({}):
        yield


async def fake_auth() -> Token:
    return Token(
        azp="vue",
        email="bruce@kung.fu",
        preferred_username="bruce",
        realm_access={"roles": set()},
        uuid="99e7b256-7dfa-4ee8-95c6-e3abe82e236a",
    )


async def admin_auth() -> Token:
    auth = await fake_auth()
    auth.realm_access.roles = {"admin", "owner"}.union(ALL_PERMISSIONS)
    return auth


async def admin_auth_uuid() -> UUID:
    token = await admin_auth()
    return token.uuid


def fake_token_getter() -> Callable[[], Awaitable[Token]]:
    async def get_fake_token():
        token = await fake_auth()
        return token

    return get_fake_token


def admin_token_getter() -> Callable[[], Awaitable[Token]]:
    async def get_fake_admin_token():
        token = await admin_auth()
        return token

    return get_fake_admin_token


class _SessionmakerDependency:
    def __init__(self, sessionmaker: async_sessionmaker) -> None:
        self.sessionmaker = sessionmaker

    def get_sessionmaker(self) -> async_sessionmaker:
        return self.sessionmaker


class _FakeSessionmaker(async_sessionmaker):
    def begin(self) -> Never:
        self._fail()

    def __call__(self, *args, **kwargs) -> Never:
        self._fail()

    @staticmethod
    def _fail() -> Never:
        # Explicitly pytest-fail to avoid the code under test catching the exception
        pytest.fail(
            "Improperly-configured test: Attempting to access unconfigured database. "
            "If this error originated from a test, you are probably trying to access "
            "the database without requesting a database fixture. If it originated "
            "from a fixture, you may need to explicitly request a TestClient or "
            "database fixture to ensure they are run before your fixture."
        )


@pytest.fixture
def sessionmaker_dependency() -> _SessionmakerDependency:
    """Binds FastAPI sessionmaker dependency to database fixture indirectly.

    This allows each test to request a TestClient and database fixture individually,
    without having to bind them together. This works by having each test-app and
    database fixture request this fixture; the test apps will overwrite its
    get_sessionmaker dependency, and the database fixture will set the class's
    sessionmaker.

    The SessionmakerDependency is initialised with a fake sessionmaker to allow using a
    TestClient without a database fixture. This is required because of the global
    set_sessionmaker_context dependency, which requests the sessionmaker dependency. By
    providing a fake we satisfy the set_sessionmaker_context and defer failing until it
    is attempted used. This can be removed in the future when we don't call
    get_sessionmaker(), but pass it properly through the stack.
    """
    return _SessionmakerDependency(sessionmaker=_FakeSessionmaker())


@pytest.fixture
def fastapi_raw_test_app(sessionmaker_dependency: _SessionmakerDependency) -> FastAPI:
    app = create_app()
    app.dependency_overrides[
        depends.get_sessionmaker
    ] = sessionmaker_dependency.get_sessionmaker
    return app


@pytest.fixture
def fastapi_test_app(fastapi_raw_test_app: FastAPI) -> FastAPI:
    fastapi_raw_test_app.dependency_overrides[auth] = fake_auth
    fastapi_raw_test_app.dependency_overrides[token_getter] = fake_token_getter
    return fastapi_raw_test_app


@pytest.fixture
def fastapi_admin_test_app(fastapi_test_app: FastAPI) -> FastAPI:
    fastapi_test_app.dependency_overrides[auth] = admin_auth
    fastapi_test_app.dependency_overrides[token_getter] = admin_token_getter
    fastapi_test_app.dependency_overrides[fetch_authenticated_user] = admin_auth_uuid
    return fastapi_test_app


@pytest.fixture(scope="session")
def latest_graphql_url() -> str:
    latest = last(graphql_versions)
    return f"/graphql/v{latest.version}"


@pytest.fixture
def raw_client(fastapi_raw_test_app: FastAPI) -> YieldFixture[TestClient]:
    """Fixture yielding a FastAPI test client."""
    with TestClient(fastapi_raw_test_app) as client:
        yield client


@pytest.fixture
def service_client(fastapi_test_app: FastAPI) -> YieldFixture[TestClient]:
    """Fixture yielding a FastAPI test client."""
    with TestClient(fastapi_test_app) as client:
        yield client


@pytest.fixture
def admin_client(fastapi_admin_test_app: FastAPI) -> YieldFixture[TestClient]:
    """Fixture yielding a FastAPI test client."""
    with TestClient(fastapi_admin_test_app) as client:
        yield client


@pytest.fixture
def service_client_not_raising(fastapi_test_app: FastAPI) -> YieldFixture[TestClient]:
    """Fixture yielding a FastAPI test client."""
    with TestClient(fastapi_test_app, raise_server_exceptions=False) as client:
        yield client


@pytest.fixture(scope="session")
def lora_settings() -> LoraSettings:
    return lora_get_settings()


@pytest.fixture(scope="session")
async def superuser(lora_settings: LoraSettings) -> AsyncYieldFixture[AsyncConnection]:
    async with superuser_connection(lora_settings) as connection:
        yield connection


@asynccontextmanager
async def _database_copy(superuser: AsyncConnection, source: str) -> AsyncIterator[str]:
    """Copy database and return the copy's name."""
    # Generate random destination name to support reentrancy for the same source
    destination = f"{source}_copy_{secrets.token_hex(4)}"
    await copy_database(superuser, source, destination)
    yield destination
    await drop_database(superuser, destination)


def _create_sesssionmaker(lora_settings: LoraSettings, database_name: str):
    engine = create_engine(
        user=lora_settings.db_user,
        password=lora_settings.db_password,
        host=lora_settings.db_host,
        name=database_name,
    )
    sessionmaker = async_sessionmaker(engine)
    return sessionmaker


@asynccontextmanager
async def _use_sessionmaker(
    lora_settings: LoraSettings, database_name: str
) -> AsyncIterator[async_sessionmaker]:
    """Patch mora.db.get_sessionmaker() to connect to the provided `database_name`.

    TestApps need to use FastAPI's `dependency_overrides` to inject the sessionmaker.
    This is done through the sessionmaker_dependency fixture.
    """
    sessionmaker = _create_sesssionmaker(lora_settings, database_name)
    data = {_DB_SESSION_CONTEXT_KEY: sessionmaker}
    with request_cycle_context(data):
        yield sessionmaker


@pytest.fixture(scope="session")
async def empty_database_template(
    superuser: AsyncConnection, lora_settings: LoraSettings
) -> AsyncYieldFixture[str]:
    async with _database_copy(superuser, "template1") as database_name:
        # Apply alembic migrations
        async with (
            _use_sessionmaker(lora_settings, database_name) as sessionmaker,
            sessionmaker.begin() as session,
        ):
            connection = await session.connection()
            await run_async_upgrade(connection.engine)
        yield database_name


@pytest.fixture(scope="session")
async def fixture_database_template(
    superuser: AsyncConnection,
    lora_settings: LoraSettings,
    empty_database_template: str,
) -> AsyncYieldFixture[str]:
    async with _database_copy(superuser, empty_database_template) as database_name:
        # Load fixture data
        async with _use_sessionmaker(lora_settings, database_name):
            await load_sample_structures()
        yield database_name


@pytest.fixture
async def empty_db(
    superuser: AsyncConnection,
    lora_settings: LoraSettings,
    sessionmaker_dependency: _SessionmakerDependency,
    empty_database_template: str,
) -> AsyncYieldFixture[async_sessionmaker]:
    async with (
        _database_copy(superuser, empty_database_template) as database_name,
        _use_sessionmaker(lora_settings, database_name) as sessionmaker,
    ):
        sessionmaker_dependency.sessionmaker = sessionmaker
        yield sessionmaker


@pytest.fixture
async def fixture_db(
    superuser: AsyncConnection,
    lora_settings: LoraSettings,
    sessionmaker_dependency: _SessionmakerDependency,
    fixture_database_template: str,
) -> AsyncYieldFixture[async_sessionmaker]:
    async with (
        _database_copy(superuser, fixture_database_template) as database_name,
        _use_sessionmaker(lora_settings, database_name) as sessionmaker,
    ):
        sessionmaker_dependency.sessionmaker = sessionmaker
        yield sessionmaker


@pytest.fixture(scope="session", autouse=True)
def event_loop_policy() -> AbstractEventLoopPolicy:
    """Custom implementation of pytest-asyncio's event_loop_policy fixture[1].

    This fixture is used by pytest-asyncio to run test's setup/run/teardown. It
    is needed to share contextvars between these stages; without it,
    contextvars from async coroutine fixtures are not passed correctly to the
    individual tests. See the issue[2] with solution implementation[3].

    The fixture name shadows the default fixture from pytest-asyncio, and thus
    overrides it. Note that the links below reference overwriting the event_loop
    fixture instead of the event_loop_policy -- this has been deprecated.

    [1] https://github.com/pytest-dev/pytest-asyncio/blob/e92efad68146469228b3ac3478b254b692c6bc90/pytest_asyncio/plugin.py#L957-L970
    [2] https://github.com/pytest-dev/pytest-asyncio/issues/127
    [3] https://github.com/Donate4Fun/donate4fun/blob/cdf047365b7d2df83a952f5bb9544c29051fbdbd/tests/fixtures.py#L87-L113
    """

    def task_factory(loop, coro, context=None):
        # The task_factory breaks context isolation for asyncio tasks, so we need to
        # check the calling context.
        stack = traceback.extract_stack()
        for frame in stack[-2::-1]:
            package_name = Path(frame.filename).parts[-2]
            if package_name != "asyncio":
                if package_name == "pytest_asyncio":
                    # This function was called from pytest_asyncio, use shared context
                    break
                else:
                    # This function was called from somewhere else, create context copy
                    context = None
                break
        return Task(coro, loop=loop, context=context)

    context = contextvars.copy_context()

    class CustomEventLoopPolicy(DefaultEventLoopPolicy):
        def new_event_loop(self):
            loop = super().new_event_loop()
            loop.set_task_factory(partial(task_factory, context=context))
            return loop

    return CustomEventLoopPolicy()


@dataclass
class GQLResponse:
    data: dict | None
    errors: list[dict] | None
    extensions: dict | None
    status_code: int


class GraphAPIPost(Protocol):
    def __call__(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        url: str = latest_graphql_url,
    ) -> GQLResponse:
        ...


@pytest.fixture
def graphapi_post(admin_client: TestClient, latest_graphql_url: str) -> GraphAPIPost:
    def _post(
        query: str,
        variables: dict[str, Any] | None = None,
        url: str = latest_graphql_url,
    ) -> GQLResponse:
        response = admin_client.post(url, json={"query": query, "variables": variables})
        data = response.json().get("data")
        errors = response.json().get("errors")
        extensions = response.json().get("extensions")
        status_code = response.status_code
        return GQLResponse(
            data=data, errors=errors, extensions=extensions, status_code=status_code
        )

    yield _post


@dataclass
class ServiceAPIResponse:
    data: dict | None
    status_code: int | None
    errors: list[Any] | None


@pytest.fixture
def serviceapi_post(service_client: TestClient):
    def _post(
        url: str,
        variables: dict[str, Any] | None = None,
        method: str = "get",
    ) -> ServiceAPIResponse:
        try:
            match (method.lower()):
                case "get":
                    response = service_client.request("GET", url, json=variables)
                case "post":
                    response = service_client.request("POST", url, json=variables)
                case _:
                    response = None

            if not response:
                return None

            return ServiceAPIResponse(
                status_code=response.status_code, data=response.json(), errors=None
            )
        except Exception as e:
            return ServiceAPIResponse(status_code=None, data=None, errors=[e])

    yield _post


def gen_organisation(
    uuid: UUID | None = None,
    name: str = "name",
    user_key: str = "user_key",
) -> dict[str, Any]:
    uuid = uuid or uuid4()
    organisation = {
        "id": str(uuid),
        "registreringer": [
            {
                "attributter": {
                    "organisationegenskaber": [
                        {
                            "brugervendtnoegle": user_key,
                            "organisationsnavn": name,
                        }
                    ]
                },
                "tilstande": {"organisationgyldighed": [{"gyldighed": "Aktiv"}]},
            }
        ],
    }
    return organisation


@pytest.fixture(autouse=True)
def passthrough_test_app_calls(request, respx_mock) -> None:
    """
    By default, RESPX asserts that all HTTPX requests are mocked. This is normally
    fine, but in many of our tests, we want to _both_ make real calls to the OS2mo
    FastAPI TestApp while simultaneously mocking the underlying calls to the LoRa app.

    [1] https://lundberg.github.io/respx/api/#configuration
    """
    respx_mock.route(name="mo", url__startswith="http://testserver/").pass_through()
    if "integration_test" in request.keywords:
        respx_mock.route(
            name="lora", url__startswith="http://localhost/lora/"
        ).pass_through()

    yield

    # RESPX asserts that every route - including the pass-through ones - were called.
    # We don't know if the tests will call MO/LoRa, so we have to remove those routes
    # before the check.
    respx_mock.pop("mo")
    if "integration_test" in request.keywords:
        respx_mock.pop("lora")


@pytest.fixture
def mock_organisation(monkeypatch) -> UUID:
    organisation = gen_organisation()

    monkeypatch.setattr(
        Organisation,
        "get_objects_direct",
        AsyncMock(return_value={"results": [[organisation]]}),
    )
    return organisation["id"]


@pytest.fixture
def mock_get_valid_organisations() -> YieldFixture[UUID]:
    organisation = gen_organisation()

    reg = one(organisation["registreringer"])
    attrs = one(reg["attributter"]["organisationegenskaber"])
    mocked_organisation = {
        "name": attrs["organisationsnavn"],
        "user_key": attrs["brugervendtnoegle"],
        "uuid": organisation["id"],
    }
    with patch("mora.service.org.get_valid_organisations") as mock:
        mock.return_value = [mocked_organisation]
        yield UUID(mocked_organisation["uuid"])


@pytest.fixture
@pytest.mark.usefixtures("fixture_db")
def org_uuids(graphapi_post: GraphAPIPost) -> list[UUID]:
    parent_uuids_query = """
        query FetchOrgUUIDs {
            org_units {
                objects {
                    uuid
                }
            }
        }
    """
    response = graphapi_post(parent_uuids_query)
    assert response.errors is None
    uuids = list(
        map(UUID, map(itemgetter("uuid"), response.data["org_units"]["objects"]))
    )
    return uuids


@pytest.fixture
@pytest.mark.usefixtures("fixture_db")
def employee_uuids(graphapi_post: GraphAPIPost) -> list[UUID]:
    parent_uuids_query = """
        query FetchEmployeeUUIDs {
            employees {
                objects {
                    uuid
                }
            }
        }
    """
    response = graphapi_post(parent_uuids_query)
    assert response.errors is None
    uuids = list(
        map(UUID, map(itemgetter("uuid"), response.data["employees"]["objects"]))
    )
    return uuids


@pytest.fixture
@pytest.mark.usefixtures("fixture_db")
def employee_and_engagement_uuids(
    graphapi_post: GraphAPIPost,
) -> list[tuple[UUID, UUID]]:
    employee_and_engagement_uuids_query = """
        query FetchEmployeeUUIDs {
            employees {
                objects {
                    objects {
                        uuid
                        engagements {
                            uuid
                        }
                    }
                }
            }
        }
    """
    response = graphapi_post(employee_and_engagement_uuids_query)
    assert response.errors is None
    uuids_and_engagements = [
        {
            "uuid": UUID(obj["uuid"]),
            "engagement_uuids": [
                UUID(engagement["uuid"]) for engagement in obj.get("engagements", [])
            ],
        }
        for employee in response.data["employees"]["objects"]
        for obj in employee["objects"]
        if obj.get("engagements")
    ]

    return uuids_and_engagements


@pytest.fixture
@pytest.mark.usefixtures("fixture_db")
def itsystem_uuids(graphapi_post: GraphAPIPost) -> list[UUID]:
    itsystem_uuids_query = """
        query FetchITSystemUUIDs {
            itsystems {
                objects {
                    uuid
                }
            }
        }
    """
    response = graphapi_post(itsystem_uuids_query)
    assert response.errors is None
    uuids = list(
        map(UUID, map(itemgetter("uuid"), response.data["itsystems"]["objects"]))
    )
    return uuids


@pytest.fixture
@pytest.mark.usefixtures("fixture_db")
def ituser_uuids(graphapi_post: GraphAPIPost) -> list[UUID]:
    ituser_uuids_query = """
        query FetchITSystemUUIDs {
            itusers {
                objects {
                    uuid
                }
            }
        }
    """
    response = graphapi_post(ituser_uuids_query)
    assert response.errors is None
    uuids = list(
        map(UUID, map(itemgetter("uuid"), response.data["itusers"]["objects"]))
    )
    return uuids


@pytest.fixture(scope="session")
def patch_loader():
    """Fixture to patch dataloaders for mocks.

    It looks a little weird, being a function yielding a function which returns
    a function. However, this is necessary in order to be able to use the fixture
    with extra parameters.
    """

    def patcher(data: list[MOModel]):
        # If our dataloader functions were sync, we could have used a lambda directly
        # when monkeypatching. They are async, however, and as such we need to mock
        # using an async function.
        async def _patcher(*args, **kwargs):
            return data

        return _patcher

    yield patcher


@pytest.fixture(scope="session")
def graphapi_test(fastapi_admin_test_app: FastAPI) -> TestClient:
    """Fixture yielding a FastAPI test client."""
    return TestClient(fastapi_admin_test_app)


@pytest.fixture(scope="session")
def graphapi_test_no_exc(fastapi_admin_test_app: FastAPI) -> TestClient:
    """Fixture yielding a FastAPI test client.

    This test client does not raise server errors. We use it to check error handling
    in our GraphQL stack.
    """
    return TestClient(fastapi_admin_test_app, raise_server_exceptions=False)


@pytest.fixture
def darmocked():
    with darmock() as mock:
        yield mock


@pytest.fixture
def mockaio():
    with MockAioresponses(["dawa-autocomplete.json"]) as mock:
        yield mock


def get_keycloak_token() -> str:
    """Get OIDC token from Keycloak to send to MOs backend.

    Returns:
        Encoded OIDC token from Keycloak
    """
    r = requests.post(
        "http://keycloak:8080/auth/realms/mo/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "mo-frontend",
            "username": "bruce",
            "password": "bruce",
        },
    )
    return r.json()["access_token"]


@pytest.fixture(scope="session")
def token():
    return get_keycloak_token()


@pytest.fixture(scope="session")
def auth_headers(token: str):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sp_configuration(monkeypatch, tmp_path) -> None:
    """Configure minimal environment variables to test Serviceplatformen integration."""
    tmp_file = tmp_path / "testfile"
    tmp_file.write_text("This is a certificate")
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("ENABLE_SP", "True")
    monkeypatch.setenv("SP_CERTIFICATE_PATH", str(tmp_file))
    yield
