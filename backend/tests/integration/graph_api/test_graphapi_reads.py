#!/usr/bin/env python3
# --------------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2021 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
import pytest
from hypothesis import given
from hypothesis import HealthCheck
from hypothesis import note
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis_graphql import strategies as gql_st
from more_itertools import all_equal

from mora.graphapi.main import get_schema
from mora.graphapi.shim import flatten_data
from tests.conftest import GQLResponse
from tests.util import _mox_testing_api
from tests.util import load_sample_structures


# --------------------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
async def sample_structures(testing_db):
    """Class scoped sample structure.

    We only do reads in this integration test, so there is no reason for us to
    load data before and db_reset after every function.
    """
    await load_sample_structures(minimal=False)
    yield
    _mox_testing_api("db-reset")


# --------------------------------------------------------------------------------------
# GraphAPI Reads integration tests
# --------------------------------------------------------------------------------------

SCHEMA = str(get_schema())
UUID_SEARCHABLE_FIELDS = [
    "addresses",
    "associations",
    "classes",
    "employees",
    "engagement_associations",
    "engagements",
    "facets",
    "itsystems",
    "itusers",
    "kles",
    "leaves",
    "managers",
    "org_units",
    "related_units",
    "roles",
]
FIELDS = UUID_SEARCHABLE_FIELDS + [
    "healths",
    "org",
    "version",
    # TODO: uncomment these and make sure tests run:
    # "configuration",
    # "files",
]


class TestGraphAPI:
    """Test the GraphAPI generated by Strawberry."""

    @settings(
        suppress_health_check=[
            HealthCheck.too_slow,
            HealthCheck.function_scoped_fixture,
        ],
        max_examples=10,  # These tests are slow and using hypothesis
        # for them is a bit much. Number of examples is fixed until we solve it.
    )
    @pytest.mark.parametrize("field", FIELDS)
    @given(data=st.data())
    def test_queries(self, data, field, graphapi_post_integration):
        """Test queries generated from the entire schema.

        This tests all manners of valid queries generated from the GraphAPI schema.
        We expect the status code to always be 200, and that data is available in the
        response, while errors are None.
        """
        query = data.draw(gql_st.query(SCHEMA, fields=[field]))
        note(f"Failing query:\n{query}")
        response: GQLResponse = graphapi_post_integration(query=query)
        assert response.status_code == 200
        assert response.data
        assert response.errors is None


class TestManagerInheritance:
    # Anders And is manager at humfak
    humfak = "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e"
    # There is no manager at filins
    filins = "85715fc7-925d-401b-822d-467eb4b163b6"

    query = """
        query TestQuery($uuids: [UUID!], $inherit: Boolean!)
        {
            org_units (uuids: $uuids) {
                objects {
                managers(inherit: $inherit) {
                        employee_uuid
                    }
                }
            }
        }
    """

    def test_manager_no_inheritance(self, graphapi_post_integration):
        """No inheritance - no manager for filins."""
        variables = {"uuids": [self.filins], "inherit": False}
        response: GQLResponse = graphapi_post_integration(
            query=self.query, variables=variables
        )
        assert response.data
        assert response.errors is None
        managers = flatten_data(response.data["org_units"])
        assert managers == [{"managers": []}]

    def test_manager_with_inheritance(self, graphapi_post_integration):
        """Inheritance - Anders And is manager of both humfak & filins."""
        variables = {"uuids": [self.humfak, self.filins], "inherit": True}
        response: GQLResponse = graphapi_post_integration(
            query=self.query, variables=variables
        )
        assert response.data
        assert response.errors is None
        managers = flatten_data(response.data["org_units"])
        assert all_equal(managers)


def test_regression_51523_1(graphapi_post_integration):
    query = """
        query TestQuery {
            org_units(uuids: ["deadbeef-dead-beef-0000-000000000000"]) {
                uuid
            }
        }
    """
    response: GQLResponse = graphapi_post_integration(query)

    assert response.errors is None
    assert response.data
    assert response.data["org_units"] == []


def test_regression_51523_2(graphapi_post_integration):
    query = """
        query TestQuery {
            org_units(uuids: ["deadbeef-dead-beef-0000-000000000000"]) {
                objects {
                    uuid
                }
            }
        }
    """
    response: GQLResponse = graphapi_post_integration(query)

    assert response.errors is None
    assert response.data
    assert response.data["org_units"] == []


@pytest.mark.parametrize("field", UUID_SEARCHABLE_FIELDS)
def test_regression_51523_generalised(graphapi_post_integration, field):
    query = f"""
        query TestQuery {{
            {field}(uuids: ["deadbeef-dead-beef-0000-000000000000"]) {{
                uuid
            }}
        }}
    """
    response: GQLResponse = graphapi_post_integration(query)

    assert response.errors is None
    assert response.data
    assert response.data[field] == []
