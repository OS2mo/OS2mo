#!/usr/bin/env python3
# --------------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2021 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
import pytest
from fastapi.testclient import TestClient
from hypothesis import given
from hypothesis_graphql import strategies as gql_st

from mora.graphapi.main import get_schema

# --------------------------------------------------------------------------------------
# Integration test of the entire GraphAPI schema
# --------------------------------------------------------------------------------------


@pytest.mark.usefixtures("lora_mock")
class TestGraphAPI:
    """Test the GraphAPI generated by Strawberry.

    These tests are more integration than unit tests: we use a mocked LoRa
    and a FastAPI test client, but otherwise the entire flow from API to dataloaders
    is tested as is.
    """

    @pytest.mark.skip(reason="Way too slow! We need a much smaller dataset.")
    @given(query=gql_st.query(str(get_schema())))
    def test_queries(self, query, graphapi_test: TestClient):
        """Test queries generated from the entire schema.

        This tests all manners of valid queries generated from the GraphAPI schema.
        We expect the status code to always be 200, and that data is available in the
        response, while errors are None.
        """
        response = graphapi_test().post("/graphql", json={"query": query})
        assert response.status_code == 200
        data, errors = response.json().get("data"), response.json().get("errors")
        assert data
        assert errors is None
