# SPDX-FileCopyrightText: 2021- Magenta ApS
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
from hypothesis import given
from pydantic import parse_obj_as
from pytest import MonkeyPatch
from ramodels.mo.details import ITSystemRead

import mora.graphapi.dataloaders as dataloaders
import mora.lora as lora
from .strategies import graph_data_strat
from .strategies import graph_data_uuids_strat
from .util import flatten_data

# --------------------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------------------


class TestITSystemsQuery:
    """Class collecting ITSystems query tests.

    Data loaders are mocked to return specific values, generated via
    Hypothesis.
    MonkeyPatch.context is used as a context manager to achieve this,
    because mocks are *not* reset between invocations of Hypothesis examples.
    """

    @given(test_data=graph_data_strat(ITSystemRead))
    def test_query_all(self, test_data, graphapi_test, patch_loader):
        """Test that we can query all attributes of the ITSystem data model."""
        # Patch dataloader
        with MonkeyPatch.context() as patch:
            # Our IT system dataloaders are ~* special *~
            # We need to intercept the connector too
            patch.setattr(lora.Scope, "get_all", patch_loader({}))
            patch.setattr(
                dataloaders,
                "lora_itsystem_to_mo_itsystem",
                lambda *args, **kwargs: parse_obj_as(list[ITSystemRead], test_data),
            )
            query = """
                query {
                    itsystems {
                        uuid
                        objects {
                            name
                            system_type
                            type
                            user_key
                            uuid
                        }
                    }
                }
            """
            response = graphapi_test.post("/graphql", json={"query": query})

        data, errors = response.json().get("data"), response.json().get("errors")
        assert errors is None
        assert data is not None
        assert flatten_data(data["itsystems"]) == test_data

    @given(test_input=graph_data_uuids_strat(ITSystemRead))
    def test_query_by_uuid(self, test_input, graphapi_test, patch_loader):
        """Test that we can query ITSystems by UUID."""
        test_data, test_uuids = test_input

        # Patch dataloader
        with MonkeyPatch.context() as patch:
            # Our facet dataloaders are ~* special *~
            # We need to intercept the connector too
            patch.setattr(lora.Scope, "get_all_by_uuid", patch_loader({}))
            patch.setattr(
                dataloaders,
                "lora_itsystem_to_mo_itsystem",
                lambda *args, **kwargs: parse_obj_as(list[ITSystemRead], test_data),
            )
            query = """
                    query TestQuery($uuids: [UUID!]) {
                        itsystems(uuids: $uuids) {
                            uuid
                        }
                    }
                """
            response = graphapi_test.post(
                "/graphql", json={"query": query, "variables": {"uuids": test_uuids}}
            )

        data, errors = response.json().get("data"), response.json().get("errors")
        assert errors is None
        assert data is not None

        # Check UUID equivalence
        result_uuids = [itsys.get("uuid") for itsys in data["itsystems"]]
        assert set(result_uuids) == set(test_uuids)
        assert len(result_uuids) == len(set(test_uuids))
