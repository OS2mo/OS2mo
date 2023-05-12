# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from unittest.mock import patch
from uuid import UUID
from uuid import uuid4

import pytest
from hypothesis import given
from hypothesis import HealthCheck
from hypothesis import settings as hypothesis_settings
from more_itertools import first
from more_itertools import one
from pydantic import parse_obj_as
from pytest import MonkeyPatch

import mora.lora as lora
from .strategies import graph_data_strat
from .strategies import graph_data_uuids_strat
from mora.graphapi.versions.latest import dataloaders
from oio_rest import db
from ramodels.mo.details import ITSystemRead
from tests.conftest import GQLResponse


@given(test_data=graph_data_strat(ITSystemRead))
def test_query_all(test_data, graphapi_post, patch_loader):
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
                    objects {
                        uuid
                        name
                        system_type
                        type
                        user_key
                        uuid
                    }
                }
            }
        """
        response: GQLResponse = graphapi_post(query)

    assert response.errors is None
    assert response.data
    assert response.data["itsystems"]["objects"] == test_data


@given(test_input=graph_data_uuids_strat(ITSystemRead))
def test_query_by_uuid(test_input, graphapi_post, patch_loader):
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
                        objects {
                            uuid
                        }
                    }
                }
            """
        response: GQLResponse = graphapi_post(query, {"uuids": test_uuids})

    assert response.errors is None
    assert response.data

    # Check UUID equivalence
    result_uuids = [
        itsys.get("uuid") for itsys in response.data["itsystems"]["objects"]
    ]
    assert set(result_uuids) == set(test_uuids)
    assert len(result_uuids) == len(set(test_uuids))


@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
def test_itsystem_create(graphapi_post) -> None:
    """Test that we can create new itsystems."""

    existing_itsystem_uuids = {
        UUID("0872fb72-926d-4c5c-a063-ff800b8ee697"),
        UUID("14466fb0-f9de-439c-a6c2-b3262c367da7"),
        UUID("59c135c9-2b15-41cc-97c8-b5dff7180beb"),
    }

    # Verify existing state
    query = """
        query ReadITSystems {
            itsystems {
                objects {
                    uuid
                    user_key
                    name
                }
            }
        }
    """
    response: GQLResponse = graphapi_post(query)
    assert response.errors is None
    assert response.data
    itsystem_map = {UUID(x["uuid"]): x for x in response.data["itsystems"]["objects"]}
    assert itsystem_map.keys() == existing_itsystem_uuids

    # Create new itsystem
    mutation = """
        mutation CreateITSystem($input: ITSystemCreateInput!) {
            itsystem_create(input: $input) {
                uuid
            }
        }
    """
    response: GQLResponse = graphapi_post(
        mutation, {"input": {"user_key": "my_user_key", "name": "my_name"}}
    )
    assert response.errors is None
    assert response.data
    new_uuid = UUID(response.data["itsystem_create"]["uuid"])

    # Verify modified state
    response: GQLResponse = graphapi_post(query)
    assert response.errors is None
    assert response.data
    itsystem_map = {UUID(x["uuid"]): x for x in response.data["itsystems"]["objects"]}
    assert itsystem_map.keys() == existing_itsystem_uuids | {new_uuid}

    # Verify new object
    itsystem = itsystem_map[new_uuid]
    assert itsystem["name"] == "my_name"
    assert itsystem["user_key"] == "my_user_key"


@hypothesis_settings(suppress_health_check=(HealthCheck.function_scoped_fixture,))
@given(uuid=..., user_key=..., name=...)
def test_itsystem_create_mocked(
    uuid: UUID,
    user_key: str,
    name: str,
    graphapi_post,
    mock_get_valid_organisations: UUID,
) -> None:
    """Test that create_or_import_object is called as expected."""
    mutation = """
        mutation CreateITSystem($input: ITSystemCreateInput!) {
            itsystem_create(input: $input) {
                uuid
            }
        }
    """
    with patch("oio_rest.db.create_or_import_object") as mock:
        mock.return_value = uuid

        response: GQLResponse = graphapi_post(
            mutation, {"input": {"user_key": user_key, "name": name}}
        )
        assert response.errors is None
        assert response.data
        new_uuid = UUID(response.data["itsystem_create"]["uuid"])
        assert new_uuid == uuid

        mock.assert_called_with(
            "itsystem",
            "",
            {
                "states": {
                    "itsystemgyldighed": [
                        {
                            "gyldighed": "Aktiv",
                            "virkning": {"from": "-infinity", "to": "infinity"},
                        }
                    ]
                },
                "attributes": {
                    "itsystemegenskaber": [
                        {
                            "brugervendtnoegle": user_key,
                            "virkning": {"from": "-infinity", "to": "infinity"},
                            "itsystemnavn": name,
                        }
                    ]
                },
                "relations": {
                    "tilknyttedeorganisationer": [
                        {
                            "uuid": str(mock_get_valid_organisations),
                            "virkning": {"from": "-infinity", "to": "infinity"},
                        }
                    ]
                },
            },
        )


@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
def test_itsystem_update(graphapi_post) -> None:
    """Test that we can update itsystems."""
    existing_itsystem_uuid = UUID("0872fb72-926d-4c5c-a063-ff800b8ee697")

    # Verify existing state
    query = """
        query ReadITSystems($uuids: [UUID!]) {
            itsystems(uuids: $uuids) {
                objects {
                    uuid
                    user_key
                    name
                }
            }
        }
    """
    response: GQLResponse = graphapi_post(query, {"uuids": str(existing_itsystem_uuid)})
    assert response.errors is None
    assert response.data
    itsystem = one(response.data["itsystems"]["objects"])
    assert itsystem["name"] == "Lokal Rammearkitektur"

    # Update new itsystem
    mutation = """
        mutation UpdateITSystem($input: ITSystemCreateInput!, $uuid: UUID!) {
            itsystem_update(input: $input, uuid: $uuid) {
                uuid
            }
        }
    """
    response: GQLResponse = graphapi_post(
        mutation,
        {
            "input": {"user_key": "my_user_key", "name": "my_name"},
            "uuid": str(existing_itsystem_uuid),
        },
    )
    assert response.errors is None
    assert response.data
    edit_uuid = UUID(response.data["itsystem_update"]["uuid"])
    assert edit_uuid == existing_itsystem_uuid

    # Verify modified state
    response: GQLResponse = graphapi_post(query, {"uuids": str(existing_itsystem_uuid)})
    assert response.errors is None
    assert response.data
    itsystem = one(response.data["itsystems"]["objects"])
    assert itsystem["name"] == "my_name"
    assert itsystem["user_key"] == "my_user_key"


@hypothesis_settings(suppress_health_check=(HealthCheck.function_scoped_fixture,))
@given(user_key=..., name=...)
def test_itsystem_update_mocked(
    user_key: str,
    name: str,
    graphapi_post,
    mock_get_valid_organisations: UUID,
) -> None:
    """Test that update_object is called as expected."""
    existing_itsystem_uuid = UUID("0872fb72-926d-4c5c-a063-ff800b8ee697")

    mutation = """
        mutation UpdateITSystem($input: ITSystemCreateInput!, $uuid: UUID!) {
            itsystem_update(input: $input, uuid: $uuid) {
                uuid
            }
        }
    """
    with (
        patch("oio_rest.db.update_object") as mock,
        patch("oio_rest.db.object_exists") as object_exists_mock,
        patch("oio_rest.db.get_life_cycle_code") as life_cycle_code_mock,
    ):
        life_cycle_code_mock.return_value = db.Livscyklus.PASSIVERET.value
        object_exists_mock.return_value = True
        mock.return_value = existing_itsystem_uuid

        response: GQLResponse = graphapi_post(
            mutation,
            {
                "input": {"user_key": user_key, "name": name},
                "uuid": str(existing_itsystem_uuid),
            },
        )
        assert response.errors is None
        assert response.data
        edit_uuid = UUID(response.data["itsystem_update"]["uuid"])
        assert edit_uuid == existing_itsystem_uuid

        mock.assert_called_with(
            "itsystem",
            "",
            {
                "states": {
                    "itsystemgyldighed": [
                        {
                            "gyldighed": "Aktiv",
                            "virkning": {"from": "-infinity", "to": "infinity"},
                        }
                    ]
                },
                "attributes": {
                    "itsystemegenskaber": [
                        {
                            "brugervendtnoegle": user_key,
                            "virkning": {"from": "-infinity", "to": "infinity"},
                            "itsystemnavn": name,
                        }
                    ]
                },
                "relations": {
                    "tilknyttedeorganisationer": [
                        {
                            "uuid": str(mock_get_valid_organisations),
                            "virkning": {"from": "-infinity", "to": "infinity"},
                        }
                    ]
                },
            },
            uuid=str(existing_itsystem_uuid),
            life_cycle_code="Importeret",
        )


@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
def test_itsystem_update_non_existent(graphapi_post) -> None:
    """Test that we cannot update non-existent itsystems."""
    mutation = """
        mutation UpdateITSystem($input: ITSystemCreateInput!, $uuid: UUID!) {
            itsystem_update(input: $input, uuid: $uuid) {
                uuid
            }
        }
    """
    response: GQLResponse = graphapi_post(
        mutation,
        {
            "input": {"user_key": "whatever", "name": "whatever"},
            "uuid": str(uuid4()),
        },
    )
    assert response.errors == [
        {
            "locations": [{"column": 13, "line": 3}],
            "message": "Cannot update a non-existent object",
            "path": ["itsystem_update"],
        }
    ]
    assert response.data is None


def test_itsystem_update_non_existent_mocked(
    graphapi_post,
    mock_get_valid_organisations: UUID,
) -> None:
    """Test that update_object is called as expected."""
    mutation = """
        mutation UpdateITSystem($input: ITSystemCreateInput!, $uuid: UUID!) {
            itsystem_update(input: $input, uuid: $uuid) {
                uuid
            }
        }
    """
    with (patch("oio_rest.db.object_exists") as object_exists_mock,):
        object_exists_mock.return_value = False

        response: GQLResponse = graphapi_post(
            mutation,
            {
                "input": {"user_key": "whatever", "name": "whatever"},
                "uuid": str(uuid4()),
            },
        )
        assert response.errors == [
            {
                "locations": [{"column": 13, "line": 3}],
                "message": "Cannot update a non-existent object",
                "path": ["itsystem_update"],
            }
        ]
        assert response.data is None


@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
def test_itsystem_delete(graphapi_post) -> None:
    """Test that we can delete an itsystem."""

    existing_itsystem_uuids = {
        UUID("0872fb72-926d-4c5c-a063-ff800b8ee697"),
        UUID("14466fb0-f9de-439c-a6c2-b3262c367da7"),
        UUID("59c135c9-2b15-41cc-97c8-b5dff7180beb"),
    }

    # Verify existing state
    query = """
        query ReadITSystems {
            itsystems {
                objects {
                    uuid
                    user_key
                    name
                }
            }
        }
    """
    response: GQLResponse = graphapi_post(query)
    assert response.errors is None
    assert response.data
    itsystem_map = {UUID(x["uuid"]): x for x in response.data["itsystems"]["objects"]}
    assert itsystem_map.keys() == existing_itsystem_uuids

    # Delete itsystem
    mutation = """
        mutation DeleteITSystem($uuid: UUID!) {
            itsystem_delete(uuid: $uuid) {
                uuid
            }
        }
    """
    response: GQLResponse = graphapi_post(
        mutation, {"uuid": str(first(existing_itsystem_uuids))}
    )
    assert response.errors is None
    assert response.data
    deleted_uuid = UUID(response.data["itsystem_delete"]["uuid"])

    # Verify modified state
    response: GQLResponse = graphapi_post(query)
    assert response.errors is None
    assert response.data
    itsystem_map = {UUID(x["uuid"]): x for x in response.data["itsystems"]["objects"]}
    assert itsystem_map.keys() == existing_itsystem_uuids - {deleted_uuid}


@given(uuid=...)
def test_itsystem_delete_mocked(uuid: UUID, graphapi_post) -> None:
    """Test that delete_object is called as expected."""
    mutation = """
        mutation DeleteITSystem($uuid: UUID!) {
            itsystem_delete(uuid: $uuid) {
                uuid
            }
        }
    """
    with patch("oio_rest.db.delete_object") as mock:
        mock.return_value = None

        response: GQLResponse = graphapi_post(mutation, {"uuid": str(uuid)})
        assert response.errors is None
        assert response.data
        deleted_uuid = UUID(response.data["itsystem_delete"]["uuid"])
        assert deleted_uuid == uuid

        mock.assert_called_with(
            "itsystem",
            {"states": {}, "attributes": {}, "relations": {}},
            "",
            str(uuid),
        )
