# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
import uuid
from datetime import datetime
from unittest.mock import ANY
from unittest.mock import AsyncMock
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from httpx import Response

from mora.graphapi.versions.v14.version import GraphQLVersion as GraphQLVersionV14
from mora.lora import AutocompleteScope
from mora.lora import Connector
from mora.service.autocomplete.orgunits import decorate_orgunit_search_result
from mora.service.autocomplete.orgunits import search_orgunits


@pytest.mark.parametrize(
    "path,expected_result",
    [
        ("bruger", []),
        ("organisationsenhed", []),
    ],
)
async def test_autocomplete(respx_mock, path: str, expected_result: list) -> None:
    respx_mock.get(f"http://localhost/lora/autocomplete/{path}?phrase=phrase").mock(
        return_value=Response(200, json={"results": []})
    )
    connector = Connector()
    scope = AutocompleteScope(connector, path)
    response = await scope.fetch("phrase")
    assert "items" in response
    result = response["items"]
    assert result == expected_result


@patch("mora.service.autocomplete.get_results")
@patch("mora.service.orgunit.config.get_settings")
def test_v2_legacy_logic(mock_get_settings, mock_get_results, service_client):
    class_uuids = [
        uuid.UUID("e8ea1a09-d3d4-4203-bfe9-d9a213371337"),
    ]

    mock_get_settings.return_value = MagicMock(
        confdb_autocomplete_v2_use_legacy=True,
        confdb_autocomplete_attrs_orgunit=class_uuids,
    )
    mock_get_results.return_value = {"items": []}

    at = datetime.now().date()
    query = "f494ad89-039d-478e-91f2-a63566554666"
    response = service_client.request(
        "GET", f"/service/ou/autocomplete/?query={query}&at={at.isoformat()}"
    )

    assert response.status_code == 200
    mock_get_results.assert_called()
    mock_get_results.assert_called_with(ANY, class_uuids, query)


@patch("mora.service.autocomplete.orgunits.execute_graphql", new_callable=AsyncMock)
async def test_v2_decorate_orgunits(mock_execute_graphql):
    test_data = {
        "uuid": "08eaf849-e9f9-53e0-b6b9-3cd45763ecbb",
        "name": "Viuf skole",
        "user_key": "Viuf skole",
        "validity": {"from": "1960-01-01T00:00:00+01:00", "to": None},
        "ancestors_validity": [
            {"name": "Skoler og børnehaver"},
            {"name": "Skole og Børn"},
            {"name": "Kolding Kommune"},
        ],
    }

    expected_result = [
        {
            "uuid": uuid.UUID(test_data["uuid"]),
            "name": test_data["name"],
            "path": [
                # [::-1] reverses the list
                ancestor["name"]
                for ancestor in test_data["ancestors_validity"][::-1]
            ]
            + [test_data["name"]],
            "attrs": [],
            "validity": test_data["validity"],
        }
    ]

    mock_execute_graphql.return_value = MagicMock(
        data={
            "org_units": {
                "objects": [
                    {
                        "uuid": test_data["uuid"],
                        "current": test_data,
                        "objects": [test_data],
                    }
                ]
            }
        },
        errors=None,
    )

    # Invoke
    now = datetime.now()
    result = await decorate_orgunit_search_result(
        settings=MagicMock(confdb_autocomplete_attrs_orgunit=None),
        search_results=[uuid.UUID(test_data["uuid"])],
        at=now.date(),
    )

    # Asserts
    mock_execute_graphql.assert_called_with(
        ANY,
        graphql_version=GraphQLVersionV14,
        variable_values={
            "uuids": [test_data["uuid"]],
            "from_date": now.date().isoformat(),
        },
    )

    assert result == expected_result


@patch("mora.service.autocomplete.orgunits.execute_graphql", new_callable=AsyncMock)
async def test_v2_decorate_orgunits_attrs(mock_execute_graphql):
    test_data = {
        "uuid": "08eaf849-e9f9-53e0-b6b9-3cd45763ecbb",
        "name": "Viuf skole",
        "user_key": "Viuf skole",
        "validity": {"from": "1960-01-01T00:00:00+01:00", "to": None},
        "ancestors_validity": [
            {"name": "Skoler og børnehaver"},
            {"name": "Skole og Børn"},
            {"name": "Kolding Kommune"},
        ],
        "addresses_validity": [
            {
                "uuid": "279a900a-a1a6-4c93-9c58-4f7d31108cdd",
                "name": "Viuf_skole@kolding.dk",
                "address_type": {
                    "uuid": "61c22b75-01b0-4e83-954c-9cf0c8dc79fe",
                    "name": "Email",
                },
            },
            {
                "uuid": "b756c0c9-75b7-4ed3-a731-b66946b09437",
                "name": "Næsbyvej 26, 6000 Kolding",
                "address_type": {
                    "uuid": "5260d4aa-e33b-48f7-ae3e-6074262cbdcf",
                    "name": "Postadresse",
                },
            },
        ],
        "itusers_validity": [
            {
                "uuid": "397c3967-fb29-425a-88a5-dac2c804cbab",
                "user_key": "viuf-skole-test-ad",
                "itsystem": {
                    "uuid": "a1608e69-c422-404f-a6cc-b873c50af111",
                    "user_key": "Active Directory",
                    "name": "Active Directory",
                },
            }
        ],
    }

    # Configure expected result from test data
    expected_attrs = []
    for addr in test_data["addresses_validity"]:
        expected_attrs.append(
            {
                "uuid": uuid.UUID(addr["uuid"]),
                "value": addr["name"],
                "title": addr["address_type"]["name"],
            }
        )

    for ituser in test_data["itusers_validity"]:
        expected_attrs.append(
            {
                "uuid": uuid.UUID(ituser["uuid"]),
                "value": ituser["user_key"],
                "title": ituser["itsystem"]["name"],
            }
        )

    expected_result = [
        {
            "uuid": uuid.UUID(test_data["uuid"]),
            "name": test_data["name"],
            "path": [
                # [::-1] reverses the list
                ancestor["name"]
                for ancestor in test_data["ancestors_validity"][::-1]
            ]
            + [test_data["name"]],
            "attrs": expected_attrs,
            "validity": test_data["validity"],
        }
    ]

    # Mock GraphQL response & Invoke
    mock_execute_graphql.return_value = MagicMock(
        data={
            "org_units": {
                "objects": [
                    {
                        "uuid": test_data["uuid"],
                        "current": test_data,
                        "objects": [test_data],
                    }
                ]
            }
        },
        errors=None,
    )

    now = datetime.now()
    result = await decorate_orgunit_search_result(
        settings=MagicMock(
            confdb_autocomplete_attrs_orgunit=[
                uuid.UUID(test_data["addresses_validity"][0]["address_type"]["uuid"]),
                uuid.UUID(test_data["addresses_validity"][1]["address_type"]["uuid"]),
                uuid.UUID(test_data["itusers_validity"][0]["itsystem"]["uuid"]),
            ]
        ),
        search_results=[uuid.UUID(test_data["uuid"])],
        at=now.date(),
    )

    # Asserts
    mock_execute_graphql.assert_called_with(
        ANY,
        graphql_version=GraphQLVersionV14,
        variable_values={
            "uuids": [test_data["uuid"]],
            "from_date": now.date().isoformat(),
        },
    )

    assert result == expected_result


@patch("mora.service.autocomplete.orgunits._sqlalchemy_generate_query")
async def test_v2_search_orgunits(mock_sqlalchemy_generate_query):
    """Test that search_orgunits() returns the expected result

    NOTE: The unit test does not patch out read_sqlalchemy_result(), but
    instead mocks the sqlalchemy result.
    """

    search_query = "Samfundsvidenskabelige"
    expected = [uuid.UUID("b688513d-11f7-4efc-b679-ab082a2055d0")]

    # Mocking
    mock_sqlalchemy_generate_query.return_value = "some-verification-return"

    session_mock = MagicMock()
    session_mock.__aenter__.return_value = session_mock
    session_mock.__aexit__.return_value = None
    session_mock.begin.return_value.__aenter__.return_value = None
    session_mock.begin.return_value.__aexit__.return_value = None

    # NOTE: 1000 is the default chunk size of read_sqlalchemy_result()
    sqlalchemy_result_chunck_size = 1000
    sqlalchemy_fetchmany_rows_mocked = [MagicMock(uuid=uuid) for uuid in expected]
    sqlalchemy_fetchmany_mock_return = [
        sqlalchemy_fetchmany_rows_mocked[i : i + sqlalchemy_result_chunck_size]
        for i in range(
            0, len(sqlalchemy_fetchmany_rows_mocked), sqlalchemy_result_chunck_size
        )
    ]
    sqlalchemy_fetchmany_mock_return.append([])

    session_mock.execute = AsyncMock(
        return_value=MagicMock(  # sqlalchemy result
            fetchmany=MagicMock(  # sqlalchemy rows
                side_effect=sqlalchemy_fetchmany_mock_return,
            )
        )
    )

    # Invoke search_orgunits with mocked sessionmaker
    result = await search_orgunits(MagicMock(return_value=session_mock), search_query)

    # Asserts
    mock_sqlalchemy_generate_query.assert_called_with(search_query, ANY)
    session_mock.execute.assert_called_with(
        mock_sqlalchemy_generate_query.return_value, {}
    )
    assert result == expected
