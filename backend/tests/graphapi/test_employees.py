# SPDX-FileCopyrightText: 2021- Magenta ApS
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
import datetime
from itertools import product
from unittest.mock import AsyncMock
from unittest.mock import patch
from uuid import uuid4

import mock
import pytest
from hypothesis import given
from hypothesis import strategies as st
from mock import patch
from mock.mock import AsyncMock
from parameterized import parameterized
from pydantic import ValidationError
from pytest import MonkeyPatch
from strawberry.types import ExecutionResult

import tests.cases
from .strategies import graph_data_strat
from .strategies import graph_data_uuids_strat
from mora import exceptions
from mora import mapping
from mora.graphapi.shim import flatten_data
from mora.graphapi.versions.latest import dataloaders
from mora.graphapi.versions.latest.models import EmployeeUpdate
from mora.graphapi.versions.latest.version import LatestGraphQLSchema
from mora.service.util import handle_gql_error
from mora.util import NEGATIVE_INFINITY
from ramodels.mo import EmployeeRead
from tests.conftest import GQLResponse

# Helpers
now_beginning = datetime.datetime.now().replace(
    hour=0, minute=0, second=0, microsecond=0
)

# --------------------------------------------------------------------------------------
# Query tests
# --------------------------------------------------------------------------------------


class TestEmployeesQuery:
    """Class collecting employees query tests.

    Data loaders are mocked to return specific values, generated via
    Hypothesis.
    MonkeyPatch.context is used as a context manager to achieve this,
    because mocks are *not* reset between invocations of Hypothesis examples.
    """

    @given(test_data=graph_data_strat(EmployeeRead))
    def test_query_all(self, test_data, graphapi_post, patch_loader):
        """Test that we can query all our employees."""
        # Patch dataloader
        with MonkeyPatch.context() as patch:
            patch.setattr(dataloaders, "search_role_type", patch_loader(test_data))
            query = """
                query {
                    employees {
                        uuid
                        objects {
                            givenname
                            surname
                            nickname_givenname
                            nickname_surname
                            cpr_no
                            seniority
                            user_key
                            type
                            uuid
                            validity {from to}
                        }
                    }
                }
            """
            response: GQLResponse = graphapi_post(query)

        assert response.errors is None
        assert response.data
        assert flatten_data(response.data["employees"]) == test_data

    @given(test_input=graph_data_uuids_strat(EmployeeRead))
    def test_query_by_uuid(self, test_input, graphapi_post, patch_loader):
        """Test that we can query employees by UUID."""
        test_data, test_uuids = test_input

        # Patch dataloader
        with MonkeyPatch.context() as patch:
            patch.setattr(dataloaders, "get_role_type_by_uuid", patch_loader(test_data))
            query = """
                    query TestQuery($uuids: [UUID!]) {
                        employees(uuids: $uuids) {
                            uuid
                        }
                    }
                """
            response: GQLResponse = graphapi_post(query, {"uuids": test_uuids})

        assert response.errors is None
        assert response.data

        # Check UUID equivalence
        result_uuids = [empl.get("uuid") for empl in response.data["employees"]]
        assert set(result_uuids) == set(test_uuids)
        assert len(result_uuids) == len(set(test_uuids))


# --------------------------------------------------------------------------------------
# Create tests
# --------------------------------------------------------------------------------------


class TestEmployeeCreate(tests.cases.AsyncLoRATestCase):
    @parameterized.expand(
        [
            (
                "Laura Christensen",
                "0103882148",
                "3b866d97-0b1f-48e0-8078-686d96f430b3",
                True,
            ),
            (
                "Laura Christensen",
                "0000000000",
                "00000000-0000-0000-0000-000000000000",
                True,
            ),
            (None, "0103882148", "3b866d97-0b1f-48e0-8078-686d96f430b3", False),
            (None, "0103882148", None, False),
            (None, None, "3b866d97-0b1f-48e0-8078-686d96f430b3", False),
            (None, None, None, False),
            ("Laura Christensen", None, "3b866d97-0b1f-48e0-8078-686d96f430b3", False),
            ("Laura Christensen", "0103882148", None, False),
        ]
    )
    async def test_mutator(
        self, given_name, given_cprno, given_org_uuid, expected_result
    ):
        with patch("mora.service.handlers.RequestHandler.construct") as mock_construct:
            mock_new_uuid = str(uuid4())
            mock_submit = AsyncMock(return_value=mock_new_uuid)
            mock_construct.return_value = AsyncMock(submit=mock_submit)

            # GraphQL
            mutation_func = "employee_create"
            query = (
                f"mutation($name: String!, $cpr_no: String!, $org: OrganizationInput!) {{"
                f"{mutation_func}(input: {{name: $name, cpr_no: $cpr_no, org: $org}}) "
                f"{{ uuid }}"
                f"}}"
            )

            var_values = {}
            if given_name:
                var_values["name"] = given_name

            if given_cprno:
                var_values["cpr_no"] = given_cprno

            if given_org_uuid:
                var_values["org"] = {mapping.UUID: given_org_uuid}

            response = await LatestGraphQLSchema.get().execute(
                query, variable_values=var_values
            )

            # Asserts
            if expected_result:
                mock_construct.assert_called()
                mock_submit.assert_called()

                self.assertEqual(
                    response.data.get(mutation_func, {}).get("uuid", None),
                    mock_new_uuid,
                )
            else:
                mock_construct.assert_not_called()
                mock_submit.assert_not_called()

    @parameterized.expand(
        [
            # Empty values
            (
                "Laura Christensen",
                "0103882148",
                "3b866d97-0b1f-48e0-8078-686d96f430b3",
                True,
            ),
            ("Laura Christensen", "", "3b866d97-0b1f-48e0-8078-686d96f430b3", False),
            ("Laura Christensen", "0103882148", "", False),
            ("Laura Christensen", "", "", False),
            ("", "0103882148", "3b866d97-0b1f-48e0-8078-686d96f430b3", False),
            ("", "", "", False),
            # Formats
            (
                "Laura Christensen",
                "0000000000",
                "3b866d97-0b1f-48e0-8078-686d96f430b3",
                True,
            ),
            (
                "Laura Christensen",
                "0103882148",
                "00000000-0000-0000-0000-000000000000",
                True,
            ),
            ("Laura", "0103882148", "3b866d97-0b1f-48e0-8078-686d96f430b3", True),
        ]
    )
    async def test_pydantic_dataclass(
        self, given_name, given_cprno, given_org_uuid, expected_result
    ):
        with patch(
            "mora.graphapi.versions.latest.mutators.employee_create"
        ) as mock_employee_create:
            mutation_func = "employee_create"
            query = (
                f"mutation($name: String!, $cpr_no: String!, $org: OrganizationInput!) {{"
                f"{mutation_func}(input: {{name: $name, cpr_no: $cpr_no, org: $org}}) "
                f"{{ uuid }}"
                f"}}"
            )

            var_values = {}
            if given_name:
                var_values["name"] = given_name

            if given_cprno:
                var_values["cpr_no"] = given_cprno

            if given_org_uuid:
                var_values["org"] = {mapping.UUID: given_org_uuid}

            _ = await LatestGraphQLSchema.get().execute(
                query, variable_values=var_values
            )

            # Asserts
            if expected_result:
                mock_employee_create.assert_called()
            else:
                mock_employee_create.assert_not_called()

    @parameterized.expand(
        [
            (
                "Laura Christensen",
                "0000000000",
                "3b866d97-0b1f-48e0-8078-686d96f430b3",
                exceptions.ErrorCodes.V_CPR_NOT_VALID.name,
            ),
            (
                "Laura Christensen",
                "0101701234",
                "00000000-0000-0000-0000-000000000000",
                exceptions.ErrorCodes.E_ORG_UNCONFIGURED.name,
            ),
            (
                "",
                "0000000000",
                "3b866d97-0b1f-48e0-8078-686d96f430b3",
                exceptions.ErrorCodes.V_MISSING_REQUIRED_VALUE.name,
            ),
            (
                "",
                "",
                "3b866d97-0b1f-48e0-8078-686d96f430b3",
                exceptions.ErrorCodes.V_MISSING_REQUIRED_VALUE.name,
            ),
        ]
    )
    async def test_fails(
        self, given_name, given_cprno, given_org_uuid, expected_result
    ):
        with patch("mora.service.org.get_valid_organisations") as mock_get_valid_orgs:
            mock_get_valid_orgs.return_value = (
                [{mapping.UUID: given_org_uuid}]
                if given_org_uuid != "00000000-0000-0000-0000-000000000000"
                else []
            )

            with patch("mora.lora.Scope.create") as mock_create:
                mock_create.side_effect = lambda *args: args[-1]

                result = None
                try:
                    query = (
                        "mutation($name: String!, $cpr_no: String!, $org: OrganizationInput!) {"
                        "employee_create(input: {name: $name, cpr_no: $cpr_no, org: $org}) "
                        "{ uuid }"
                        "}"
                    )
                    response = await LatestGraphQLSchema.get().execute(
                        query,
                        variable_values={
                            "name": given_name,
                            "cpr_no": given_cprno,
                            "org": {mapping.UUID: given_org_uuid},
                        },
                    )
                    handle_gql_error(response)
                except Exception as e:
                    result = (
                        e.key.name
                        if hasattr(e, "key") and hasattr(e.key, "name")
                        else result
                    )

                # Assert
                mock_create.assert_not_called()
                assert result == expected_result


class TestEmployeeTerminate(tests.cases.AsyncLoRATestCase):
    @parameterized.expand(
        [
            (
                "3b866d97-0b1f-48e0-8078-686d96f430b3",
                NEGATIVE_INFINITY,
                now_beginning,
                True,
            ),
            (
                "3b866d97-0b1f-48e0-8078-686d96f430b3",
                now_beginning,
                now_beginning,
                True,
            ),
            ("3b866d97-0b1f-48e0-8078-686d96f430b3", None, now_beginning, True),
            ("3b866d97-0b1f-48e0-8078-686d96f430b3", now_beginning, None, False),
            ("3b866d97-0b1f-48e0-8078-686d96f430b3", None, None, False),
            (None, now_beginning, None, False),
            (None, None, now_beginning, False),
            (None, None, None, False),
        ]
    )
    async def test_mutator(
        self, given_uuid, given_from_date, given_to_date, expected_result
    ):
        with patch("mora.lora.Scope.get_all") as mock_lora_get_all, patch(
            "mora.service.handlers.get_handler_for_function"
        ) as mock_get_handler_for_function, patch(
            "mora.common.add_history_entry"
        ) as mock_add_history_entry:
            # Mocking
            mock_lora_get_all.return_value = {
                given_uuid: {
                    "tilstande": {
                        "organisationenhedgyldighed": [
                            {"virkning": {mapping.FROM: NEGATIVE_INFINITY}}
                        ]
                    }
                }
            }.items()

            mock_request_handler_submit = AsyncMock()
            mock_request_handler_construct = AsyncMock(
                return_value=AsyncMock(submit=mock_request_handler_submit)
            )

            mock_get_handler_for_function.return_value = AsyncMock(
                construct=mock_request_handler_construct,
            )

            # Invoke GraphQL
            mutation_func = "employee_terminate"
            query, var_values = self._get_graphql_query_and_vars(
                mutation_func,
                uuid=given_uuid,
                from_date=given_from_date,
                to_date=given_to_date,
            )

            response = await LatestGraphQLSchema.get().execute(
                query, variable_values=var_values
            )

            # Asserts
            if expected_result:
                mock_lora_get_all.assert_called()
                mock_get_handler_for_function.assert_called()
                mock_add_history_entry.assert_called()

                mock_request_handler_construct.assert_called()
                mock_request_handler_submit.assert_called()

                self.assertEqual(
                    response.data.get(mutation_func, {}).get("uuid", None),
                    given_uuid,
                )
            else:
                mock_lora_get_all.assert_not_called()
                mock_get_handler_for_function.assert_not_called()
                mock_add_history_entry.assert_not_called()

                mock_request_handler_construct.assert_not_called()
                mock_request_handler_submit.assert_not_called()

    @parameterized.expand(
        [
            (
                "3b866d97-0b1f-48e0-8078-686d96f430b3",
                NEGATIVE_INFINITY,
                now_beginning,
                True,
            ),
            (
                "3b866d97-0b1f-48e0-8078-686d96f430b3",
                now_beginning,
                now_beginning,
                True,
            ),
            ("3b866d97-0b1f-48e0-8078-686d96f430b3", "", now_beginning, True),
            ("3b866d97-0b1f-48e0-8078-686d96f430b3", "", "", False),
            ("", now_beginning, "", False),
            ("", "", now_beginning, False),
            ("", NEGATIVE_INFINITY, now_beginning, False),
            ("", "", "", False),
        ]
    )
    async def test_pydantic_dataclass(
        self, given_uuid, given_from_date, given_to_date, expected_result
    ):
        with patch(
            "mora.graphapi.versions.latest.mutators.terminate_employee"
        ) as mock_terminate_employee:
            # Invoke GraphQL
            mutation_func = "employee_terminate"
            query, var_values = self._get_graphql_query_and_vars(
                mutation_func,
                uuid=given_uuid,
                from_date=given_from_date,
                to_date=given_to_date,
            )

            _ = await LatestGraphQLSchema.get().execute(
                query, variable_values=var_values
            )

            if expected_result:
                mock_terminate_employee.assert_called()
            else:
                mock_terminate_employee.assert_not_called()

    @staticmethod
    def _get_graphql_query_and_vars(
        mutation_func: str = "employee_terminate", **kwargs
    ):
        query = (
            f"mutation($uuid: UUID!, $from: DateTime, $to: DateTime!, "
            f"$triggerless: Boolean) {{"
            f"{mutation_func}(input: {{uuid: $uuid, from: $from, to: $to, "
            f"triggerless: $triggerless}}) "
            f"{{ uuid }}"
            f"}}"
        )

        var_values = {}
        uuid = kwargs.get("uuid", None)
        if uuid:
            var_values["uuid"] = uuid

        from_date = kwargs.get("from_date", None)
        if from_date:
            var_values["from"] = from_date.isoformat()

        to_date = kwargs.get("to_date", None)
        if to_date:
            var_values["to"] = to_date.isoformat()

        return query, var_values


@given(
    st.uuids(),
    # from & to
    st.tuples(st.datetimes(), st.datetimes() | st.none()).filter(
        lambda dts: dts[0] <= dts[1] if dts[0] and dts[1] else True
    ),
    # name, given_name, sur_name
    st.tuples(
        st.text() | st.none(),
        st.text() | st.none(),
        st.text() | st.none(),
    ).filter(lambda names: not (names[0] and (names[1] or names[2]))),
    # nickname, nickname_givenname, nickname_surname,
    st.tuples(
        st.text() | st.none(),
        st.text() | st.none(),
        st.text() | st.none(),
    ).filter(lambda names: not (names[0] and (names[1] or names[2]))),
    # given_seniority
    st.text() | st.none(),
    # cpr_no
    st.from_regex(r"^\d{10}$") | st.none(),
)
async def test_update(
    given_uuid,
    given_validity_dts,
    given_name_tuple,
    given_nickname_tuple,
    given_seniority,
    given_cpr_no,
):
    # Unpack tuples
    given_uuid_str = str(given_uuid)
    given_validity_from, given_validity_to = given_validity_dts
    given_name, given_givenname, given_surname = given_name_tuple
    (
        given_nickname,
        given_nickname_givenname,
        given_nickname_surname,
    ) = given_nickname_tuple

    # Create variable values for GraphQL (init with required fields)
    var_values = {
        "uuid": given_uuid_str,
        "from": given_validity_from.date().isoformat(),
    }
    pydantic_values = {**var_values}

    if given_validity_to:
        var_values["to"] = given_validity_to.date().isoformat()
        pydantic_values["to"] = given_validity_to.date().isoformat()

    _set_gql_var("name", given_name, var_values, pydantic_values)
    _set_gql_var("given_name", given_givenname, var_values, pydantic_values)
    _set_gql_var("sur_name", given_surname, var_values, pydantic_values)
    _set_gql_var("nickname", given_nickname, var_values, pydantic_values)
    _set_gql_var(
        "nickname_given_name", given_nickname_givenname, var_values, pydantic_values
    )
    _set_gql_var(
        "nickname_sur_name", given_nickname_surname, var_values, pydantic_values
    )
    _set_gql_var("seniority", given_seniority, var_values, pydantic_values)
    _set_gql_var("cpr_no", given_cpr_no, var_values, pydantic_values)

    # Create pydantic model manually, to determine how the test should be asserted.
    # If we are not able to create it, the response from GraphQL should fail equally
    expected_exception = None
    try:
        _ = EmployeeUpdate(**pydantic_values)
    except Exception as e:
        expected_exception = e

    # GraphQL
    mutation_func = "employee_update"
    query = (
        "mutation($uuid: UUID!, $from: DateTime!, $to: DateTime, $name: String, "
        "$givenName: String, $surName: String, $nickname: String, "
        "$nicknameGivenName: String, $nicknameSurName: String, $seniority: String, "
        "$cprNo: String) {"
        f"{mutation_func}(input: {{uuid: $uuid, from: $from, to: $to, name: $name, "
        "given_name: $givenName, sur_name: $surName, nickname: $nickname, "
        "nickname_given_name: $nicknameGivenName, "
        "nickname_sur_name: $nicknameSurName, seniority: $seniority, cpr_no: $cprNo})"
        "}"
    )

    with mock.patch(
        "mora.graphapi.versions.latest.mutators.employee_update"
    ) as mock_employee_update:
        mock_employee_update.return_value = given_uuid_str
        response = await LatestGraphQLSchema.get().execute(
            query, variable_values=var_values
        )

        if expected_exception:
            response_exception = None
            if isinstance(response.errors, list) and response.errors[0]:
                response_exception = response.errors[0].original_error

            with pytest.raises(ValidationError) as e_info:
                raise response_exception

            assert e_info.type is ValidationError
        else:
            updated_employee_uuid = (
                response.data.get(mutation_func)
                if isinstance(response, ExecutionResult)
                and isinstance(response.data, dict)
                else None
            )
            assert updated_employee_uuid == given_uuid_str


def _set_gql_var(field_name, value, gql_values, pydantic_values):
    """Helper method to assign variables to dicts used by GraphQL and pydantic."""

    if not value:
        return

    components = field_name.split("_")
    value_camel_case = components[0] + "".join(x.title() for x in components[1:])

    gql_values[value_camel_case] = value
    pydantic_values[field_name] = value
