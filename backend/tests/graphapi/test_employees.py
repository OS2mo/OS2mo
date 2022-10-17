# SPDX-FileCopyrightText: 2021- Magenta ApS
# SPDX-License-Identifier: MPL-2.0
import datetime
from unittest.mock import AsyncMock
from unittest.mock import patch
from uuid import UUID
from uuid import uuid4

import pytest
from fastapi.encoders import jsonable_encoder
from hypothesis import given
from hypothesis import strategies as st
from hypothesis.strategies import characters
from more_itertools import one
from parameterized import parameterized
from pydantic import ValidationError
from pytest import MonkeyPatch

import tests.cases
from .strategies import graph_data_strat
from .strategies import graph_data_uuids_strat
from mora import lora
from mora import mapping
from mora.graphapi.shim import execute_graphql
from mora.graphapi.shim import flatten_data
from mora.graphapi.versions.latest import dataloaders
from mora.graphapi.versions.latest.models import EmployeeCreate
from mora.graphapi.versions.latest.models import EmployeeUpdate
from mora.graphapi.versions.latest.types import EmployeeType
from mora.graphapi.versions.latest.types import EmployeeUpdateResponseType
from mora.util import NEGATIVE_INFINITY
from ramodels.mo import EmployeeRead
from tests.conftest import GQLResponse


# Helpers
# from ..util import sample_structures_minimal_decorator, foo

now_beginning = datetime.datetime.now().replace(
    hour=0, minute=0, second=0, microsecond=0
)


@given(test_data=graph_data_strat(EmployeeRead))
def test_query_all(test_data, graphapi_post, patch_loader):
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
def test_query_by_uuid(test_input, graphapi_post, patch_loader):
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
    @pytest.mark.slow
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

            response = await execute_graphql(query, variable_values=var_values)

            # Asserts
            if expected_result:
                mock_lora_get_all.assert_called()
                mock_get_handler_for_function.assert_called()
                mock_add_history_entry.assert_called()

                mock_request_handler_construct.assert_called()
                mock_request_handler_submit.assert_called()

                assert (
                    response.data.get(mutation_func, {}).get("uuid", None) == given_uuid
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

            _ = await execute_graphql(query, variable_values=var_values)

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
        uuid = kwargs.get("uuid")
        if uuid:
            var_values["uuid"] = uuid

        from_date = kwargs.get("from_date")
        if from_date:
            var_values["from"] = from_date.isoformat()

        to_date = kwargs.get("to_date")
        if to_date:
            var_values["to"] = to_date.isoformat()

        return query, var_values


@given(test_data=...)
@patch("mora.graphapi.versions.latest.mutators.employee_create", new_callable=AsyncMock)
async def test_create_employee(
    create_employee: AsyncMock, test_data: EmployeeCreate
) -> None:
    """Test that pydantic jsons are passed through to employee_create."""

    mutate_query = """
        mutation CreateOrgUnit($input: EmployeeCreateInput!) {
            employee_create(input: $input) {
                uuid
            }
        }
    """
    created_uuid = uuid4()
    create_employee.return_value = EmployeeType(uuid=created_uuid)

    payload = jsonable_encoder(test_data)
    response = await execute_graphql(
        query=mutate_query, variable_values={"input": payload}
    )
    assert response.errors is None
    assert response.data == {"employee_create": {"uuid": str(created_uuid)}}

    create_employee.assert_called_with(test_data)


@st.composite
def valid_cprs(draw) -> str:
    # TODO: Add minimum and maximum birthyears as parameters
    valid_date = draw(
        st.dates(
            min_value=datetime.date(1970, 1, 1),  # Should really start at 1857
            max_value=datetime.date(2057, 1, 1),
        )
    )
    if valid_date.year < 1900:
        # TODO: Add mixed region 5000->9000
        code = draw(st.integers(min_value=5000, max_value=9000))
    elif valid_date.year < 2000:
        # TODO: Add mixed regions 4000->5000, 5000->9000 and 9000+
        code = draw(st.integers(min_value=0, max_value=4000))
    else:
        # TODO: Add mixed regions 4000->5000 and 9000+
        code = draw(st.integers(min_value=9000, max_value=9999))
    valid_code = str(code).zfill(4)
    cpr_number = valid_date.strftime("%d%m%y") + valid_code
    return cpr_number


@patch(
    "mora.service.employee.does_employee_with_cpr_already_exist", new_callable=AsyncMock
)
@given(
    test_data=st.builds(
        EmployeeCreate,
        givenname=st.text(
            alphabet=st.characters(whitelist_categories=("L",)), min_size=1
        ),
        surname=st.text(
            alphabet=st.characters(whitelist_categories=("L",)), min_size=1
        ),
        cpr_number=st.none() | valid_cprs(),
    )
)
@pytest.mark.slow
@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
async def test_create_employee_integration_test(
    does_employee_with_cpr_already_exist: AsyncMock,
    test_data: EmployeeCreate,
    graphapi_post,
) -> None:
    """Test that employees can be created in LoRa via GraphQL."""

    does_employee_with_cpr_already_exist.return_value = None

    mutate_query = """
        mutation CreateEmployee($input: EmployeeCreateInput!) {
            employee_create(input: $input) {
                uuid
            }
        }
    """
    response: GQLResponse = graphapi_post(
        mutate_query, {"input": jsonable_encoder(test_data)}
    )
    assert response.errors is None
    uuid = UUID(response.data["employee_create"]["uuid"])

    verify_query = """
        query VerifyQuery($uuid: UUID!) {
            employees(uuids: [$uuid], from_date: null, to_date: null) {
                objects {
                    user_key
                    givenname
                    surname
                    cpr_no
                }
            }
        }
    """
    response: GQLResponse = graphapi_post(verify_query, {"uuid": str(uuid)})
    assert response.errors is None
    obj = one(one(response.data["employees"])["objects"])
    assert obj["givenname"] == test_data.givenname
    assert obj["surname"] == test_data.surname
    assert obj["user_key"] == test_data.user_key or str(uuid)
    assert obj["cpr_no"] == test_data.cpr_number


# --------------------------------------------------------------------------------------
# Update tests
# --------------------------------------------------------------------------------------


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
    # st.text() | st.none(),
    st.datetimes(
        min_value=datetime.datetime(1930, 1, 1),
        max_value=now_beginning,
    )
    | st.none(),
    # cpr_no
    st.from_regex(r"^\d{10}$") | st.none(),
)
async def test_update_mutator(
    given_uuid,
    given_validity_dts,
    given_name_tuple,
    given_nickname_tuple,
    given_seniority,
    given_cpr_no,
):
    """Test which verifies pydantic values can be sent through the mutator.

    This is done by trying to generate a EmployeeUpdate pydantic class, if this
    succeeds, we also expect the mutator to succeed.. otherwise we expect validation
    errors.
    """

    # Unpack tuples
    given_uuid_str = str(given_uuid)
    given_validity_from, given_validity_to = given_validity_dts
    given_name, given_givenname, given_surname = given_name_tuple
    (
        given_nickname,
        given_nickname_givenname,
        given_nickname_surname,
    ) = given_nickname_tuple

    # Create arguments for GraphQL (init with required fields)
    mutator_args = {
        "uuid": given_uuid_str,
        "from": given_validity_from.date().isoformat(),
    }

    if given_validity_to:
        mutator_args["to"] = given_validity_to.date().isoformat()

    if given_name:
        mutator_args["name"] = given_name
    if given_givenname:
        mutator_args["given_name"] = given_givenname
    if given_surname:
        mutator_args["surname"] = given_surname

    if given_nickname:
        mutator_args["nickname"] = given_nickname
    if given_nickname_givenname:
        mutator_args["nickname_given_name"] = given_nickname_givenname
    if given_nickname_surname:
        mutator_args["nickname_surname"] = given_nickname_surname

    if given_seniority:
        mutator_args["seniority"] = given_seniority.date().isoformat()
    if given_cpr_no:
        mutator_args["cpr_no"] = given_cpr_no

    # GraphQL
    with patch(
        "mora.graphapi.versions.latest.mutators.employee_update"
    ) as mock_employee_update:
        mock_employee_update.return_value = EmployeeUpdateResponseType(uuid=given_uuid)

        mutation_func = "employee_update"
        query = _get_employee_update_mutation_query(mutation_func)
        response = await execute_graphql(query=query, variable_values=mutator_args)

        # Assert
        response_uuid = None
        if response and response.data:
            response_uuid = response.data.get(mutation_func, {}).get("uuid", None)

        assert response_uuid == str(given_uuid)


@pytest.mark.parametrize(
    "given_expected_err_str,given_mutator_args,exception_type",
    [
        (
            EmployeeUpdate._ERR_INVALID_NAME,
            {
                "name": "TestMan Duke",
                "given_name": "TestMan",
                "surname": "Duke",
            },
            ValueError,
        ),
        (
            EmployeeUpdate._ERR_INVALID_NICKNAME,
            {
                "nickname": "Test Lord",
                "nickname_given_name": "Test",
                "nickname_surname": "Lord",
            },
            ValueError,
        ),
        (EmployeeUpdate._ERR_INVALID_CPR, {"cpr_no": ""}, ValidationError),
        (EmployeeUpdate._ERR_INVALID_CPR, {"cpr_no": "00112233445"}, ValidationError),
        (EmployeeUpdate._ERR_INVALID_CPR, {"cpr_no": "001122334"}, ValidationError),
        (EmployeeUpdate._ERR_INVALID_CPR, {"cpr_no": "001"}, ValidationError),
    ],
)
async def test_update_mutator_fails(
    given_expected_err_str, given_mutator_args, exception_type
):
    """Test which verifies that certain mutator inputs, cause a validation error."""

    # Configure mutator variables
    var_values = {
        "uuid": "00000000-0000-0000-0000-000000000000",
        "from": now_beginning.date().isoformat(),
        **given_mutator_args,
    }

    for key, value in given_mutator_args.items():
        if value is None:
            continue

        var_values[key] = value

    # Mock & Run
    with patch(
        "mora.graphapi.versions.latest.employee.handle_requests"
    ) as mock_handle_requests:
        mock_handle_requests.return_value = var_values["uuid"]

        query = _get_employee_update_mutation_query("employee_update")
        response = await execute_graphql(query=query, variable_values=var_values)

        response_exception_type = None
        response_exception_msg_str = None
        if isinstance(response.errors, list) and response.errors[0]:
            response_exception = response.errors[0].original_error

        if response_exception:
            # with pytest.raises(ValidationError) as e_info:
            with pytest.raises(exception_type) as e_info:
                raise response_exception

            response_exception_type = e_info.type

            if exception_type == ValidationError:
                response_exception_msg_str = str(e_info.value.args[0][0].exc)
            else:
                response_exception_msg_str = e_info.value.args[0]

        # Assert
        mock_handle_requests.assert_not_called()

        assert response_exception_type is exception_type
        assert response_exception_msg_str == given_expected_err_str


@pytest.mark.parametrize(
    "given_uuid,given_from,given_mutator_args",
    [
        (
            "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
            datetime.datetime.now(),
            {"name": "YeeHaaa man"},
        ),
        (
            "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
            datetime.datetime.now(),
            {"given_name": "Test Given Name"},
        ),
        (
            "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
            datetime.datetime.now(),
            {"surname": "Duke"},
        ),
        (
            "6ee24785-ee9a-4502-81c2-7697009c9053",
            datetime.datetime.now(),
            {"nickname": "Fancy Nickname"},
        ),
        (
            "6ee24785-ee9a-4502-81c2-7697009c9053",
            datetime.datetime.now(),
            {"nickname_given_name": "Fancy Nickname Given Name"},
        ),
        (
            "6ee24785-ee9a-4502-81c2-7697009c9053",
            datetime.datetime.now(),
            {"nickname_surname": "Lord Nick"},
        ),
        (
            "7626ad64-327d-481f-8b32-36c78eb12f8c",
            datetime.datetime.now(),
            {"seniority": datetime.datetime.now().date().isoformat()},
        ),
        (
            "236e0a78-11a0-4ed9-8545-6286bb8611c7",
            datetime.datetime.now(),
            {"cpr_no": "0000000000"},
        ),
        (
            "236e0a78-11a0-4ed9-8545-6286bb8611c7",
            datetime.datetime.now(),
            {
                "name": "YeeHaaa man",
                "nickname": "Fancy Nickname",
                "seniority": datetime.datetime.now().date().isoformat(),
                "cpr_no": "0000000000",
            },
        ),
        (
            "236e0a78-11a0-4ed9-8545-6286bb8611c7",
            datetime.datetime.now(),
            {
                "given_name": "TestMan",
                "surname": "Duke",
                "nickname_given_name": "Test",
                "nickname_surname": "Lord",
                "seniority": datetime.datetime.now().date().isoformat(),
                "cpr_no": "0101872144",
            },
        ),
    ],
)
@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
async def test_update_integration(given_uuid, given_from, given_mutator_args):
    # Configure mutator variables
    var_values = {
        "uuid": given_uuid,
        "from": given_from.date().isoformat(),
        **given_mutator_args,
    }

    for key, value in given_mutator_args.items():
        if value is None:
            continue

        var_values[key] = value

    # Run the query
    mutation_func = "employee_update"
    query = _get_employee_update_mutation_query(mutation_func)
    _ = await execute_graphql(query=query, variable_values=var_values)

    # Fetch employee from LoRa
    c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")
    lora_employee = await c.bruger.get(uuid=given_uuid)

    # Assert all the update values have been assigned
    for key, value in given_mutator_args.items():
        if value is None:
            continue

        newest_update_value = _get_lora_mutator_arg(key, lora_employee)
        assert newest_update_value == value


@given(data=st.data())
@pytest.mark.slow
@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
async def _test_update_integration_hypothesis(data, graphapi_post) -> None:
    valid_employee_uuids = [
        UUID("53181ed2-f1de-4c4a-a8fd-ab358c2c454a"),
        UUID("6ee24785-ee9a-4502-81c2-7697009c9053"),
        # UUID("236e0a78-11a0-4ed9-8545-6286bb8611c7"),
        # FAILS when making a lookup before doing anything
        # UUID("7626ad64-327d-481f-8b32-36c78eb12f8c"),
    ]

    # Generate data using hypothesis'es draw functionality
    employee_uuid = data.draw(st.sampled_from(valid_employee_uuids))
    now = datetime.datetime.utcnow()
    yesterday = now - datetime.timedelta(days=1)
    validity = data.draw(
        st.tuples(
            st.datetimes(
                min_value=datetime.datetime(1930, 1, 1),
                max_value=datetime.datetime(
                    yesterday.year, yesterday.month, yesterday.day
                ),
            ),
            st.datetimes() | st.none(),
        ).filter(lambda dts: dts[0] <= dts[1] if dts[0] and dts[1] else True)
    )
    test_data_validity_from, test_data_validity_to = validity
    test_data_validity_from = datetime.datetime.combine(
        test_data_validity_from.date(), datetime.datetime.min.time()
    )

    names_whitelist_cats = ("Ll", "Lo", "Lu")
    given_name, given_given_name, given_surname = data.draw(
        st.tuples(
            st.text(alphabet=characters(whitelist_categories=names_whitelist_cats))
            | st.none(),
            st.text(alphabet=characters(whitelist_categories=names_whitelist_cats))
            | st.none(),
            st.text(alphabet=characters(whitelist_categories=names_whitelist_cats))
            | st.none(),
        ).filter(lambda names: not (names[0] and (names[1] or names[2]))),
    )

    given_nickname, given_nickname_given_name, given_nickname_surname = data.draw(
        st.tuples(
            st.text(alphabet=characters(whitelist_categories=names_whitelist_cats))
            | st.none(),
            st.text(alphabet=characters(whitelist_categories=names_whitelist_cats))
            | st.none(),
            st.text(alphabet=characters(whitelist_categories=names_whitelist_cats))
            | st.none(),
        ).filter(lambda names: not (names[0] and (names[1] or names[2]))),
    )

    # TODO: Find a way to implement this, when figuring out how employees behave after
    #  senority have been updated
    # seniority = data.draw(
    #     st.datetimes(
    #         min_value=datetime.datetime(1930, 1, 1),
    #         max_value=datetime.datetime(yesterday.year, yesterday.month, yesterday.day),
    #     )
    #     | st.none()
    # )

    test_data = data.draw(
        st.builds(
            EmployeeUpdate,
            uuid=st.just(employee_uuid),
            from_date=st.just(test_data_validity_from),
            name=st.just(given_name),
            given_name=st.just(given_given_name),
            surname=st.just(given_surname),
            nickname=st.just(given_nickname),
            nickname_given_name=st.just(given_nickname_given_name),
            nickname_surname=st.just(given_nickname_surname),
            # TODO: Make the integration test able to verify these two attrbiutes.
            #  I have had issues with getting success from update-mutator, but then
            #  we cant for some reason get the employee afterwards.. both the old
            #  and the new query method don't work here.. but it seems to occur after a
            #  couple of interation.. so i am afraid that a specific update causes a
            #  weird state for the customer, which i am not sure how to handle.
            # seniority=st.just(seniority),
            # cpr_no=st.from_regex(r"^\d{10}$") | st.none(),
        ).filter(lambda model: not model.no_values())
    )
    payload = jsonable_encoder(test_data)

    # TODO: Remove this, when a proper way of testing CPR-NO have been implemented.
    # if payload.get('cpr_no'):
    #     # Convert from-date since i am having issues getting employees with certain
    #     # dates, when using CPR No.
    #     payload['from'] = datetime.datetime.combine(
    #         yesterday.date(), datetime.datetime.min.time()
    #     ).isoformat()

    # Execute the mutation query
    mutation_response: GQLResponse = graphapi_post(
        """
        mutation($input: EmployeeUpdateInput!) {
            employee_update(input: $input) {
                uuid
            }
        }
        """,
        {"input": payload},
    )
    assert mutation_response.errors is None

    # OBS: We run it through the UUID() constructor to verify its a valid UUID.
    test_data_uuid_updated = UUID(mutation_response.data["employee_update"]["uuid"])

    # Query the updated user and assert values have been updated
    verify_response: GQLResponse = graphapi_post(
        _get_employee_verify_query(), {mapping.UUID: str(test_data_uuid_updated)}
    )
    assert verify_response.errors is None
    assert len(verify_response.data["employees"]) > 0

    updated_employee_data = None
    for e_obj in one(verify_response.data["employees"]).get("objects", []):
        if not e_obj.get("validity", {}).get("to"):
            updated_employee_data = e_obj

    assert updated_employee_data is not None

    # New Asserts
    if test_data.name:
        if len(test_data.name.split(" ")) > 1:
            employee_data_givenname = updated_employee_data.get("givenname")
            employee_data_surname = updated_employee_data.get("surname")
            employee_data_name = (
                f"{employee_data_givenname} {employee_data_surname}"
                if employee_data_surname and len(employee_data_surname) > 0
                else employee_data_givenname
            )
            assert test_data.name == employee_data_name
        else:
            assert test_data.name == updated_employee_data.get("givenname")

    if test_data.given_name:
        assert test_data.given_name == updated_employee_data.get("givenname")

    if test_data.surname:
        assert test_data.surname == updated_employee_data.get("surname")

    if test_data.nickname:
        if len(test_data.nickname.split(" ")) > 1:
            employee_data_nickname_givenname = updated_employee_data.get(
                "nickname_givenname"
            )
            employee_data_nickname_surname = updated_employee_data.get(
                "nickname_surname"
            )
            employee_data_nickname = (
                f"{employee_data_nickname_givenname} {employee_data_nickname_surname}"
                if employee_data_nickname_surname
                and len(employee_data_nickname_surname) > 0
                else employee_data_nickname_givenname
            )
            assert test_data.name == employee_data_nickname
        else:
            assert test_data.nickname == updated_employee_data.get("nickname_givenname")

    if test_data.nickname_given_name:
        assert test_data.nickname_given_name == updated_employee_data.get(
            "nickname_givenname"
        )

    if test_data.nickname_surname:
        assert test_data.nickname_surname == updated_employee_data.get(
            "nickname_surname"
        )

    if test_data.seniority:
        assert test_data.seniority == updated_employee_data.get("seniority")

    if test_data.cpr_no:
        assert test_data.cpr_no == updated_employee_data.get("cpr_no")


@pytest.mark.slow
@given(data=st.data())
@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
async def test_update_integration_hypothesis(data, graphapi_post):
    employee_uuid = data.draw(
        st.sampled_from(
            [
                UUID("53181ed2-f1de-4c4a-a8fd-ab358c2c454a"),
                # UUID("6ee24785-ee9a-4502-81c2-7697009c9053"),
                # UUID("236e0a78-11a0-4ed9-8545-6286bb8611c7"),
            ]
        )
    )

    now = datetime.datetime.utcnow()
    yesterday = now - datetime.timedelta(days=1)
    validity = data.draw(
        st.tuples(
            st.datetimes(
                min_value=datetime.datetime(1930, 1, 1),
                max_value=datetime.datetime(
                    yesterday.year, yesterday.month, yesterday.day
                ),
            ),
            st.datetimes() | st.none(),
        ).filter(lambda dts: dts[0] <= dts[1] if dts[0] and dts[1] else True)
    )
    test_data_validity_from, _ = validity
    test_data_validity_from = datetime.datetime.combine(
        test_data_validity_from.date(), datetime.datetime.min.time()
    )

    names_whitelist_cats = ("Ll", "Lo", "Lu")
    test_data = data.draw(
        st.builds(
            EmployeeUpdate,
            uuid=st.just(employee_uuid),
            from_date=st.just(test_data_validity_from),
            # name=st.text(alphabet=characters(whitelist_categories=names_whitelist_cats))
            # | st.none(),
            given_name=st.text(
                alphabet=characters(whitelist_categories=names_whitelist_cats)
            )
            | st.none(),
        ).filter(lambda model: not model.no_values())
    )
    payload = jsonable_encoder(test_data)

    mutation_response: GQLResponse = graphapi_post(
        """
        mutation($input: EmployeeUpdateInput!) {
            employee_update(input: $input) {
                uuid
            }
        }
        """,
        {"input": payload},
    )
    assert mutation_response.errors is None
    test_data_uuid_updated = UUID(mutation_response.data["employee_update"]["uuid"])

    # Fetch employee and verify the employee have been updated
    verify_response: GQLResponse = graphapi_post(
        _get_employee_verify_query(), {mapping.UUID: str(test_data_uuid_updated)}
    )

    print("----------------------------------------------------------")
    print(verify_response.data)
    print("----------------------------------------------------------")

    assert verify_response.errors is None
    assert len(verify_response.data["employees"]) > 0

    verify_data_employee = one(verify_response.data["employees"])
    verify_data_employee_objs = verify_data_employee.get("objects", [])

    c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")
    lora_employee = await c.bruger.get(uuid=str(test_data_uuid_updated))

    assert test_data.given_name == _get_lora_mutator_arg("given_name", lora_employee)
    assert len(verify_data_employee_objs) > 1

    verify_data = None
    for e_obj in verify_data_employee_objs:
        if not e_obj.get("validity", {}).get("to"):
            verify_data = e_obj
            break

    assert verify_data[mapping.UUID] == str(test_data_uuid_updated)

    # if test_data.name:
    #     assert verify_data.get("givenname") == test_data.name

    if test_data.given_name:
        assert verify_data.get("givenname") == test_data.given_name


# --------------------------------------------------------------------------------------
# Helper methods
# --------------------------------------------------------------------------------------


def _get_employee_update_mutation_query(mutation_func: str):
    return (
        "mutation($uuid: UUID!, $from: DateTime!, $to: DateTime, $name: String, "
        # "$givenName: String, $surName: String, $nickname: String, "
        "$given_name: String, $surname: String, $nickname: String, "
        # "$nicknameGivenName: String, $nicknameSurName: String, $seniority: Date, "
        "$nickname_given_name: String, $nickname_surname: String, $seniority: Date, "
        "$cpr_no: String) {"
        f"{mutation_func}(input: {{uuid: $uuid, from: $from, to: $to, name: $name, "
        "given_name: $given_name, surname: $surname, nickname: $nickname, "
        "nickname_given_name: $nickname_given_name, "
        "nickname_surname: $nickname_surname, seniority: $seniority, cpr_no: $cpr_no}) "
        "{ uuid }"
        "}"
    )


def _get_lora_mutator_arg(mutator_key: str, lora_employee: dict):
    """Finds LoRa-employee equivalent value to a employee-update mutation argument.

    IMPORTANT: lora-employee attributes & relations are lists of objects with all
    attributes, which all have a "from" and "to", to specify if "the set of attributes"
    is active. The way this method finds the active ones are just by looking for an
    object where "to" is set to the string: "infinity".>
    """
    if not lora_employee:
        return None

    # Find expansion by finding the one where to==infinity
    employee_expansions = lora_employee.get("attributter", {}).get(
        "brugerudvidelser", []
    )
    active_expansion = None
    for expansion in employee_expansions:
        expansion_to = expansion.get("virkning", {}).get("to", None)
        if expansion_to != mapping.INFINITY:
            continue

        active_expansion = expansion
        break

    # Find associated people (for CPR no) by finding the one where to==infinity
    employee_associated_people = lora_employee.get("relationer", {}).get(
        "tilknyttedepersoner", []
    )
    employee_associated_people_active = None
    for asso_ppl in employee_associated_people:
        to_date = asso_ppl.get("virkning", {}).get("to", None)
        if not to_date or to_date != mapping.INFINITY:
            continue

        employee_associated_people_active = asso_ppl
        break

    # Find mutator key equivalent
    if mutator_key == "from_date":
        from_date_str = lora_employee.get("fratidspunkt", {}).get(
            "tidsstempeldatotid", None
        )
        return datetime.datetime.fromisoformat(from_date_str)

    if mutator_key == "name":
        return f"{active_expansion['fornavn']} {active_expansion['efternavn']}"

    if mutator_key == "given_name":
        return active_expansion["fornavn"]

    if mutator_key == "surname":
        return active_expansion["efternavn"]

    if mutator_key == "nickname":
        return f"{active_expansion['kaldenavn_fornavn']} {active_expansion['kaldenavn_efternavn']}"

    # if mutator_key == "nicknameGivenName":
    if mutator_key == "nickname_given_name":
        return active_expansion["kaldenavn_fornavn"]

    # if mutator_key == "nicknameSurName":
    if mutator_key == "nickname_surname":
        return active_expansion["kaldenavn_efternavn"]

    if mutator_key == "seniority":
        return active_expansion["seniority"]

    if mutator_key == "cpr_no":
        cpr_no = employee_associated_people_active.get("urn", "").split(":")[-1]
        return cpr_no if len(cpr_no) > 0 else None

    return None


def _get_employee_data_from_mutator_key(
    employee_data: dict, mutator_key: str, new_value: str | None
):
    if mutator_key == "name":
        givenname = employee_data.get("givenname", "")
        surname = employee_data.get("surname", "")

        # ignore the surname, if the new value don't include one
        # Ex. if an employee already have a surname and we only update the givenname -
        # using the "name"-attribute (yes we only update "what was found" in "name")
        if new_value:
            new_value_split = new_value.split(" ")
            if len(new_value_split) < 2:
                surname = ""

        return f"{givenname} {surname}" if surname else givenname

    if mutator_key == "nickname":
        nickname_givenname = employee_data.get("nickname_givenname", "")
        nickname_surname = employee_data.get("nickname_surname", "")

        if new_value:
            new_value_split = new_value.split(" ")
            if len(new_value_split) < 2:
                nickname_surname = ""

        return (
            f"{nickname_givenname} {nickname_surname}"
            if nickname_surname
            else nickname_givenname
        )

    if mutator_key == "given_name":
        return employee_data["givenname"]

    if mutator_key == "nickname_given_name":
        return employee_data["nickname_givenname"]

    return employee_data[mutator_key]


def _get_employee_verify_query():
    return """
        query VerifyQuery($uuid: UUID!){
          employees(uuids: [$uuid], from_date: null, to_date: null)
              {
                uuid,
                objects {
                  uuid
                  givenname
                  surname
                  nickname_givenname
                  nickname_surname
                  seniority
                  cpr_no
                  validity {
                      from
                      to
                  }
                }
              }
        }
    """
