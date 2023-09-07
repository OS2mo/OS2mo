# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from _datetime import datetime
from unittest.mock import AsyncMock
from unittest.mock import patch
from uuid import UUID

import pytest
from fastapi.encoders import jsonable_encoder
from hypothesis import given
from hypothesis import strategies as st
from more_itertools import one
from pydantic import Field
from pytest import MonkeyPatch

from .strategies import graph_data_strat
from .strategies import graph_data_uuids_strat
from .utils import fetch_class_uuids
from .utils import fetch_org_unit_validity
from mora.graphapi.shim import execute_graphql
from mora.graphapi.shim import flatten_data
from mora.graphapi.versions.latest import dataloaders
from mora.graphapi.versions.latest.models import ITAssociationCreate
from ramodels.mo import Validity as RAValidity
from ramodels.mo.details import AssociationRead
from tests.conftest import GQLResponse


class ITAssociationRead(AssociationRead):
    # This is needed since these 2 will be `None` otherwise, which would result in
    # 0 ITAssociations created in the MonkeyPatch..
    it_user_uuid: UUID = Field(
        description="UUID of an 'ITUser' model, only defined for 'IT associations.'"
    )
    job_function_uuid: UUID = Field(description="UUID of the 'job_function'")


@given(test_data=graph_data_strat(ITAssociationRead))
def test_query_all(test_data, graphapi_post, patch_loader):
    """Test that we can query all our ITAssociations."""
    # JSON encode test data
    test_data = jsonable_encoder(test_data)

    # Patch dataloader
    with MonkeyPatch.context() as patch:
        patch.setattr(dataloaders, "search_role_type", patch_loader(test_data))
        query = """
            query {
                associations(filter: {it_association: true}) {
                    objects {
                        uuid
                        objects {
                            uuid
                            user_key
                            org_unit_uuid
                            employee_uuid
                            association_type_uuid
                            primary_uuid
                            substitute_uuid
                            job_function_uuid
                            primary_uuid
                            it_user_uuid
                            dynamic_class_uuid
                            type
                            validity {from to}
                        }
                    }
                }
            }
        """
        response = graphapi_post(query)

    assert response.errors is None
    assert response.data

    assert flatten_data(response.data["associations"]["objects"]) == test_data


@given(test_data=graph_data_strat(ITAssociationRead))
def test_query_none(test_data, graphapi_post, patch_loader):
    """Test that we don't get any ITAssociations, when using the `it_association` parameter."""
    # JSON encode test data
    test_data = jsonable_encoder(test_data)

    # Patch dataloader
    with MonkeyPatch.context() as patch:
        patch.setattr(dataloaders, "search_role_type", patch_loader(test_data))
        query = """
            query {
                associations(filter: {it_association: false}) {
                    objects {
                        uuid
                        objects {
                            uuid
                            user_key
                            org_unit_uuid
                            employee_uuid
                            association_type_uuid
                            primary_uuid
                            substitute_uuid
                            job_function_uuid
                            primary_uuid
                            it_user_uuid
                            dynamic_class_uuid
                            type
                            validity {from to}
                        }
                    }
                }
            }
        """
        response = graphapi_post(query)

    assert response.errors is None
    assert response.data

    assert flatten_data(response.data["associations"]["objects"]) == []


@given(test_input=graph_data_uuids_strat(ITAssociationRead))
def test_query_by_uuid(test_input, graphapi_post, patch_loader):
    """Test that we can query associations by UUID."""
    # Sample UUIDs
    test_data, test_uuids = test_input

    # Patch dataloader
    with MonkeyPatch.context() as patch:
        patch.setattr(dataloaders, "get_role_type_by_uuid", patch_loader(test_data))
        query = """
                query TestQuery($uuids: [UUID!]) {
                    associations(filter: {uuids: $uuids, it_association: true}) {
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
        assoc.get("uuid") for assoc in response.data["associations"]["objects"]
    ]
    assert set(result_uuids) == set(test_uuids)
    assert len(result_uuids) == len(set(test_uuids))


@given(test_data=...)
@patch(
    "mora.graphapi.versions.latest.mutators.create_itassociation",
    new_callable=AsyncMock,
)
async def test_create_itassociation_mutation_unit_test(
    create_itassociation: AsyncMock, test_data: ITAssociationCreate
) -> None:
    """Tests that the mutator function for creating a ITAssociation annotation passes through,
    with the defined pydantic model."""

    mutation = """
        mutation CreateITAssociation($input: ITAssociationCreateInput!) {
            itassociation_create(input: $input) {
                uuid
            }
        }
    """

    create_itassociation.return_value = test_data.uuid

    payload = jsonable_encoder(test_data)

    response = await execute_graphql(query=mutation, variable_values={"input": payload})
    assert response.errors is None
    assert response.data == {"itassociation_create": {"uuid": str(test_data.uuid)}}

    create_itassociation.assert_called_with(test_data)


@given(data=st.data())
@pytest.mark.integration_test
@pytest.mark.usefixtures("load_fixture_data_with_reset")
async def test_create_itassociation_integration_test(
    data, graphapi_post, org_uuids, employee_uuids, ituser_uuids
) -> None:
    """Test that ITAssociation annotations can be created in LoRa via GraphQL."""

    org_uuid = data.draw(st.sampled_from(org_uuids))
    parent_from, parent_to = fetch_org_unit_validity(graphapi_post, org_uuid)

    test_data_validity_start = data.draw(
        st.datetimes(min_value=parent_from, max_value=parent_to or datetime.max)
    )
    if parent_to:
        test_data_validity_end_strat = st.datetimes(
            min_value=test_data_validity_start, max_value=parent_to
        )
    else:
        test_data_validity_end_strat = st.none() | st.datetimes(
            min_value=test_data_validity_start,
        )

    job_function_uuids = fetch_class_uuids(graphapi_post, "engagement_job_function")

    test_data = data.draw(
        st.builds(
            ITAssociationCreate,
            uuid=st.uuids() | st.none(),
            org_unit=st.just(org_uuid),
            it_user=st.sampled_from(ituser_uuids),
            person=st.sampled_from(employee_uuids),
            job_function=st.sampled_from(job_function_uuids),
            validity=st.builds(
                RAValidity,
                from_date=st.just(test_data_validity_start),
                to_date=test_data_validity_end_strat,
            ),
        )
    )

    mutation = """
        mutation CreateITAssociation($input: ITAssociationCreateInput!) {
            itassociation_create(input: $input) {
                uuid
            }
        }
    """
    response: GQLResponse = graphapi_post(
        mutation, {"input": jsonable_encoder(test_data)}
    )

    assert response.errors is None
    uuid = UUID(response.data["itassociation_create"]["uuid"])

    verify_query = """
        query VerifyQuery($uuid: UUID!) {
            associations(filter: {uuids: [$uuid], from_date: null, to_date: null, it_association: true}) {
                objects {
                    objects {
                        user_key
                        org_unit: org_unit_uuid
                        employee: employee_uuid
                        it_user: it_user_uuid
                        job_function: job_function_uuid
                        validity {
                            from
                            to
                        }
                    }
                }
            }
        }
    """

    response: GQLResponse = graphapi_post(verify_query, {"uuid": str(uuid)})
    assert response.errors is None
    obj = one(one(response.data["associations"]["objects"])["objects"])

    assert UUID(obj["employee"]) == test_data.person
    assert UUID(obj["it_user"]) == test_data.it_user
    assert UUID(obj["org_unit"]) == test_data.org_unit
    assert obj["user_key"] == (test_data.user_key or str(uuid))
    assert UUID(obj["job_function"]) == test_data.job_function

    assert (
        datetime.fromisoformat(obj["validity"]["from"]).date()
        == test_data.validity.from_date.date()
    )
    if obj["validity"]["to"] is not None:
        assert (
            datetime.fromisoformat(obj["validity"]["to"]).date()
            == test_data.validity.to_date.date()
        )
    else:
        assert test_data.validity.to_date is None
