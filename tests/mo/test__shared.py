#!/usr/bin/env python3
# --------------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2021 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
import pytest
from hypothesis import assume
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from ramodels.mo._shared import AddressType
from ramodels.mo._shared import AssociationType
from ramodels.mo._shared import EngagementAssociationType
from ramodels.mo._shared import EngagementRef
from ramodels.mo._shared import EngagementType
from ramodels.mo._shared import JobFunction
from ramodels.mo._shared import ManagerLevel
from ramodels.mo._shared import ManagerType
from ramodels.mo._shared import MOBase
from ramodels.mo._shared import OrganisationRef
from ramodels.mo._shared import OrgUnitHierarchy
from ramodels.mo._shared import OrgUnitLevel
from ramodels.mo._shared import OrgUnitRef
from ramodels.mo._shared import OrgUnitType
from ramodels.mo._shared import ParentRef
from ramodels.mo._shared import PersonRef
from ramodels.mo._shared import Primary
from ramodels.mo._shared import Responsibility
from ramodels.mo._shared import Validity
from ramodels.mo._shared import Visibility

# --------------------------------------------------------------------------------------
# MOBase
# --------------------------------------------------------------------------------------


class TestMOBase:
    def test_init(self):
        # MOBase cannot be instantiated
        with pytest.raises(TypeError, match="may not be instantiated"):
            MOBase()

    def test_fields(self):
        # Subclasses of MOBase should have a UUID field
        class MOSub(MOBase):
            pass

        assert MOSub.__fields__.get("uuid")


# --------------------------------------------------------------------------------------
# AddressType
# --------------------------------------------------------------------------------------


class TestAddressType:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert AddressType(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# EngagementAssociationType
# --------------------------------------------------------------------------------------


class TestEngagementAssociationType:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert EngagementAssociationType(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# EngagementRef
# --------------------------------------------------------------------------------------


class TestEngagementRef:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert EngagementRef(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# EngagementType
# --------------------------------------------------------------------------------------


class TestEngagementType:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert EngagementType(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# AssociationType
# --------------------------------------------------------------------------------------


class TestAssociationType:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert AssociationType(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# JobFunction
# --------------------------------------------------------------------------------------


class TestJobFunction:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert JobFunction(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# ManagerLevel
# --------------------------------------------------------------------------------------


class TestManagerLevel:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert ManagerLevel(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# ManagerType
# --------------------------------------------------------------------------------------


class TestManagerType:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert ManagerType(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# OrganisationRef
# --------------------------------------------------------------------------------------


class TestOrganisationRef:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert OrganisationRef(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# OrgUnitHierarchy
# --------------------------------------------------------------------------------------


class TestOrgUnitHierarchy:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert OrgUnitHierarchy(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# OrgUnitLevel
# --------------------------------------------------------------------------------------


class TestOrgUnitLevel:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert OrgUnitLevel(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# OrgUnitRef
# --------------------------------------------------------------------------------------


class TestOrgUnitRef:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert OrgUnitRef(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# OrgUnitType
# --------------------------------------------------------------------------------------


class TestOrgUnitType:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert OrgUnitType(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# ParentRef
# --------------------------------------------------------------------------------------


class TestParentRef:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert ParentRef(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# PersonRef
# --------------------------------------------------------------------------------------


class TestPersonRef:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert PersonRef(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# Primary
# --------------------------------------------------------------------------------------


class TestPrimary:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert Primary(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# Responsibility
# --------------------------------------------------------------------------------------


class TestResponsibility:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert Responsibility(uuid=hy_uuid)


# --------------------------------------------------------------------------------------
# Validity
# --------------------------------------------------------------------------------------


class TestValidity:
    @given(st.tuples(st.datetimes(), st.datetimes()))
    def test_init(self, dt_tup):
        from_dt, to_dt = dt_tup
        assume(from_dt <= to_dt)
        assert Validity(from_date=from_dt, to_date=to_dt)

    @given(st.tuples(st.datetimes(), st.datetimes()))
    def test_validator(self, dt_tup):
        from_dt, to_dt = dt_tup
        assume(from_dt > to_dt)
        with pytest.raises(
            ValidationError, match="from_date must be less than or equal to to_date"
        ):
            Validity(from_date=from_dt, to_date=to_dt)


# --------------------------------------------------------------------------------------
# Visibility
# --------------------------------------------------------------------------------------


class TestVisibility:
    @given(st.uuids())
    def test_init(self, hy_uuid):
        assert Visibility(uuid=hy_uuid)
