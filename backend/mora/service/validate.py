#
# Copyright (c) 2017-2018, Magenta ApS
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#


import flask

from . import facet
from .address_handler import base
from .. import lora
from .. import mapping
from .. import util
from .. import validator

blueprint = flask.Blueprint('validate', __name__, static_url_path='',
                            url_prefix='/service/validate')


@blueprint.route('/org-unit/', methods=['POST'])
@util.restrictargs()
def org_unit_validity():
    """
    Verify that an org unit is valid within a given set of start/end dates

    .. :quickref: Validate; Validate org unit

    :<json object org_unit: The associated org unit
    :<json object validity: The relevant validities to be checked

    .. sourcecode:: json

      {
        "org_unit": {
          "uuid": "a30f5f68-9c0d-44e9-afc9-04e58f52dfec"
        },
        "validity": {
            "from": "2016-01-01",
            "to": "2017-12-31"
        }
      }
    """
    req = flask.request.get_json()

    org_unit = util.checked_get(req, mapping.ORG_UNIT, {}, required=True)
    valid_from, valid_to = util.get_validities(req)

    validator.is_date_range_in_org_unit_range(
        org_unit, valid_from, valid_to)

    return flask.jsonify(success=True)


@blueprint.route('/employee/', methods=['POST'])
@util.restrictargs()
def employee_validity():
    """
    Verify that an employee is valid within a given set of start/end dates

    .. :quickref: Validate; Validate employee

    :<json object org_unit: The associated org unit
    :<json object validity: The relevant validities to be checked

    .. sourcecode:: json

      {
        "person": {
          "uuid": "a30f5f68-9c0d-44e9-afc9-04e58f52dfec"
        },
        "validity": {
            "from": "2016-01-01",
            "to": "2017-12-31"
        }
      }
    """
    req = flask.request.get_json()

    employee = util.checked_get(req, mapping.PERSON, {}, required=True)
    valid_from, valid_to = util.get_validities(req)

    validator.is_date_range_in_employee_range(employee, valid_from, valid_to)

    return flask.jsonify(success=True)


@blueprint.route('/cpr/', methods=['POST'])
@util.restrictargs()
def check_cpr():
    """
    Verify that an employee with the given CPR no. does not already exist

    .. :quickref: Validate; Validate CPR no.

    :<json string cpr: The associated CPR number
    :<json object org: The associated organisation
    :<json object validity: The relevant validities to be checked

    .. sourcecode:: json

      {
        "cpr_no": "1212121212",
        "org": {
          "uuid": "a30f5f68-9c0d-44e9-afc9-04e58f52dfec"
        },
        "validity": {
            "from": "2016-01-01",
            "to": "2017-12-31"
        }
      }
    """
    req = flask.request.get_json()

    cpr = util.checked_get(req, mapping.CPR_NO, "", required=True)
    org_uuid = util.get_mapping_uuid(req, mapping.ORG, required=True)

    validator.does_employee_with_cpr_already_exist(
        cpr, '-infinity', 'infinity', org_uuid)

    return flask.jsonify(success=True)


@blueprint.route('/active-engagements/', methods=['POST'])
@util.restrictargs()
def employee_engagements():
    """
    Verify that an employee has active engagements

    .. :quickref: Validate; Validate active engagements

    :<json object person: The associated employee
    :<json object validity: The relevant validities to be checked

    .. sourcecode:: json

      {
        "person": {
          "uuid": "a30f5f68-9c0d-44e9-afc9-04e58f52dfec"
        },
        "validity": {
            "from": "2016-01-01",
            "to": "2017-12-31"
        }
      }
    """
    req = flask.request.get_json()

    employee_uuid = util.get_mapping_uuid(req, mapping.PERSON, required=True)
    valid_from, valid_to = util.get_validities(req)

    validator.does_employee_have_active_engagement(
        employee_uuid, valid_from, valid_to)

    return flask.jsonify(success=True)


@blueprint.route('/existing-associations/', methods=['POST'])
@util.restrictargs()
def employee_existing_associations():
    """
    Verify that an employee does not have existing associations for a given
    org unit

    .. :quickref: Validate; Validate existing associations

    :<json object person: The associated employee
    :<json object person: The associated org unit
    :<json object validity: The relevant validities to be checked

    .. sourcecode:: json

      {
        "person": {
          "uuid": "a30f5f68-9c0d-44e9-afc9-04e58f52dfec"
        },
        "org_unit": {
          "uuid": "c55e9eb3-2b23-4364-b5e4-dff51ddf289e"
        },
        "validity": {
            "from": "2016-01-01",
            "to": "2017-12-31"
        }
      }
    """
    req = flask.request.get_json()

    employee_uuid = util.get_mapping_uuid(req, mapping.PERSON, required=True)
    org_unit_uuid = util.get_mapping_uuid(req, mapping.ORG_UNIT, required=True)
    valid_from, valid_to = util.get_validities(req)

    validator.does_employee_have_existing_association(
        employee_uuid, org_unit_uuid, valid_from, valid_to)

    return flask.jsonify(success=True)


@blueprint.route('/candidate-parent-org-unit/', methods=['POST'])
@util.restrictargs()
def candidate_parent_org_unit():
    """
    Verify that a given parent is a suitable candidate for a org unit move,
    i.e. that the candidate parent is not in the sub tree of the org unit being
    moved, and that the org unit being moved is not a root unit.

    .. :quickref: Validate; Validate candidate parent org unit

    :<json object org_unit: The associated org unit to be moved
    :<json object parent: The associated parent org unit
    :<json object from: The date on which the move is to take place

    .. sourcecode:: json

      {
        "org_unit": {
          "uuid": "c55e9eb3-2b23-4364-b5e4-dff51ddf289e"
        },
        "parent": {
          "uuid": "a30f5f68-9c0d-44e9-afc9-04e58f52dfec"
        },
        "validity": {
            "from": "2016-01-01",
        }
      }
    """
    req = flask.request.get_json()

    org_unit_uuid = util.get_mapping_uuid(req, mapping.ORG_UNIT, required=True)
    parent_uuid = util.get_mapping_uuid(req, mapping.PARENT, required=True)
    valid_from = util.get_valid_from(req)

    validator.is_candidate_parent_valid(
        org_unit_uuid, parent_uuid, valid_from)

    return flask.jsonify(success=True)


@blueprint.route('/address/', methods=['POST'])
@util.restrictargs()
def address_value():
    """
    Verify that a given address value conforms to the format for the given
    address type. E.g. that a phone number consists of 8 digits.

    .. :quickref: Validate; Validate address value

    :<json object value: The address value to be checked
    :<json object address_type: The address type to be checked against

    .. sourcecode:: json

      {
        "value": "12345678",
        "address_type": {
          "uuid": "a30f5f68-9c0d-44e9-afc9-04e58f52dfec"
        }
      }
    """

    req = flask.request.get_json()
    address_type_uuid = util.get_mapping_uuid(req, mapping.ADDRESS_TYPE,
                                              required=True)
    value = util.checked_get(req, mapping.VALUE, default="", required=True)

    c = lora.Connector()
    type_obj = facet.get_one_class(c, address_type_uuid)

    scope = util.checked_get(type_obj, 'scope', '', required=True)

    handler = base.get_handler_for_scope(scope)

    handler.validate_value(value)

    return flask.jsonify(success=True)
