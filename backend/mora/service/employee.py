#
# Copyright (c) 2017-2018, Magenta ApS
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#


'''
Employees
---------

This section describes how to interact with employees.

For more information regarding reading relations involving employees, refer to
:http:get:`/service/(any:type)/(uuid:id)/details/`

'''
import copy
import uuid

import flask

from mora.service import detail_writing as writing
from . import org
from .. import common
from .. import exceptions
from .. import lora
from .. import mapping
from .. import settings
from .. import util

blueprint = flask.Blueprint('employee', __name__, static_url_path='',
                            url_prefix='/service')


def get_one_employee(c, userid, user=None, full=False):
    if not user:
        user = c.bruger.get(userid)

        if not user or not util.is_reg_valid(user):
            return None

    props = user['attributter']['brugeregenskaber'][0]

    r = {
        mapping.NAME: props['brugernavn'],
        mapping.UUID: userid,
    }

    if full:
        rels = user['relationer']
        orgid = rels['tilhoerer'][0]['uuid']

        if rels.get('tilknyttedepersoner'):
            r[mapping.CPR_NO] = (
                rels['tilknyttedepersoner'][0]['urn'].rsplit(':', 1)[-1]
            )

        r[mapping.ORG] = org.get_one_organisation(c, orgid)
        r[mapping.USER_KEY] = props['brugervendtnoegle']

    return r


@blueprint.route('/o/<uuid:orgid>/e/')
@util.restrictargs('at', 'start', 'limit', 'query')
def list_employees(orgid):
    '''Query employees in an organisation.

    .. :quickref: Employee; List & search

    :param uuid orgid: UUID of the organisation to search.

    :queryparam date at: Show employees at this point in time,
        in ISO-8601 format.
    :queryparam int start: Index of first unit for paging.
    :queryparam int limit: Maximum items
    :queryparam string query: Filter by employees matching this string.
        Please note that this only applies to attributes of the user, not the
        relations or engagements they have.

    :>json string items: The returned items.
    :>json string offset: Pagination offset.
    :>json string total: Total number of items available on this query.

    :>jsonarr string name: Human-readable name.
    :>jsonarr string uuid: Machine-friendly UUID.

    :status 200: Always.

    **Example Response**:

    .. sourcecode:: json

      {
        "items": [
          {
            "name": "Hans Bruger",
            "uuid": "9917e91c-e3ee-41bf-9a60-b024c23b5fe3"
          },
          {
            "name": "Joe User",
            "uuid": "cd2dcfad-6d34-4553-9fee-a7023139a9e8"
          }
        ],
        "offset": 0,
        "total": 1
      }

    '''

    # TODO: share code with list_orgunits?

    c = common.get_connector()

    args = flask.request.args

    kwargs = dict(
        limit=int(args.get('limit', 0)) or settings.DEFAULT_PAGE_SIZE,
        start=int(args.get('start', 0)) or 0,
        tilhoerer=str(orgid),
        gyldighed='Aktiv',
    )

    if 'query' in args:
        if util.is_cpr_number(args['query']):
            kwargs.update(
                tilknyttedepersoner='urn:dk:cpr:person:' + args['query'],
            )
        else:
            kwargs.update(vilkaarligattr='%{}%'.format(args['query']))

    return flask.jsonify(
        c.bruger.paged_get(get_one_employee, **kwargs)
    )


@blueprint.route('/e/<uuid:id>/')
@util.restrictargs('at')
def get_employee(id):
    '''Retrieve an employee.

    .. :quickref: Employee; Get

    :queryparam date at: Show the employee at this point in time,
        in ISO-8601 format.

    :>json string name: Human-readable name.
    :>json string uuid: Machine-friendly UUID.
    :>json object org: The organisation that this employee belongs to, as
        yielded by :http:get:`/service/o/`.
    :>json string cpr_no: CPR number of for the corresponding person.
        Please note that this is the only means for obtaining the CPR
        number; due to confidentiality requirements, all other end
        points omit it.

    :status 200: Whenever the user ID is valid and corresponds to an
        existing user.
    :status 404: Otherwise.

    **Example Response**:

    .. sourcecode:: json

      {
        "cpr_no": "1011101010",
        "name": "Hans Bruger",
        "uuid": "9917e91c-e3ee-41bf-9a60-b024c23b5fe3",
        "org": {
          "name": "Magenta ApS",
          "user_key": "Magenta ApS",
          "uuid": "8efbd074-ad2a-4e6a-afec-1d0b1891f566"
        }
      }

    '''
    c = common.get_connector()

    r = get_one_employee(c, id, full=True)

    if r:
        return flask.jsonify(r)
    else:
        raise exceptions.HTTPException(exceptions.ErrorCodes.E_USER_NOT_FOUND)


@blueprint.route('/e/<uuid:employee_uuid>/terminate', methods=['POST'])
def terminate_employee(employee_uuid):
    """Terminates an employee and all of his roles beginning at a
    specified date.

    .. :quickref: Employee; Terminate

    :statuscode 200: The termination succeeded.

    :param employee_uuid: The UUID of the employee to be terminated.

    :<json string to: When the termination should occur, as an ISO 8601 date.

    **Example Request**:

    .. sourcecode:: json

      {
        "validity": {
          "to": "2015-12-31"
        }
      }

    """
    date = util.get_valid_to(flask.request.get_json())

    # Org funks
    types = (
        mapping.ENGAGEMENT_KEY,
        mapping.ASSOCIATION_KEY,
        mapping.ROLE_KEY,
        mapping.LEAVE_KEY,
        mapping.MANAGER_KEY
    )

    c = lora.Connector(effective_date=date)

    for key in types:
        for obj in c.organisationfunktion.get_all(
            tilknyttedebrugere=employee_uuid,
            funktionsnavn=key
        ):
            c.organisationfunktion.update(
                common.inactivate_org_funktion_payload(
                    date,
                    "Afslut medarbejder"),
                obj[0])

    # Write a noop entry to the user, to be used for the history
    common.add_history_entry(c.bruger, employee_uuid, "Afslut medarbejder")

    # TODO:
    return flask.jsonify(employee_uuid), 200


@blueprint.route('/e/<uuid:employee_uuid>/history/', methods=['GET'])
def get_employee_history(employee_uuid):
    """
    Get the history of an employee

    .. :quickref: Employee; Get history

    :param employee_uuid: The UUID of the employee

    **Example response**:

    :<jsonarr string from: When the change is active from
    :<jsonarr string to: When the change is active to
    :<jsonarr string action: The action performed
    :<jsonarr string life_cycle_code: The type of action performed
    :<jsonarr string user_ref: A reference to the user who made the change

    .. sourcecode:: json

      [
        {
          "from": "2018-02-21T11:27:20.909206+01:00",
          "to": "infinity",
          "action": "Opret orlov",
          "life_cycle_code": "Rettet",
          "user_ref": "42c432e8-9c4a-11e6-9f62-873cf34a735f"
        },
        {
          "from": "2018-02-21T11:27:20.803682+01:00",
          "to": "2018-02-21T11:27:20.909206+01:00",
          "action": "Rediger engagement",
          "life_cycle_code": "Rettet",
          "user_ref": "42c432e8-9c4a-11e6-9f62-873cf34a735f"
        },
        {
          "from": "2018-02-21T11:27:20.619990+01:00",
          "to": "2018-02-21T11:27:20.803682+01:00",
          "action": null,
          "life_cycle_code": "Importeret",
          "user_ref": "42c432e8-9c4a-11e6-9f62-873cf34a735f"
        }
      ]

    """

    c = lora.Connector()
    user_registrations = c.bruger.get(uuid=employee_uuid,
                                      registreretfra='-infinity',
                                      registrerettil='infinity')

    if not user_registrations:
        raise exceptions.HTTPException(exceptions.ErrorCodes.E_USER_NOT_FOUND,
                                       employee_uuid=employee_uuid)

    history_entries = list(map(common.convert_reg_to_history,
                               user_registrations))

    return flask.jsonify(history_entries)


@blueprint.route('/e/create', methods=['POST'])
def create_employee():
    """Create a new employee

    .. :quickref: Employee; Create

    :statuscode 200: Creation succeeded.

    **Example Request**:

    :<json string name: The name of the employee
    :<json string cpr_no: The CPR no of the employee
    :<json string user_key: Short, unique key identifying the employee.
    :<json object org: The organisation with which the employee is associated
    :<json string uuid: An **optional** parameter, that will be used as the
      UUID for the employee.

    .. sourcecode:: json

      {
        "name": "Name Name",
        "cpr_no": "0101501234",
        "user_key": "1234",
        "org": {
          "uuid": "62ec821f-4179-4758-bfdf-134529d186e9"
        },
        "uuid": "f005a114-e5ef-484b-acfd-bff321b26e3f"
      }

    :returns: UUID of created employee

    """

    c = lora.Connector()

    req = flask.request.get_json()

    name = util.checked_get(req, mapping.NAME, "", required=True)
    org_uuid = util.get_mapping_uuid(req, mapping.ORG, required=True)
    cpr = util.checked_get(req, mapping.CPR_NO, "", required=False)
    userid = util.get_uuid(req, required=False)
    if not userid:
        userid = uuid.uuid4()

    try:
        valid_from = \
            util.get_cpr_birthdate(cpr) if cpr else util.NEGATIVE_INFINITY
    except ValueError as exc:
        raise exceptions.HTTPException(
            exceptions.ErrorCodes.V_CPR_NOT_VALID,
            cpr=cpr,
            cause=exc,
        )

    userids = c.bruger.fetch(
        tilknyttedepersoner="urn:dk:cpr:person:{}".format(cpr),
        tilhoerer=org_uuid
    )

    if userids and userid not in userids:
        raise exceptions.HTTPException(
            exceptions.ErrorCodes.V_EXISTING_CPR,
            cpr=cpr,
        )

    valid_to = util.POSITIVE_INFINITY

    # TODO: put something useful into the default user key
    bvn = util.checked_get(req, mapping.USER_KEY, str(uuid.uuid4()))

    user = common.create_bruger_payload(
        valid_from=valid_from,
        valid_to=valid_to,
        brugernavn=name,
        brugervendtnoegle=bvn,
        tilhoerer=org_uuid,
        cpr=cpr,
    )

    details = util.checked_get(req, 'details', [])

    decorated = _decorate_create_payloads(details, userid, valid_from,
                                          valid_to)
    # Validate the creation payloads
    validated_details = writing.process_requests(
        writing.CREATE_VALIDATION_HANDLERS,
        decorated)

    userid = c.bruger.create(user, uuid=userid)

    creation_uuids = writing.process_requests(writing.CREATION_HANDLERS,
                                              validated_details)

    return flask.jsonify([userid] + creation_uuids)


def _decorate_create_payloads(details, employee_uuid, valid_from, valid_to):
    decorated = copy.deepcopy(details)
    for detail in decorated:
        detail['person'] = {
            mapping.UUID: employee_uuid,
            mapping.VALID_FROM: valid_from,
            mapping.VALID_TO: valid_to,
            'future': True
        }

    return decorated
