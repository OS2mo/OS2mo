# SPDX-FileCopyrightText: 2017-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0

'''
Authentication
--------------

This section describes how to authenticate with MO. The API is work in
progress.

'''
import os

from fastapi import APIRouter

__all__ = (
    'get_user',
)

basedir = os.path.dirname(__file__)

router = APIRouter()


@router.get('/user')
def get_user():
    """
    Get the currently logged in user

    .. :quickref: Authentication; Get user

    :return: The username of the user who is currently logged in.
    """
    #
    #    if not flask.current_app.config['SAML_USERNAME_FROM_NAMEID']:
    #        username_attr = flask.current_app.config['SAML_USERNAME_ATTR']
    #        try:
    #            username = flask_saml_sso.get_session_attributes()[
    #                username_attr][0]
    #        except (AttributeError, LookupError, TypeError):
    #            flask.current_app.logger.exception(
    #                'Unable to get username from session attribute')
    #            username = None
    #    else:
    #        username = flask_saml_sso.get_session_name_id()
    #
    #    return flask.jsonify(username)
    return "dummy"
