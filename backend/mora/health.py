# SPDX-FileCopyrightText: 2019-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0

import logging

import flask
import requests
from functools import wraps
from pika.exceptions import AMQPError
from requests.exceptions import RequestException

from flask_saml_sso.health import (
    session_database as session_database_health,
    idp as idp_health,
)

import mora.async_util
from mora import lora, util, conf_db
from mora.exceptions import HTTPException
from mora.settings import config
from mora.triggers.internal import amqp_trigger

blueprint = flask.Blueprint(
    "health", __name__, static_url_path="", url_prefix="/health"
)

logger = logging.getLogger(__name__)

HEALTH_ENDPOINTS = []


def register_health_endpoint(fn):
    HEALTH_ENDPOINTS.append(fn)
    return fn


@register_health_endpoint
def amqp():
    """Check if AMQP connection is open.

    Return `True` if open. `False` if not open or an error occurs.
    `None` if AMQP support is disabled.
    """
    if not config["amqp"]["enable"]:
        return None
    connection = amqp_trigger.get_connection()

    try:
        conn = connection.get("conn")
    except AMQPError as e:
        logger.exception(f"AMQP health check error {e}")
        return False

    if not conn:
        logger.critical("AMQP connection not found")
        return False

    if not conn.is_open:
        logger.critical("AMQP connection is closed")
        return False

    return True


@register_health_endpoint
def oio_rest():
    """
    Check if the configured oio_rest can be reached
    :return: True if reachable. False if not
    """
    url = config["lora"]["url"] + "site-map"
    try:
        r = requests.get(url)

        if r.status_code == 200:
            return True
        else:
            logger.critical("oio_rest returned status code {}".format(r.status_code))
            return False
    except RequestException as e:
        logger.exception("oio_rest returned: {}".format(e))
        return False


@register_health_endpoint
def session_database():
    """
    Check if the session database can be reached
    :return: True if reachable. False if not. None if SAML SSO not enabled.
    """
    if not config["saml_sso"]["enable"]:
        return None

    return session_database_health(flask.current_app)


@register_health_endpoint
def configuration_database():
    """
    Check if configuration database is reachable and initialized with default data
    :return: True if reachable and initialized. False if not.
    """
    healthy, msg = conf_db.health_check()
    if not healthy:
        logger.critical(msg)
    return healthy


@register_health_endpoint
@mora.async_util.async_to_sync  # needs to be sync, flask blueprint endpoint
async def dataset():
    """
    Check if LoRa contains data. We check this by determining if an organisation
    exists in the system
    :return: True if data. False if not.
    """
    c = lora.Connector(virkningfra="-infinity", virkningtil="infinity")
    try:
        org = await c.organisation.fetch(bvn="%")
        if not org:
            logger.critical("No dataset found in LoRa")
            return False
    except HTTPException as e:
        logger.exception(
            "Fetching data from oio_rest responded with status code {}".format(e.code)
        )
        return False
    except RequestException as e:
        logger.exception("Fetching data from oio_rest responded with {}".format(e))
        return False
    return True


@register_health_endpoint
def dar():
    """
    Check whether DAR can be reached
    :return: True if reachable. False if not.
    """
    url = "https://dawa.aws.dk/autocomplete"
    try:
        r = requests.get(url)
        if r.status_code == 200:
            return True
        else:
            return False
    except RequestException:
        return False


@register_health_endpoint
def idp():
    """Check whether the IdP for SAML SSO can be reached.

    Works by trying to reach configured IdP metadata endpoint.

    Return `True` if reachable. `False` if not. `None` if SAML SSO is
    not enabled, or if metadata is configured to come from a file.
    """
    if not config["saml_sso"]["enable"] or config["saml_sso"]["idp_metadata_file"]:
        return None

    return idp_health(flask.current_app)


@blueprint.route("/")
@util.restrictargs()
def root():
    health = {func.__name__: func() for func in HEALTH_ENDPOINTS}
    return flask.jsonify(health)


def register_routes():
    def wrap_output(function):
        @wraps(function)
        def wrapper():
            return flask.jsonify(function())

        return wrapper

    for func in HEALTH_ENDPOINTS:
        url = "/" + func.__name__
        restricted_args_fn = util.restrictargs()(func)
        blueprint.add_url_rule(url, func.__name__, wrap_output(restricted_args_fn))


register_routes()
