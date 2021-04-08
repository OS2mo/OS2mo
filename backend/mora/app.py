# SPDX-FileCopyrightText: 2017-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0

import os
import typing

import flask
import flask_saml_sso
from flask_cors import CORS
import werkzeug
from werkzeug.middleware.proxy_fix import ProxyFix

import mora.async_util
from mora import __version__, log
from mora import health
from . import exceptions
from . import lora
from . import service
from . import settings
from . import util
from .api.v1 import read_orgfunk
from .auth import base
from .integrations import serviceplatformen
from . import triggers

basedir = os.path.dirname(__file__)
templatedir = os.path.join(basedir, 'templates')
distdir = os.path.join(basedir, '..', '..', 'frontend', 'dist')


def enable_cors(app):
    """Enable CORS if configured to do so."""
    if app.config.get("ENABLE_CORS", False):
        CORS(app)


def create_app(overrides: typing.Dict[str, typing.Any] = None):
    '''Create and return a Flask app instance for MORA.

    :param dict overrides: Settings to override prior to extension
                           instantiation.

    '''

    log.init()

    app = flask.Flask(__name__, root_path=distdir, template_folder=templatedir)

    app.config.update(settings.app_config)
    app.url_map.converters['uuid'] = util.StrUUIDConverter

    if overrides is not None:
        app.config.update(overrides)

    # Initialize SSO and Session
    flask_saml_sso.init_app(app)

    base.blueprint.before_request(flask_saml_sso.check_saml_authentication)
    app.register_blueprint(base.blueprint)
    app.register_blueprint(health.blueprint)
    app.register_blueprint(read_orgfunk.blueprint)

    for blueprint in service.blueprints:
        blueprint.before_request(flask_saml_sso.check_saml_authentication)
        app.register_blueprint(blueprint)

    @app.errorhandler(Exception)
    def handle_invalid_usage(error):
        """
        Handles errors in case an exception is raised.

        :param error: The error raised.
        :return: JSON describing the problem and the apropriate status code.
        """

        if not isinstance(error, werkzeug.routing.RoutingException):
            util.log_exception('unhandled exception')

        if not isinstance(error, werkzeug.exceptions.HTTPException):
            error = exceptions.HTTPException(
                description=str(error),
            )

        return error.get_response(flask.request.environ)

    @app.route("/version/")
    @mora.async_util.async_to_sync
    async def version():
        lora_version = await lora.get_version()
        return flask.jsonify({
            "mo_version": __version__,
            "lora_version": lora_version,
        })

    # We serve index.html and favicon.ico here. For the other static files,
    # Flask automatically adds a static view that takes a path relative to the
    # `flaskr/static` directory.

    @app.route("/")
    @app.route("/organisation/")
    @app.route("/organisation/<path:path>")
    @app.route("/medarbejder/")
    @app.route("/medarbejder/<path:path>")
    @app.route("/hjaelp/")
    @app.route("/organisationssammenkobling/")
    @app.route("/forespoergsler/")
    @app.route("/tidsmaskine/")
    def index(path=""):
        """Serve index.html on `/` and unknown paths.
        """
        return flask.send_file("index.html")

    @app.route("/favicon.ico")
    def favicon():
        """Serve favicon.ico on `/favicon.ico`.
        """
        return flask.send_file("favicon.ico")

    @app.route("/service/<path:path>")
    def no_such_endpoint(path=""):
        """Throw an error on unknown `/service/` endpoints.
        """
        exceptions.ErrorCodes.E_NO_SUCH_ENDPOINT()

    serviceplatformen.check_config(app)
    triggers.register(app)

    # Fix for incident: https://redmine.magenta-aps.dk/issues/35832
    # Respect the X-Forwarded-Proto scheme
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=0)
    enable_cors(app)

    return app
