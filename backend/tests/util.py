# SPDX-FileCopyrightText: 2017-2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0
import contextlib
import copy
import json
import os
import re
from copy import deepcopy
from typing import Union
from unittest.mock import MagicMock
from unittest.mock import patch
from urllib.parse import parse_qsl

import aioresponses
import jinja2
import requests
import requests_mock
from fastapi import APIRouter
from fastapi.encoders import jsonable_encoder
from yarl import URL

from mora import conf_db, lora, settings
from mora.exceptions import ImproperlyConfigured

TESTS_DIR = os.path.dirname(__file__)
BASE_DIR = os.path.dirname(TESTS_DIR)
FIXTURE_DIR = os.path.join(TESTS_DIR, "fixtures")
MOCKING_DIR = os.path.join(TESTS_DIR, "mocking")

jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(
        searchpath=FIXTURE_DIR,
    ),
)


def _mox_testing_api(method):
    """Calls MOX `testing/<method>` REST API."""
    r = requests.get(settings.LORA_URL + "testing/" + method)
    if r.status_code == 404:
        raise ImproperlyConfigured("LORAs testing API returned 404. Is it enabled?")
    r.raise_for_status()


def jsonfile_to_dict(path):
    """
    Reads JSON from resources folder and converts to Python dictionary
    :param path: path to json resource
    :return: dictionary corresponding to the resource JSON
    """
    try:
        with open(os.path.join(BASE_DIR, path)) as f:
            return json.load(f)
    except json.JSONDecodeError:
        raise ValueError("failed to decode " + path)


def get_fixture(fixture_name, **kwargs):
    if not kwargs:
        return jsonfile_to_dict(os.path.join(FIXTURE_DIR, fixture_name))
    else:
        return json.loads(
            jinja_env.get_template(fixture_name).render(**kwargs),
        )


def get_mock_data(mock_name):
    return jsonfile_to_dict(os.path.join(MOCKING_DIR, mock_name))


async def load_fixture(path, fixture_name, uuid=None, **kwargs):
    """Load a fixture, i.e. a JSON file with the 'fixtures' directory,
    into LoRA at the given path & UUID.

    """
    scope = lora.Scope(lora.Connector(), path)
    r = await scope.create(get_fixture(fixture_name, **kwargs), uuid)
    return r


async def load_sample_structures(minimal=False):
    """Inject our test data into LoRA."""
    orgid = "456362c4-0ee4-4e5e-a72c-751239745e62"

    fixtures = [
        (
            "organisation/organisation",
            "create_organisation_AU.json",
            orgid,
        )
    ]

    units = {
        # L1
        "root": "2874e1dc-85e6-4269-823a-e1125484dfd3",
    }

    classes = {
        # org_unit_type
        "afdeling": "32547559-cfc1-4d97-94c6-70b192eff825",
    }

    facets = {
        "association_type": "ef71fe9c-7901-48e2-86d8-84116e210202",
        "employee_address_type": "baddc4eb-406e-4c6b-8229-17e4a21d3550",
        "engagement_job_function": "1a6045a2-7a8e-4916-ab27-b2402e64f2be",
        "engagement_association_type": "c8a8935e-6f0e-4ca3-b1ea-79556f9b6317",
        "engagement_type": "3e702dd1-4103-4116-bb2d-b150aebe807d",
        "kle_number": "27935dbb-c173-4116-a4b5-75022315749d",
        "kle_aspect": "8a29b2cf-ef98-46f4-9794-0e39354d6ddf",
        "leave_type": "99a9d0ab-615e-4e99-8a43-bc9d3cea8438",
        "manager_level": "d56f174d-c45d-4b55-bdc6-c57bf68238b9",
        "manager_type": "a22f8575-89b4-480b-a7ba-b3f1372e25a4",
        "org_unit_address_type": "3c44e5d2-7fef-4448-9bf6-449bf414ec49",
        "org_unit_level": "77c39616-dd98-4cf5-87fb-cdb9f3a0e455",
        "org_unit_type": "fc917e7c-fc3b-47c2-8aa5-a0383342a280",
        "primary_type": "1f6f34d8-d065-4bb7-9af0-738d25dc0fbf",
        "responsibility": "452e1dd0-658b-477a-8dd8-efba105c06d6",
        "role_type": "68ba77bc-4d57-43e2-9c24-0c9eda5fddc7",
        "time_planning": "c4ad4c87-28a8-4d5c-afeb-b59de9c9f549",
        "visibility": "c9f103c7-3d53-47c0-93bf-ccb34d044a3f",
    }

    # TODO: add classifications, etc.

    functions = {
        "engagement_andersand": "d000591f-8705-4324-897a-075e3623f37b",
        "engagement_eriksmidthansen": "d3028e2e-1d7a-48c1-ae01-d4c64e64bbab",
        "engagement_eriksmidthansen_sekundaer": "301a906b-ef51-4d5c-"
        "9c77-386fb8410459",
        "tilknytning": "c2153d5d-4a2b-492d-a18c-c498f7bb6221",
        "rolle": "1b20d0b9-96a0-42a6-b196-293bb86e62e8",
        "orlov_andersand": "b807628c-030c-4f5f-a438-de41c1f26ba5",
        "leder": "05609702-977f-4869-9fb4-50ad74c6999a",
        "itsystem_user": "aaa8c495-d7d4-4af1-b33a-f4cb27b82c66",
        "itsystem_unit": "cd4dcccb-5bf7-4c6b-9e1a-f6ebb193e276",
        "tilknyttetenhed_hist": "daa77a4d-6500-483d-b099-2c2eb7fa7a76",
        "tilknyttetenhed_hum": "5c68402c-2a8d-4776-9237-16349fc72648",
        "kle": "4bee0127-a3a3-419a-8bcc-d1b81d21c5b5",
    }

    users = {
        "andersand": "53181ed2-f1de-4c4a-a8fd-ab358c2c454a",
        "fedtmule": "6ee24785-ee9a-4502-81c2-7697009c9053",
        "lis_jensen": "7626ad64-327d-481f-8b32-36c78eb12f8c",
        "erik_smidt_hansen": "236e0a78-11a0-4ed9-8545-6286bb8611c7",
    }

    itsystems = {
        "ad": "59c135c9-2b15-41cc-97c8-b5dff7180beb",
        "lora": "0872fb72-926d-4c5c-a063-ff800b8ee697",
        "sap": "14466fb0-f9de-439c-a6c2-b3262c367da7",
    }

    if not minimal:
        units.update(
            {
                # L2
                "hum": "9d07123e-47ac-4a9a-88c8-da82e3a4bc9e",
                # L3
                "fil": "85715fc7-925d-401b-822d-467eb4b163b6",
                # L2
                "samf": "b688513d-11f7-4efc-b679-ab082a2055d0",
                "social_og_sundhed": "68c5d78e-ae26-441f-a143-0103eca8b62a",
                "skole_og_børn": "dad7d0ad-c7a9-4a94-969d-464337e31fec",
                # L3
                "it_sup": "fa2e23c9-860a-4c90-bcc6-2c0721869a25",
                # L1
                "løn": "b1f69701-86d8-496e-a3f1-ccef18ac1958",
                # L2
                "social_og_sundhed_løn": "5942ce50-2be8-476f-914b-6769a888a7c8",
                "hist": "da77153e-30f3-4dc2-a611-ee912a28d8aa",
                "frem": "04c78fc2-72d2-4d02-b55f-807af19eac48",
            }
        )

        classes.update(
            {
                # org_unit_type
                "fakultet": "4311e351-6a3c-4e7e-ae60-8a3b2938fbd6",
                "institut": "ca76a441-6226-404f-88a9-31e02e420e52",
                # association_type
                "medlem": "62ec821f-4179-4758-bfdf-134529d186e9",
                "projektleder": "8eea787c-c2c7-46ca-bd84-2dd50f47801e",
                "teammedarbejder": "45751985-321f-4d4f-ae16-847f0a633360",
                # engagement_job_function
                "specialist": "890d4ff0-b453-4900-b79b-dbb461eda3ee",
                "skolepsykolog": "07cea156-1aaf-4c89-bf1b-8e721f704e22",
                "bogopsaetter": "f42dd694-f1fd-42a6-8a97-38777b73adc4",
                # engagement_type
                "ansat": "06f95678-166a-455a-a2ab-121a8d92ea23",
                # employee_address_type
                "bruger_adresse": "4e337d8e-1fd2-4449-8110-e0c8a22958ed",
                "bruger_email": "c78eb6f7-8a9e-40b3-ac80-36b9f371c3e0",
                "bruger_telefon": "cbadfa0f-ce4f-40b9-86a0-2e85d8961f5d",
                # org_unit_address_type
                "org_unit_adresse": "28d71012-2919-4b67-a2f0-7b59ed52561e",
                "org_unit_ean": "e34d4426-9845-4c72-b31e-709be85d6fa2",
                "org_unit_email": "73360db1-bad3-4167-ac73-8d827c0c8751",
                "org_unit_telefon": "1d1d3711-5af4-4084-99b3-df2b8752fdec",
                "org_unit_contactopenhours": "e8ea1a09-d3d4-4203-bfe9-d9a2da100f3b",
                # org_unit_level
                "org_unit_level_10": "0f015b67-f250-43bb-9160-043ec19fad48",
                # visibility
                "public": "f63ad763-0e53-4972-a6a9-63b42a0f8cb7",
                # primary_level
                "primaer": "89b6cef8-3d03-49ac-816f-f7530b383411",
                "sekundaer": "2f16d140-d743-4c9f-9e0e-361da91a06f6",
                # role_type
                "tillidsrepraesentant": "0fa6073f-32c0-4f82-865f-adb622ca0b04",
                # manager_type
                "direktoer": "0d72900a-22a4-4390-a01e-fd65d0e0999d",
                # manager_level
                "niveau1": "3c791935-2cfa-46b5-a12e-66f7f54e70fe",
                "niveau3": "991915c0-f4f4-4337-95fa-dbeb9da13247",
                # responsibility
                "beredskabsledelse": "93ea44f9-127c-4465-a34c-77d149e3e928",
                # leave_type
                "barselsorlov": "bf65769c-5227-49b4-97c5-642cfbe41aa1",
                # time_planning
                "tjenestetid": "ebce5c35-4e30-4ba8-9a08-c34592650b04",
                # kle_aspect
                "kle_ansvarlig": "9016d80a-c6d2-4fb4-83f1-87ecc23ab062",
                "kle_indsigt": "fdbdb18f-5a28-4414-bc43-d5c2b70c0510",
                "kle_udfoerende": "f9748c65-3354-4682-a035-042c534c6b4e",
                # kle_number
                "kle_number": "d7c12965-6207-4c82-88b8-68dbf6667492",
                # engagement_association_type
                "ea_k1": "5695e331-d837-473f-9b00-6f528fbd23f6",
                "ea_k2": "51cc63b8-d8d1-4b74-95df-7c105c9c88dd",
            }
        )

        functions.update(
            {
                "email_andersand": "fba61e38-b553-47cc-94bf-8c7c3c2a6887",
                "email_fedtmule": "64ea02e2-8469-4c54-a523-3d46729e86a7",
                "adresse_fedtmule": "cd6008bc-1ad2-4272-bc1c-d349ef733f52",
                "adresse_root": "414044e0-fe5f-4f82-be20-1e107ad50e80",
                "adresse_hum": "e1a9cede-8c9b-4367-b628-113834361871",
                "tlf_hum": "55848eca-4e9e-4f30-954b-78d55eec0473",
                "ean_hum": "a0fe7d43-1e0d-4232-a220-87098024b34d",
            }
        )

    for facetkey, facetid in facets.items():
        fixtures.append(
            (
                "klassifikation/facet",
                "create_facet_{}.json".format(facetkey),
                facetid,
            )
        )

    for classkey, classid in classes.items():
        fixtures.append(
            (
                "klassifikation/klasse",
                "create_klasse_{}.json".format(classkey),
                classid,
            )
        )

    for unitkey, unitid in units.items():
        fixtures.append(
            (
                "organisation/organisationenhed",
                "create_organisationenhed_{}.json".format(unitkey),
                unitid,
            )
        )

    for funckey, funcid in functions.items():
        fixtures.append(
            (
                "organisation/organisationfunktion",
                "create_organisationfunktion_{}.json".format(funckey),
                funcid,
            )
        )

    for userkey, userid in users.items():
        fixtures.append(
            (
                "organisation/bruger",
                "create_bruger_{}.json".format(userkey),
                userid,
            )
        )

    for itsystemkey, itsystemid in itsystems.items():
        fixtures.append(
            (
                "organisation/itsystem",
                "create_itsystem_{}.json".format(itsystemkey),
                itsystemid,
            )
        )

    for path, fixture_name, uuid in fixtures:
        await load_fixture(path, fixture_name, uuid)


def setup_test_routing(app):
    """
    Returns an app with testing API for e2e-test enabled. It is a superset
    to `mora.app.create_app()`.

    """
    testing_router = APIRouter()

    @testing_router.get("/testing/testcafe-db-setup")
    async def _testcafe_db_setup():
        _mox_testing_api("db-setup")
        await load_sample_structures()
        load_sample_confdb()
        return jsonable_encoder({"testcafe-db-setup": True})

    @testing_router.get("/testing/testcafe-db-teardown")
    def _testcafe_db_teardown():
        _mox_testing_api("db-teardown")
        return jsonable_encoder({"testcafe-db-teardown": True})

    app.include_router(testing_router)

    return app


def override_lora_url(lora_url="http://mox/"):
    return patch("mora.settings.LORA_URL", lora_url)


@contextlib.contextmanager
def override_config(overrides: dict):
    original = copy.deepcopy(settings.config)

    settings.update_dict(settings.config, overrides)
    try:
        yield
    finally:
        settings.update_dict(settings.config, original)


@contextlib.contextmanager
def override_app_config(**overrides):
    originals = {}

    for k, v in overrides.items():
        originals[k] = settings.config[k]
        settings.config[k] = v

    yield

    settings.config.update(overrides)


@contextlib.contextmanager
def patch_query_args(query_args=None):
    if not query_args:
        query_args = dict()
    with patch("mora.util.context", new={"query_args": query_args}):
        yield


class mock(requests_mock.Mocker):
    """Decorator for running a function under requests_mock, with the
    given mocking fixture loaded, and optionally overriding the LORA
    URL to a fixed location.

    """

    def __init__(self, names=None, allow_mox=False, **kwargs):
        super().__init__(**kwargs)

        self.__names = names
        self.__allow_mox = allow_mox
        self.__kwargs = kwargs

        if names:
            if not isinstance(names, (list, tuple)):
                names = [names]

            # inject the fixture; note that complete_qs is
            # important: without it, a URL need only match *some*
            # of the query parameters passed, and that's quite
            # obnoxious if requests only differ by them
            for name in names:
                for url, value in get_mock_data(name).items():
                    self.get(url, json=value, complete_qs=True)

        if not allow_mox:
            self.__overrider = override_lora_url()
        else:
            self.__overrider = None
            self.register_uri(
                requests_mock.ANY,
                re.compile("^{}/.*".format(settings.LORA_URL.rstrip("/"))),
                real_http=True,
            )

    def copy(self):
        """Returns an exact copy of current mock"""
        return mock(self.__names, self.__allow_mox, **self.__kwargs)

    def start(self):
        if self.__overrider:
            self.__overrider.__enter__()

        super().start()

    def stop(self):
        super().stop()

        if self.__overrider:
            self.__overrider.__exit__(None, None, None)


class MockAioresponses(aioresponses.aioresponses):
    def __init__(self, names=None, override_lora=True, **kwargs):
        self.__overrider = override_lora_url()
        self.__names = names
        self.__kwargs = kwargs
        self.__override_lora = override_lora
        self.__names_need_init = True
        super().__init__(**kwargs)

    def __enter__(self):
        if self.__override_lora:
            self.__overrider.__enter__()

        ret = super().__enter__()
        if self.__names_need_init:  # lazy init, need to wait for __enter__
            self.__names_need_init = False
            if self.__names:
                if not isinstance(self.__names, (list, tuple)):
                    self.__names = [self.__names]

                # inject the fixture
                for name in self.__names:
                    for url, value in get_mock_data(name).items():
                        encoded_url = URL(url, encoded=True)
                        self.get(encoded_url, payload=value)

        return ret

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.__override_lora:
            self.__overrider.__exit__(None, None, None)
        return super().__exit__(exc_type, exc_val, exc_tb)


def modified_normalize_url(url: Union[URL, str]) -> URL:
    """Normalize url to make comparisons."""
    url = URL(url)
    return url.with_query(sorted(parse_qsl(url.query_string)))


aioresponses.core.normalize_url = modified_normalize_url


class CopyingMock(MagicMock):
    """MagicMock that refers to its arguments by value instead of by reference.

    Workaround for mutable mock arguments and to avoid the following:

    >>> from mock import MagicMock
    >>> b = MagicMock()
    >>> a = {}
    >>> b(a)
    <MagicMock name='mock()' id='140710831830928'>
    >>> b.assert_called_with({})

    Good so far, but then this happens:

    >>> a['b'] = 'c'
    >>> b.assert_called_with({})
    Expected: mock({})
    Actual: mock({'b': 'c'})

    With CopyingMock we do not have `a` by reference, but by value instead, and
    thus it works 'as you would expect'.

    See: https://docs.python.org/3/library/unittest.mock-examples.html under
    "Coping with mutable arguments" for further details and the source of this code.
    """

    def __call__(self, /, *args, **kwargs):
        args = deepcopy(args)
        kwargs = deepcopy(kwargs)
        return super().__call__(*args, **kwargs)


def load_sample_confdb():
    """Ensure MO configuration has all feature flags turned on during
    end-to-end tests.

    Used during TestCafe test runs.
    """

    # Base sample configuration
    configuration = {
        # comma-separated list of UUIDs
        "substitute_roles": "",
        # comma-separated list of UUIDs
        "association_dynamic_facets": "",
        # comma-separated list of labels
        "extension_field_ui_labels": "",
    }

    # Names of all feature flags which should be turned on during test
    feature_flags = {
        "inherit_manager",
        "show_cpr_no",
        "show_engagement_hyperlink",
        "show_kle",
        "show_level",
        "show_location",
        "show_org_unit_button",
        "show_primary_association",
        "show_primary_engagement",
        "show_roles",
        "show_time_planning",
        "show_user_key",
        "show_user_key_in_search",
    }

    # Update configuration, setting all feature flags to "True"
    configuration.update(dict.fromkeys(feature_flags, "True"))

    # Update `orgunit_settings` table in `mora` database
    conf_db.set_configuration({"org_units": configuration})

    return configuration
