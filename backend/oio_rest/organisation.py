# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from .oio_base import OIORestObject
from .oio_base import OIOStandardHierarchy


class Bruger(OIORestObject):
    """
    Implement a Bruger  - manage access to database layer from the API.
    """

    pass


class ItSystem(OIORestObject):
    """
    Implement an ItSystem  - manage access to database from the API.
    """

    pass


class Organisation(OIORestObject):
    """
    Implement an Organisation  - manage access to database from the API.
    """

    pass


class OrganisationEnhed(OIORestObject):
    """
    Implement an OrganisationEnhed - manage access to database from the API.
    """

    pass


class OrganisationFunktion(OIORestObject):
    """
    Implement an OrganisationFunktion.
    """

    pass


class OrganisationsHierarki(OIOStandardHierarchy):
    """Implement the Organisation Standard."""

    _name = "Organisation"
    _classes = [
        Bruger,
        ItSystem,
        Organisation,
        OrganisationEnhed,
        OrganisationFunktion,
    ]
