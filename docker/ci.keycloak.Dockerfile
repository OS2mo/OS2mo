# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0

# This Dockerfile is only used for running the test suite,
# i.e. the unsecure passwords are not important

FROM quay.io/keycloak/keycloak:21.1.1

ENV KEYCLOAK_USER=admin
ENV KEYCLOAK_PASSWORD=admin
ENV KEYCLOAK_IMPORT="/srv/keycloak-realm.json"

COPY ./keycloak-realm.json /srv/keycloak-realm.json

CMD [\
  # The -b flag is important. It is the default CMD from the docker image. It
  # is passed to keycloak's standalone.sh. If it is not present, the service
  # will only bind to a single network interface. If there are multiple
  # interfaces, it appears to choose an interface at random, leading to subtle
  # breaking when the container is restarted and the interface on the
  # docker-compose network is not chosen.
  "-b", "0.0.0.0",\
  "-Dkeycloak.migration.action=import",\
  "-Dkeycloak.migration.provider=singleFile",\
  "-Dkeycloak.migration.file=/srv/keycloak-realm.json"\
]
