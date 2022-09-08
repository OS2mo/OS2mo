#!/bin/sh

# SPDX-FileCopyrightText: 2020 Magenta ApS
# SPDX-License-Identifier: MPL-2.0

set -e

# If DISABLE_ALEMBIC is unset or false, run alembic
if [ -z "$DISABLE_ALEMBIC" ] || [ "$DISABLE_ALEMBIC" = "false" ]; then
    # Check if 'ENABLE_INTERNAL_LORA' is "truthy" ("y", "yes", "true", "1", etc.)
    if [ "$(python3 -c "from os import environ; from distutils.util import strtobool; print(strtobool(environ['ENABLE_INTERNAL_LORA']))")" = 1 ]; then
        python3 -m oio_rest initdb --wait 30
    else
        echo "ENABLE_INTERNAL_LORA is $ENABLE_INTERNAL_LORA, not running 'initdb'"
    fi
elif [ "$DISABLE_ALEMBIC" = "true" ]; then
    echo "Alembic disabled by switch"
else
    echo "UNKNOWN DISABLE_ALEMBIC value: $DISABLE_ALEMBIC"
    exit 1
fi
