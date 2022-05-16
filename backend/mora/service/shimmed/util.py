#!/usr/bin/env python3
# --------------------------------------------------------------------------------------
# SPDX-FileCopyrightText: 2021 - 2022 Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
# --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------------------
from collections.abc import Iterable
from typing import Any

# --------------------------------------------------------------------------------------
# Code
# --------------------------------------------------------------------------------------


def filter_data(data: Iterable, key: str, value: Any) -> filter:
    return filter(lambda obj: obj[key] == value, data)
