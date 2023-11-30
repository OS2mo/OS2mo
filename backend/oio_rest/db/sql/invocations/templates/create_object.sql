-- SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
-- SPDX-License-Identifier: MPL-2.0

SELECT * from as_create_or_import_{{ class_name|lower }}(
    {{registration}},
    {% if uuid != None %} '{{uuid}}' :: uuid {% else %}null{% endif %}
);
