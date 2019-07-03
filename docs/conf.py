#
# Copyright (c) Magenta ApS
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# OS2MO 2.0 documentation build configuration file, created by
# sphinx-quickstart on Wed Aug 23 09:52:25 2017.
#
# This file is execfile()d with the current directory set to its
# containing dir.
#
# Note that not all possible configuration values are present in this
# autogenerated file.
#
# All configuration values have a default; values that are commented out
# serve to show the default.

import json
import os
import sys
from unittest.mock import MagicMock

from jinja2 import Template

TOP_DIR = os.path.dirname(os.path.dirname(__file__))
BACKEND_DIR = os.path.join(TOP_DIR, 'backend')
FRONTEND_DIR = os.path.join(TOP_DIR, 'frontend')

DOCS_DIR = os.path.join(TOP_DIR, 'docs')
BLUEPRINTS_DIR = os.path.join(DOCS_DIR, 'blueprints')

os.environ['FLASK_ENV'] = 'docs'

#
# -- Generated files ------------------------------------------------------
#
sys.path.insert(0, BACKEND_DIR)


# -- General configuration ------------------------------------------------

# If your documentation needs a minimal Sphinx version, state it here.
#
# needs_sphinx = '1.0'

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.coverage',
    'sphinx.ext.viewcode',
    'sphinx.ext.githubpages',
    'sphinx.ext.doctest',
    'sphinx.ext.intersphinx',
    'sphinxcontrib.httpdomain',
    'sphinxcontrib.autohttp.flask',
    'sphinxcontrib.autohttp.flaskqref',
    'sphinxcontrib.apidoc',
    'sphinx_click.ext',
]

autodoc_default_flags = [
    # 'members',
    # 'undoc-members',
]

MOCK_MODULES = [
    'flask_session',
    'lxml',
    'lxml.etree',
    'service_person_stamdata_udvidet',
    'flask_saml_sso',
    'validators',

    'onelogin',
    'onelogin.saml2',
    'onelogin.saml2.auth',
    'onelogin.saml2.response',
    'onelogin.saml2.xml_utils',
    'onelogin.saml2.constants',
    'onelogin.saml2.idp_metadata_parser',
]
sys.modules.update({mod_name: MagicMock() for mod_name in MOCK_MODULES})


apidoc_module_dir = '../backend/mora'
apidoc_output_dir = 'backend'

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates', 'mora/templates']

# The suffix(es) of source filenames.
# You can specify multiple suffix as a list of string:
#
source_suffix = ['.rst', '.md']
# source_suffix = '.rst'

source_parsers = {
    '.md': 'recommonmark.parser.CommonMarkParser',
}

#
# References to other Sphinx documentation sites.
#
intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
    'werkzeug': ('http://werkzeug.pocoo.org/docs/', None),
    'flask': ('http://flask.pocoo.org/docs/', None),
    'mox': ('https://mox.readthedocs.io/en/latest', None),
}

primary_domain = 'py'


# The master toctree document.
master_doc = 'index'

# General information about the project.
project = 'OS2MO 2.0'
copyright = 'OS2 — Offentligt digitaliseringsfællesskab'
author = 'Magenta ApS'

# The version info for the project you're documenting, acts as replacement for
# |version| and |release|, also used in various other places throughout the
# built documents.
#

with open(os.path.join(FRONTEND_DIR, 'package.json')) as fp:
    # 'version' is the short X.Y version and 'release' is the full
    # version, including alpha/beta/rc tags.
    release = version = json.load(fp)['version']

# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
#
# This is also used if you do content translation via gettext catalogs.
# Usually you set "language" from the command line for these cases.
language = 'da_DK'

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This patterns also effect to html_static_path and html_extra_path
exclude_patterns = [
    'docs',
    '_build',
    'Thumbs.db',
    '.DS_Store',
    'venv*',
    'sandbox',
    'node_modules',
]

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# If true, `todo` and `todoList` produce output, else they produce nothing.
todo_include_todos = False


# -- Options for HTML output ----------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_rtd_theme"

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
#
html_theme_options = {
    # 'headerbg': "#002f5d",
    'logo_only': True,
}

html_show_sphinx = False
html_logo = 'graphics/logo.svg'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['static']

# Custom sidebar templates, must be a dictionary that maps document names
# to template names.
#
# This is required for the alabaster theme
# refs: http://alabaster.readthedocs.io/en/latest/installation.html#sidebars
html_sidebars = {
    '**': [
        'about.html',
        'navigation.html',
        'relations.html',  # needs 'show_related': True theme option to display
        'searchbox.html',
        'donate.html',
    ]
}


# -- Options for HTMLHelp output ------------------------------------------

# Output file base name for HTML help builder.
htmlhelp_basename = 'Os2modoc'


# -- Options for LaTeX output ---------------------------------------------

latex_elements = {
    # The paper size ('letterpaper' or 'a4paper').
    #
    'papersize': 'a4paper',

    # The font size ('10pt', '11pt' or '12pt').
    #
    # 'pointsize': '10pt',

    # Additional stuff for the LaTeX preamble.
    #
    # 'preamble': '',

    # Latex figure (float) alignment
    #
    # 'figure_align': 'htbp',
}

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
    (master_doc, 'mora.tex', 'OS2MO 2.0 Documentation',
     'Magenta ApS', 'manual'),
]


# -- Options for manual page output ---------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
    (master_doc, 'mora', 'OS2MO 2.0 Documentation',
     [author], 1)
]


# -- Options for Texinfo output -------------------------------------------

# Grouping the document tree into Texinfo files. List of tuples
# (source start file, target name, title, author,
#  dir menu entry, description, category)
texinfo_documents = [
    (
        master_doc, 'MORa', 'OS2MO 2.0 Documentation',
        author, 'OS2MO 2.0',
        'OS2MO 2.0 — MedarbejderOrganisation + LoRa, fuldstænding dokumentation',
        'Miscellaneous',
    ),
]
