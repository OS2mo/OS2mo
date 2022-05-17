---
title: Installation from source
---

This page describes the installation of OS2MO,
`LoRa <mox:index>`{.interpreted-text role="doc"} and Postgres on Ubuntu
18.04 without Docker. If you want a Docker based development
environment, see `dev-env`{.interpreted-text role="ref"}.

Postgres
========

Both OS2MO and LoRa need access to a database engine. LoRa need it for
the main storage, both LoRa and OS2MO share the
`session database <mox:user/auth>`{.interpreted-text role="doc"} and
OS2MO needs it for `user_configuration`{.interpreted-text role="ref"}.
The three different databases do not need to be on the same database
engine, but in this guide we will do so.

<!-- ::: {.sidebar} -->
**Reference**

[postgres-os2mo](https://hub.docker.com/r/magentaaps/postgres-os2mo)
Docker image and `LoRa database <mox:database>`{.interpreted-text
role="ref"}.
:::

The following use the default users, passwords and database names. They
should oblivious be changed in a production environment. Both here and
in the corresponding settings for LoRa and MO.

To install postgres and create the necessary databases and users:

``` {.bash}
sudo apt-get update
sudo apt-get install -y postgresql
# mox db
sudo -u postgres psql -v ON_ERROR_STOP=1 <<-EOSQL1
     create user mox with encrypted password 'mox';
     create database mox;
     grant all privileges on database mox to mox;
     alter database mox set search_path to actual_state, public;
     alter database mox set datestyle to 'ISO, YMD';
     alter database mox set intervalstyle to 'sql_standard';
     \connect mox
     create schema actual_state authorization mox;
     create extension if not exists "uuid-ossp" with schema actual_state;
     create extension if not exists "btree_gist" with schema actual_state;
     create extension if not exists "pg_trgm" with schema actual_state;
EOSQL1
# mora conf db
sudo -u postgres psql -v ON_ERROR_STOP=1 <<-EOSQL2
     create user mora with encrypted password 'mora';
     create database mora owner mora;
     grant all privileges on database mora to mora;
EOSQL2
# sessions db
sudo -u postgres psql -v ON_ERROR_STOP=1 <<-EOSQL3
     create user sessions with encrypted password 'sessions';
     create database sessions owner sessions;
     grant all privileges on database sessions to sessions;
EOSQL3
```

For an explanation of the setup of the mox database see `LoRa database
<mox:database>`{.interpreted-text role="ref"}.

System packages
===============

<!-- ::: {.sidebar} -->
**Reference**

[Nodejs
install](https://github.com/nodesource/distributions/blob/master/README.md#debinstall)
and [Yarn
install](https://classic.yarnpkg.com/en/docs/install/#debian-stable).
:::

The following will install node, python and LoRas and OS2MOs one system
dependency.

``` {.bash}
curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
sudo apt-get install -y nodejs yarn python3-dev python3-venv libxmlsec1-dev
```

LoRA
====

<!-- ::: {.sidebar} -->
**Reference**

LoRa `installation <mox:user/installation>`{.interpreted-text
role="doc"} and `settings
<mox:Settings>`{.interpreted-text role="ref"}.
:::

The following will clone the LoRa repo, create a `virtual environment
<python:tut-venv>`{.interpreted-text role="ref"} and install the LoRa
python requirements.

``` {.bash}
git clone https://github.com/magenta-aps/mox.git
cd mox
# git checkout development
python3 -m venv venv
source venv/bin/activate
pip install -U pip
cd oio_rest
pip install -r requirements.txt
pip install .
```

Create a settings file, `~/mox/user-settings.toml`{.interpreted-text
role="file"}, with the following content. More options are available
here: `LoRa settings <mox:Settings>`{.interpreted-text role="ref"}.

``` {.toml}
[db_extensions]
path = "oio_rest/oio_rest/db_extensions/mo-01.json"
```

Finally, tell LoRa to use the settings file and initialize the mox
database.

``` {.bash}
export MOX_USER_CONFIG_PATH=~/mox/user-settings.toml
python3 -m oio_rest initdb
deactivate && cd ~
```

OS2MO
=====

The following will clone the OS2MO repo, install frontend dependencies,
build the frontend, create a
`virtual environment <python:tut-venv>`{.interpreted-text role="ref"}
and install the OS2MO python requirements.

``` {.bash}
git clone https://github.com/OS2mo/os2mo.git
cd os2mo
# git checkout development
cd frontend
yarn install
yarn build
cd ..
python3 -m venv venv
source venv/bin/activate
pip install -U pip
cd backend
pip install -r requirements.txt
pip install .
```

Create a settings file, `~/os2mo/user-settings.toml`{.interpreted-text
role="file"}, with the following content. More options are available
here: `Settings`{.interpreted-text role="ref"}.

``` {.toml}
dummy_mode = true
```

Finally, set the configuration file and flask app environment variables
and initialize the configuration database.

``` {.bash}
export OS2MO_USER_CONFIG_PATH=~/os2mo/user-settings.toml
export FLASK_APP=mora.app:create_app

python3 -m mora.cli initdb
deactivate && cd ~
```

Starting the services
=====================

The services should now be ready to start. Run the following in two
different terminals:

``` {.bash}
cd mox
source venv/bin/activate
export MOX_USER_CONFIG_PATH=~/mox/user-settings.toml
python3 -m oio_rest run -h 0.0.0.0 -p 8080
```

``` {.bash}
cd os2mo
source venv/bin/activate
cd backend
export OS2MO_USER_CONFIG_PATH=~/os2mo/user-settings.toml
python3 -m mora.cli run -h 0.0.0.0 -p 5000
```

You can now access OS2MO on <http://localhost:5000>.
