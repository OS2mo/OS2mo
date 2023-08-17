---
title: Database
---

# Database

This document describes what you need to do to prepare a database for
usage by `mox`. Generally, there are 2 steps. The first requires a high
level of privileges and creates a user. The second is within the
database and can be done by the created user. The 2 following
subchapters reflect these two levels of privilege.

## Database, user and extensions initialization

`mox` requires a database and a user in that database.The user should have [all
privileges](https://www.postgresql.org/docs/11.7/sql-grant.html) on the
database. Furthermore, there should be a schema in the database called
*actual_state* that the user has authorization over. At
last, the search path should be set to *"actual_state,
public"*. Please refer to the reference script
`docker/postgres-initdb.d/10-init-db.sh`.

There is one more thing `mox` needs before it can work with the
database: **extensions**. The required extensions are *uuid-ossp*,
*btree_gist* and *pg_trgm* and they should be created with the schema
*actual_state*. Note that extensions can only be created by
a superuser (this is because extensions can run arbitrary code). Please
refer to the reference script
`docker/postgres-initdb.d/20-create-extensions.sh`

## Object initialization

With mox comes a utility called `initdb` that populates a Postgres
server database with all the necessary postgresql objects.

`initdb` is only intended to run succesfully against a database that has
been initialized as described in [Database, user and extensions initialization](./database.md#database-user-and-extensions-initialization)

To invoke `initdb`, run:

    python -m oio_rest initdb

Please also read `python -m oio_rest initdb --help`.
