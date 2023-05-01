# SPDX-FileCopyrightText: Magenta ApS <https://magenta.dk>
# SPDX-License-Identifier: MPL-2.0
from contextlib import suppress
from datetime import datetime
from functools import lru_cache
from uuid import UUID

from sqlalchemy import Column
from sqlalchemy import create_engine
from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import LargeBinary
from sqlalchemy import String
from sqlalchemy import update
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
from structlog import get_logger

from mora import config

logger = get_logger()

Base = declarative_base()


class SessionModel(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)
    session_id = Column(String(255), unique=True)
    data = Column(LargeBinary)
    expiry = Column(DateTime)

    def __init__(self, session_id, data, expiry):
        self.session_id = session_id
        self.data = data
        self.expiry = expiry

    def __repr__(self):
        return "<Session data %s>" % self.data


def _get_connection_url():
    settings = config.get_settings()
    dbname = settings.session_db_name
    user = settings.session_db_user
    password = settings.session_db_password
    host = settings.session_db_host
    port = settings.session_db_port
    connection_url = "postgresql+psycopg2://"
    connection_url += str(user) + ":" + str(password)
    connection_url += "@" + str(host) + ":" + str(port)
    connection_url += "/" + str(dbname)
    return connection_url


@lru_cache
def _get_engine():
    connection_url = _get_connection_url()
    logger.debug("Open connection to database")
    try:
        # Create exactly one database connection per MO worker process.
        # In case this worker process has already created a database connection, reuse
        # that connection.
        engine = create_engine(
            connection_url,
            execution_options={"isolation_level": "AUTOCOMMIT"},
            pool_size=1,
            max_overflow=0,
        )
        return engine
    except Exception:
        logger.error("Database connection error")
        raise


def validate_session(session_id: str) -> bool:
    """Validate the existence of a session from legacy session table"""
    settings = config.get_settings()
    if settings.os2mo_legacy_sessions is not None:
        with suppress(ValueError):
            return UUID(session_id) in settings.os2mo_legacy_sessions
        return False

    store_id = f"session:{session_id}"
    engine = _get_engine()
    with Session(engine) as session:
        # Mark session as used by setting expiry to max
        result = session.execute(
            update(SessionModel)
            .values(expiry=datetime.max)
            .where(SessionModel.session_id == store_id)
            .returning(SessionModel.id)
        )
        return result.scalar() is not None
