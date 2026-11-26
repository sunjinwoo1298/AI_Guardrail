"""Database engine and sessions for the control plane (SQLAlchemy 2.0, sync).

The control plane is read on the request path only through an in-memory cache
(app/control/tenancy.py), so a synchronous engine is enough: admin endpoints and cache
misses run it in a worker thread. Postgres in production; SQLite for tests and local use.
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator, Optional

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core import config
from app.core.logger import logger


class Base(DeclarativeBase):
    pass


_engine: Optional[Engine] = None
_session_factory: Optional[sessionmaker] = None
_lock = threading.Lock()


def init_engine(url: Optional[str] = None, *, create_tables: Optional[bool] = None) -> Optional[Engine]:
    """(Re)initialise the engine. ``url`` defaults to DATABASE_URL; empty disables the
    control plane. Tests call this with "sqlite://" for an isolated in-memory database."""
    global _engine, _session_factory
    url = config.DATABASE_URL if url is None else url
    with _lock:
        if _engine is not None:
            _engine.dispose()
        _engine, _session_factory = None, None
        if not url:
            return None
        kwargs = {"future": True}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
            if url in ("sqlite://", "sqlite:///:memory:"):
                kwargs["poolclass"] = StaticPool  # one shared in-memory database
        else:
            kwargs.update(pool_pre_ping=True, pool_size=10, max_overflow=20, pool_recycle=1800)
        engine = create_engine(url, **kwargs)
        if url.startswith("sqlite"):
            @event.listens_for(engine, "connect")
            def _sqlite_fk(dbapi_connection, _record):  # enforce foreign keys like Postgres
                dbapi_connection.execute("PRAGMA foreign_keys=ON")
        _engine = engine
        _session_factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    if config.DB_AUTO_CREATE if create_tables is None else create_tables:
        from app.control import models  # noqa: F401 - register tables

        Base.metadata.create_all(_engine)
    logger.info(f"Control plane database initialised ({engine.dialect.name})")
    return _engine


def enabled() -> bool:
    return _session_factory is not None


@contextmanager
def session_scope() -> Iterator[Session]:
    if _session_factory is None:
        raise RuntimeError("Control plane database is not configured (DATABASE_URL)")
    session = _session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def ping() -> bool:
    if _engine is None:
        return False
    try:
        with _engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
        return True
    except Exception as exc:
        logger.warning(f"Control plane database unavailable: {exc}")
        return False
