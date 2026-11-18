"""Collector expiration must compare instants across PostgreSQL time zones."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app.auth import authorize_collector


TENANT = "01234567-89ab-cdef-0123-456789abcdef"
CREDENTIAL = TENANT + "." + "fixture-only-" * 6


def collector_session(expiration):
    session = MagicMock()
    session.get_bind.return_value.dialect.name = "sqlite"
    session.scalar.return_value = SimpleNamespace(expires_at=expiration)
    return session


def test_expired_aware_postgres_timestamp_cannot_gain_hours_from_timezone():
    expired = (datetime.now(timezone.utc) - timedelta(minutes=2)).astimezone(
        timezone(timedelta(hours=2))
    )
    with pytest.raises(HTTPException) as error:
        authorize_collector(collector_session(expired), CREDENTIAL, False, False)
    assert error.value.status_code == 401


def test_aware_unexpired_timestamp_remains_valid():
    future = (datetime.now(timezone.utc) + timedelta(minutes=3)).astimezone(
        timezone(timedelta(hours=-5))
    )
    collector = authorize_collector(collector_session(future), CREDENTIAL, False, False)
    assert collector.expires_at == future


def test_naive_utc_sqlite_expiry_retains_its_original_meaning():
    expired = (datetime.now(timezone.utc) - timedelta(minutes=2)).replace(tzinfo=None)
    with pytest.raises(HTTPException) as error:
        authorize_collector(collector_session(expired), CREDENTIAL, False, False)
    assert error.value.status_code == 401


def test_missing_expiry_denies_credential():
    with pytest.raises(HTTPException) as error:
        authorize_collector(collector_session(None), CREDENTIAL, False, False)
    assert error.value.status_code == 401
