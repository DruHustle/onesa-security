"""Configuration gates that cannot be weakened by inherited deployment settings."""
import pytest
from app.config import Settings


def test_collector_mtls_defaults_to_required(monkeypatch):
    monkeypatch.delenv("COLLECTOR_REQUIRE_MTLS", raising=False)
    monkeypatch.delenv("ONESA_SECURITY_ENV", raising=False)
    monkeypatch.delenv("ONESA_DEV_ISOLATED", raising=False)
    assert Settings.from_env().collector_mtls_required is True


@pytest.mark.parametrize("value", ["false", "FALSE", "False"])
def test_public_or_misidentified_environment_cannot_disable_mtls(monkeypatch, value):
    monkeypatch.setenv("COLLECTOR_REQUIRE_MTLS", value)
    monkeypatch.delenv("ONESA_DEV_ISOLATED", raising=False)
    monkeypatch.delenv("ONESA_SECURITY_ENV", raising=False)
    with pytest.raises(RuntimeError, match="isolated development"):
        Settings.from_env()

    monkeypatch.setenv("ONESA_SECURITY_ENV", "development")
    with pytest.raises(RuntimeError, match="isolated development"):
        Settings.from_env()

    monkeypatch.setenv("ONESA_DEV_ISOLATED", "1")
    assert Settings.from_env().collector_mtls_required is False


@pytest.mark.parametrize("value", ["0", "off", "disabled", ""])
def test_mtls_configuration_rejects_ambiguous_values(monkeypatch, value):
    monkeypatch.setenv("COLLECTOR_REQUIRE_MTLS", value)
    with pytest.raises(RuntimeError, match="must be true or false"):
        Settings.from_env()
