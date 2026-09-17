# Drishti v0.1 — settings validation tests | 11-Jul-2026
"""Settings validation — refuse to boot with the public default JWT secret
outside dev/test envs (security audit fix)."""
import pytest
from pydantic import ValidationError

from app.config import Settings


def test_default_jwt_secret_allowed_in_local():
    settings = Settings(app_env="local", jwt_secret="change-me")
    assert settings.jwt_secret == "change-me"


def test_default_jwt_secret_allowed_in_test():
    settings = Settings(app_env="test", jwt_secret="change-me")
    assert settings.jwt_secret == "change-me"


@pytest.mark.parametrize("app_env", ["docker", "production", "staging"])
def test_default_jwt_secret_rejected_outside_dev_envs(app_env):
    with pytest.raises(ValidationError, match="JWT_SECRET"):
        Settings(app_env=app_env, jwt_secret="change-me")


def test_custom_jwt_secret_allowed_in_production():
    settings = Settings(app_env="production", jwt_secret="a-real-random-secret")
    assert settings.jwt_secret == "a-real-random-secret"
