"""Configuration. All secrets come from environment variables or a local .env file."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ACCESSDESK_", extra="ignore"
    )

    # No default on purpose: startup fails if the secret is missing or too short.
    # 32+ characters is the floor for an HS256 signing key.
    jwt_secret: str = Field(min_length=32)
    jwt_issuer: str = "accessdesk"
    jwt_audience: str = "accessdesk-api"
    # Short-lived access tokens. Capped at 60 minutes so a typo cannot create a week-long token.
    access_token_minutes: int = Field(default=15, ge=1, le=60)
    database_path: str = "accessdesk.db"


@lru_cache
def get_settings() -> Settings:
    return Settings()
