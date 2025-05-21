from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        validate_assignment=True,
        case_sensitive=False,
    )

    forward_key: str = Field(default="forwarded-by-reverse-proxy")
    port: int = Field(default=8000)

    host: str = Field(default="0.0.0.0")

    database_url: str = Field(default="sqlite:///db.db")

    secret_key: str = Field(default="verysecretkey")

    token_expire_minutes: int = Field(default=60)

    hash_algorithm: str = Field(default="HS256")


settings: Settings = Settings()  # noqa
