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
    port: int = Field(default=9000)

    host: str = Field(default="0.0.0.0")

    server_url: str = Field(default="http://localhost:8000")

    database_url: str = Field(default="sqlite:///db.db")


settings: Settings = Settings()  # noqa
