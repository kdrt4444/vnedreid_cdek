import os

from authx import AuthXConfig
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DB_HOST: str
    DB_PORT: int
    DB_NAME: str
    DB_USER: str
    DB_PASSWORD: str
    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
    )


settings = Settings()

def get_db_url():
    return (f"postgresql+asyncpg://{settings.DB_USER}:{settings.DB_PASSWORD}@"
            f"{settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}")


class JWTSettings(BaseSettings):
    JWT_SECRET_KEY: str = "insecure_dev_secret" # добавить в env
    JWT_ACCESS_COOKIE_NAME: str = "access_token"
    JWT_TOKEN_LOCATION: list[str] = ["cookies"]

    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
    )


jwt_settings = JWTSettings()

config = AuthXConfig()
config.JWT_SECRET_KEY = jwt_settings.JWT_SECRET_KEY
config.JWT_ACCESS_COOKIE_NAME = jwt_settings.JWT_ACCESS_COOKIE_NAME
config.JWT_TOKEN_LOCATION = ["cookies"]
config.JWT_COOKIE_CSRF_PROTECT = False