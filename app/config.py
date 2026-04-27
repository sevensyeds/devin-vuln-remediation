from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    devin_api_key: str = "cog_missing"
    devin_org_id: str = "org_missing"
    devin_base_url: str = "https://api.devin.ai/v3"

    github_token: str = "ghp_missing"
    github_repo: str = "sevensyeds/superset"

    superset_path: str = "/superset"

    scan_cron: str = "*/10 * * * *"

    max_concurrent_sessions: int = 2
    max_acu_per_session: int = 10
    session_max_wall_clock_seconds: int = 3600
    poll_interval_seconds: int = 10

    mock_devin: bool = False

    db_path: str = "/data/state.db"


settings = Settings()
