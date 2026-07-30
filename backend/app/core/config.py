"""Application configuration (pydantic-settings)."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LEDGERRAG_", env_file=".env")

    # Providers (local fallbacks keep the demo offline-friendly)
    embedding_provider: str = "local"  # "local" | "openai"
    llm_provider: str = "local"        # "local" | "openai"
    openai_api_key: str = ""

    # Vector store
    vector_store: str = "chroma"       # "chroma" | "pgvector"
    pg_dsn: str = "postgresql://localhost/ledgerrag"

    # RAG
    chunk_size: int = 800
    chunk_overlap: int = 120
    top_k: int = 4


settings = Settings()
