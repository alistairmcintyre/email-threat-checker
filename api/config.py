from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ollama_host: str = "http://localhost:11434"
    llm_model: str = "llama3.2:3b"
    embedding_model: str = "nomic-embed-text"

    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    qdrant_collection: str = "email_threats"

    api_host: str = "0.0.0.0"
    api_port: int = 8000

    quarantine_threshold: float = 0.8
    suspicious_threshold: float = 0.5

    llm_temperature: float = 0.0
    llm_seed: int = 42

    class Config:
        env_file = ".env"


settings = Settings()
