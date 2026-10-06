"""
SecureCodeGuard – Configuration Module
Loads all settings from .env and provides typed access via Pydantic Settings.
"""

from __future__ import annotations

import os
from pathlib import Path
try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseModel
    class BaseSettings(BaseModel):  # type: ignore[no-redef]
        def __init__(self, **values):
            # Simple env var loader fallback
            for field_name in self.__class__.model_fields:
                env_val = os.environ.get(field_name.upper()) or os.environ.get(field_name)
                if env_val is not None and field_name not in values:
                    field_info = self.__class__.model_fields[field_name]
                    target_type = field_info.annotation
                    try:
                        if target_type == int:
                            values[field_name] = int(env_val)
                        elif target_type == float:
                            values[field_name] = float(env_val)
                        elif target_type == bool:
                            values[field_name] = env_val.lower() in ("true", "1", "yes")
                        else:
                            values[field_name] = env_val
                    except Exception:
                        pass
            super().__init__(**values)

from pydantic import Field


# Project root is the directory containing this package's parent
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Application-wide settings loaded from environment / .env file."""

    # ── Ollama / Local LLM ───────────────────────────────────────────
    ollama_base_url: str = Field(default="http://localhost:11434")
    ollama_model: str = Field(default="mistral:7b-instruct-v0.3-q4_K_M")
    ollama_timeout: int = Field(default=120)

    # ── Embedding Model ─────────────────────────────────────────────
    embedding_model: str = Field(default="BAAI/bge-small-en-v1.5")
    embedding_device: str = Field(default="cpu")

    # ── ChromaDB ─────────────────────────────────────────────────────
    chroma_persist_dir: str = Field(default="./chroma_db")
    chroma_collection_code: str = Field(default="code_chunks")
    chroma_collection_guidelines: str = Field(default="guideline_chunks")
    chroma_collection_logs: str = Field(default="log_chunks")
    chroma_collection_static: str = Field(default="static_analysis_chunks")
    chroma_collection_historical: str = Field(default="historical_findings")

    # ── SQLite ───────────────────────────────────────────────────────
    sqlite_db_path: str = Field(default="./data/securecodeguard.db")

    # ── RAG Settings ─────────────────────────────────────────────────
    rag_top_k: int = Field(default=5)
    rag_similarity_threshold: float = Field(default=0.3)
    rag_max_context_tokens: int = Field(default=2048)

    # ── Data Paths ───────────────────────────────────────────────────
    data_code_dir: str = Field(default="./data/code")
    data_guidelines_dir: str = Field(default="./data/guidelines")
    data_logs_dir: str = Field(default="./data/logs")
    data_static_dir: str = Field(default="./data/static_analysis")
    data_eval_dir: str = Field(default="./data/evaluation")
    reports_dir: str = Field(default="./reports")

    # ── Server ───────────────────────────────────────────────────────
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    streamlit_port: int = Field(default=8501)

    # ── Logging ──────────────────────────────────────────────────────
    log_level: str = Field(default="INFO")
    log_file: str = Field(default="./data/securecodeguard.log")

    # ── Seed ─────────────────────────────────────────────────────────
    random_seed: int = Field(default=42)

    class Config:
        env_file = str(_PROJECT_ROOT / ".env")
        env_file_encoding = "utf-8"
        extra = "ignore"

    # ── Helpers ──────────────────────────────────────────────────────
    def resolve_path(self, relative_path: str) -> Path:
        """Resolve a relative path against the project root."""
        p = Path(relative_path)
        if p.is_absolute():
            return p
        return _PROJECT_ROOT / p

    @property
    def project_root(self) -> Path:
        return _PROJECT_ROOT

    def get_collection_name(self, doc_type: str) -> str:
        """Return the ChromaDB collection name for a document type."""
        mapping = {
            "code": self.chroma_collection_code,
            "guidelines": self.chroma_collection_guidelines,
            "logs": self.chroma_collection_logs,
            "static_analysis": self.chroma_collection_static,
            "static-analysis": self.chroma_collection_static,
            "historical": self.chroma_collection_historical,
            "historical-findings": self.chroma_collection_historical,
        }
        return mapping.get(doc_type, self.chroma_collection_code)


# Singleton
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Return the application settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
