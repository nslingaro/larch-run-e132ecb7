"""Service configuration, read from ``LARCH_*`` environment variables.

Secrets (token signing key, document encryption keys, database password) are
injected at runtime by the platform from the secret store (for example App Service
Key Vault references). They are never read from files in the repository or image.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from functools import cached_property
from typing import Annotated

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_RATE_RE = re.compile(r"^\s*(\d+)\s*/\s*(\d+)\s*$")


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


@dataclass(frozen=True)
class RateLimit:
    """``limit`` requests per ``window_seconds``."""

    limit: int
    window_seconds: int

    @classmethod
    def parse(cls, value: str) -> RateLimit:
        match = _RATE_RE.match(value)
        if not match:
            raise ValueError(f"rate limit must look like '<count>/<seconds>', got {value!r}")
        limit, window = int(match.group(1)), int(match.group(2))
        if limit < 1 or window < 1:
            raise ValueError("rate limit count and window must be positive")
        return cls(limit, window)


def _split_csv(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LARCH_", extra="ignore", frozen=True)

    # Defaults to production so a deployment that forgets to set it fails closed:
    # production refuses to start without real keys and a TLS PostgreSQL URL.
    environment: Environment = Environment.PRODUCTION

    database_url: str = "sqlite:///./var/larch.db"
    database_pool_size: int = Field(default=5, ge=1, le=50)
    database_max_overflow: int = Field(default=10, ge=0, le=50)
    database_pool_timeout_seconds: int = Field(default=10, ge=1, le=60)
    database_statement_timeout_ms: int = Field(default=10_000, ge=100, le=600_000)

    documents_dir: str = "./var/documents"

    # Bearer access tokens: ES256-signed JWTs (see larch/security/tokens.py).
    token_signing_key: SecretStr | None = None  # PEM, EC P-256 private key
    token_previous_public_keys: SecretStr | None = None  # PEM bundle, kept during rotation overlap
    token_issuer: str = "https://api.larch.example"
    token_audience: str = "https://apply.larch.example"
    # OPEN DECISION: token lifetime. 60 minutes, no refresh tokens.
    access_token_ttl_minutes: int = Field(default=60, ge=1, le=24 * 60)

    # Document envelope encryption (AES-256-GCM). Comma-separated "<key-id>:<base64 32 bytes>".
    document_encryption_keys: SecretStr | None = None
    document_encryption_active_key_id: str | None = None

    # OPEN DECISION: Argon2id parameters. Defaults are argon2-cffi's RFC 9106
    # "low memory" profile.
    argon2_time_cost: int = Field(default=3, ge=1, le=10)
    argon2_memory_cost_kib: int = Field(default=65_536, ge=8, le=1_048_576)
    argon2_parallelism: int = Field(default=4, ge=1, le=16)

    # OPEN DECISION: approved browser origins. Empty means no cross-origin access.
    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    # OPEN DECISION: HSTS policy.
    hsts_max_age_seconds: int = Field(default=31_536_000, ge=0)
    hsts_include_subdomains: bool = False

    # Interactive API documentation (/docs, /redoc, /openapi.json). Off unless enabled;
    # require explicit approval to enable it outside development.
    enable_api_docs: bool | None = None

    # OPEN DECISION: rate-limit values. Format "<count>/<seconds>".
    rate_limit_login_per_ip: str = "20/60"
    rate_limit_login_per_account: str = "10/900"
    rate_limit_register_per_ip: str = "20/3600"
    rate_limit_upload_per_user: str = "30/60"
    rate_limit_download_per_user: str = "120/60"
    rate_limit_authenticated_per_user: str = "300/60"
    rate_limit_per_ip: str = "600/60"

    max_json_body_bytes: int = Field(default=256 * 1024, ge=1024)

    # OPEN DECISION: malware scanning of uploads. "none" until decided.
    malware_scanner: str = "none"

    # OPEN DECISION: retention. Unset means the purge command refuses to run.
    retention_days_after_closure: int | None = Field(default=None, ge=1)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_origins(cls, value: object) -> object:
        return _split_csv(value)

    @field_validator("cors_origins")
    @classmethod
    def _check_origins(cls, origins: list[str]) -> list[str]:
        for origin in origins:
            if origin in ("*", "null") or not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d+)?", origin):
                raise ValueError(f"CORS origin {origin!r} is not an explicit http(s) origin")
        return origins

    @field_validator(
        "rate_limit_login_per_ip",
        "rate_limit_login_per_account",
        "rate_limit_register_per_ip",
        "rate_limit_upload_per_user",
        "rate_limit_download_per_user",
        "rate_limit_authenticated_per_user",
        "rate_limit_per_ip",
    )
    @classmethod
    def _check_rate(cls, value: str) -> str:
        RateLimit.parse(value)
        return value

    @field_validator("malware_scanner")
    @classmethod
    def _check_scanner(cls, value: str) -> str:
        if value != "none":
            raise ValueError("only 'none' is available until the malware-scanning decision is made")
        return value

    @model_validator(mode="after")
    def _check_deployed_environment(self) -> Settings:
        if self.environment is Environment.DEVELOPMENT:
            return self
        problems = []
        if self.token_signing_key is None or not self.token_signing_key.get_secret_value().strip():
            problems.append("LARCH_TOKEN_SIGNING_KEY is required")
        if self.document_encryption_keys is None or not self.document_encryption_keys.get_secret_value().strip():
            problems.append("LARCH_DOCUMENT_ENCRYPTION_KEYS is required")
        if not self.document_encryption_active_key_id:
            problems.append("LARCH_DOCUMENT_ENCRYPTION_ACTIVE_KEY_ID is required")
        url = self.database_url
        if not url.startswith("postgresql"):
            problems.append("LARCH_DATABASE_URL must be a PostgreSQL URL outside development")
        elif not re.search(r"[?&]sslmode=(require|verify-ca|verify-full)\b", url):
            problems.append("LARCH_DATABASE_URL must set sslmode=require, verify-ca or verify-full")
        if problems:
            raise ValueError(f"unsafe {self.environment.value} configuration: " + "; ".join(problems))
        return self

    @property
    def is_development(self) -> bool:
        return self.environment is Environment.DEVELOPMENT

    @property
    def api_docs_enabled(self) -> bool:
        if self.enable_api_docs is None:
            return self.is_development
        return self.enable_api_docs

    @cached_property
    def rate_limits(self) -> dict[str, RateLimit]:
        return {
            "login_ip": RateLimit.parse(self.rate_limit_login_per_ip),
            "login_account": RateLimit.parse(self.rate_limit_login_per_account),
            "register_ip": RateLimit.parse(self.rate_limit_register_per_ip),
            "upload_user": RateLimit.parse(self.rate_limit_upload_per_user),
            "download_user": RateLimit.parse(self.rate_limit_download_per_user),
            "user": RateLimit.parse(self.rate_limit_authenticated_per_user),
            "ip": RateLimit.parse(self.rate_limit_per_ip),
        }
