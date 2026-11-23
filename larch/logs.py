"""Structured JSON logging to standard output.

- Every record carries the request's correlation ID.
- Fields are passed explicitly and filtered against an allow-list; free-form personal
  data (names, emails, addresses, file names, document contents) is never logged.
- Exceptions are logged as type plus stack frames only. Exception messages are dropped
  because they can carry SQL parameters or other personal data.
- Strings that look like bearer tokens or JWTs are masked as a last line of defence.

App Service forwards standard output to Log Analytics (docs/design/architecture.md).
"""

from __future__ import annotations

import json
import logging
import re
import sys
import traceback
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
client_ip_var: ContextVar[str | None] = ContextVar("client_ip", default=None)

SECURITY_LOGGER = "larch.security"

# Only these keys may appear in a log record's structured fields.
ALLOWED_FIELDS = frozenset(
    {
        "event",
        "outcome",
        "actor_id",
        "actor_role",
        "target_type",
        "target_id",
        "reason",
        "method",
        "route",
        "status",
        "duration_ms",
        "source_ip",
        "environment",
        "error_code",
        "error_type",
        "bucket",
        "count",
    }
)

_TOKEN_PATTERNS = (
    re.compile(r"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/\-]+=*"),
)

_environment = "unknown"


def _mask(value: str) -> str:
    for pattern in _TOKEN_PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    return value


def _safe_traceback(exc_info: Any) -> str:
    exc_type, _exc, tb = exc_info
    frames = traceback.extract_tb(tb)
    lines = [f"{frame.filename}:{frame.lineno} in {frame.name}" for frame in frames[-15:]]
    return f"{exc_type.__name__} | " + " <- ".join(reversed(lines))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": _mask(record.getMessage()),
            "environment": _environment,
        }
        request_id = getattr(record, "request_id", None) or request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            for key, value in fields.items():
                if key in ALLOWED_FIELDS and value is not None:
                    payload[key] = _mask(value) if isinstance(value, str) else value
        if record.exc_info and record.exc_info[0] is not None:
            payload["exception"] = _safe_traceback(record.exc_info)
        return json.dumps(payload, default=str)


_base_record_factory = logging.getLogRecordFactory()


def _record_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
    # Stamp the correlation ID when the record is created, not when it is formatted.
    record = _base_record_factory(*args, **kwargs)
    record.request_id = request_id_var.get()
    return record


def configure_logging(environment: str, level: int = logging.INFO) -> None:
    global _environment
    _environment = environment
    logging.setLogRecordFactory(_record_factory)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.set_name("larch-json")
    root = logging.getLogger()
    for existing in list(root.handlers):
        if existing.get_name() == "larch-json":
            root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
    for name in ("uvicorn", "uvicorn.error"):
        logger = logging.getLogger(name)
        logger.handlers = []
        logger.propagate = True
    # Our access log records the route template, not the raw URL with its query string.
    access = logging.getLogger("uvicorn.access")
    access.handlers = []
    access.propagate = False
    access.disabled = True


def log(logger: logging.Logger, level: int, message: str, **fields: Any) -> None:
    logger.log(level, message, extra={"fields": fields})


def security_event(event: str, outcome: str, **fields: Any) -> None:
    """Record a security-relevant event (authentication, authorisation, admin, config)."""
    fields.setdefault("source_ip", client_ip_var.get())
    log(logging.getLogger(SECURITY_LOGGER), logging.INFO if outcome == "success" else logging.WARNING,
        event, event=event, outcome=outcome, **fields)
