"""
Payload-limit helpers for the /invocations shims.

- check_structure: iterative (never recursive) depth / node / string-length walk.
- parse_json_body: json.loads + check_structure; the top level must be an object.
- ConcurrencyGate: non-blocking bounded semaphore behind the shims' 429.
- REQUEST_REF_RE: the lowercase uuid4 form accepted for `request_ref`
  (unanchored; callers use REQUEST_REF_RE.fullmatch).
- request_ref_ok / new_request_ref: the accepted request_ref is a uuid4
  that the PAN classifier does NOT flag (about 2 % of random uuid4s are
  PAN-shaped). request_ref is stored in the audit tables and sealed in the
  WORM archive, so a PAN-shaped one is refused, never stored.

Error codes never carry caller bytes, so a shim can return them verbatim.
"""
import json
import logging
import os
import re
import threading
import uuid

from .pan_filter import contains_full_pan

logger = logging.getLogger(__name__)

DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_NODES = 250_000
DEFAULT_MAX_STR_LEN = 65_536
DEFAULT_MAX_CONCURRENT_INVOCATIONS = 4

TOO_DEEP = "TOO_DEEP"
TOO_MANY_NODES = "TOO_MANY_NODES"
STRING_TOO_LONG = "STRING_TOO_LONG"
TOO_MANY_ITEMS = "TOO_MANY_ITEMS"
INVALID_JSON = "INVALID_JSON"
LIMIT_CODES = frozenset({TOO_DEEP, TOO_MANY_NODES, STRING_TOO_LONG, TOO_MANY_ITEMS})

REQUEST_REF_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")


def request_ref_ok(value) -> bool:
    """True only for a lowercase uuid4 the PAN classifier does not flag.
    A PAN-shaped uuid could carry a planted card number into the audit
    records and the immutable archive, so it is refused like any other
    malformed request_ref."""
    return (isinstance(value, str) and REQUEST_REF_RE.fullmatch(value) is not None
            and not contains_full_pan(value))


def new_request_ref() -> str:
    """A fresh uuid4 that request_ref_ok accepts (regenerated when the
    random id happens to be PAN-shaped)."""
    while True:
        ref = str(uuid.uuid4())
        if request_ref_ok(ref):
            return ref


class PayloadLimitError(ValueError):
    """A request body violated a structure limit or was not valid JSON."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def check_structure(obj, *, max_depth: int = DEFAULT_MAX_DEPTH, max_nodes: int = DEFAULT_MAX_NODES,
                    max_str_len: int = DEFAULT_MAX_STR_LEN) -> None:
    """Raise PayloadLimitError if `obj` exceeds the limits.

    Depth counts containers: a top-level object is depth 1. Every value
    (container or scalar) is a node; object keys are checked for length but
    not counted as nodes. Explicit stack, so a 10,000-deep list raises
    TOO_DEEP rather than RecursionError."""
    nodes = 0
    stack = [(obj, 1)]
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise PayloadLimitError(TOO_MANY_NODES)
        if isinstance(value, dict):
            if depth > max_depth:
                raise PayloadLimitError(TOO_DEEP)
            for key, child in value.items():
                if isinstance(key, str) and len(key) > max_str_len:
                    raise PayloadLimitError(STRING_TOO_LONG)
                stack.append((child, depth + 1))
        elif isinstance(value, (list, tuple)):
            if depth > max_depth:
                raise PayloadLimitError(TOO_DEEP)
            for child in value:
                stack.append((child, depth + 1))
        elif isinstance(value, str):
            if len(value) > max_str_len:
                raise PayloadLimitError(STRING_TOO_LONG)


def parse_json_body(body: bytes, **limits) -> dict:
    """Parse a request body. An empty body is {} (the shims' existing behaviour)."""
    if not body:
        return {}
    try:
        payload = json.loads(body)
    except (RecursionError, ValueError) as exc:  # JSONDecodeError/UnicodeDecodeError are ValueErrors
        raise PayloadLimitError(INVALID_JSON) from exc
    if not isinstance(payload, dict):
        raise PayloadLimitError(INVALID_JSON)
    check_structure(payload, **limits)
    return payload


def concurrency_limit_from_env(default: int = DEFAULT_MAX_CONCURRENT_INVOCATIONS) -> int:
    """MAX_CONCURRENT_INVOCATIONS as a positive int; anything else -> default."""
    raw = os.environ.get("MAX_CONCURRENT_INVOCATIONS", "")
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value < 1:
        logger.warning("MAX_CONCURRENT_INVOCATIONS is not a positive integer; using %d", default)
        return default
    return value


class ConcurrencyGateFull(RuntimeError):
    """Raised by ConcurrencyGate.__enter__ when every slot is taken."""


class ConcurrencyGate:
    """Non-blocking bounded semaphore. A full gate is a 429, never a wait."""

    def __init__(self, limit: int):
        if not isinstance(limit, int) or limit < 1:
            raise ValueError("concurrency limit must be a positive integer")
        self.limit = limit
        self._semaphore = threading.BoundedSemaphore(limit)

    def try_acquire(self) -> bool:
        return self._semaphore.acquire(blocking=False)

    def release(self) -> None:
        self._semaphore.release()

    def __enter__(self):
        if not self.try_acquire():
            raise ConcurrencyGateFull("concurrency limit reached")
        return self

    def __exit__(self, exc_type, exc, tb):
        self.release()
        return False
