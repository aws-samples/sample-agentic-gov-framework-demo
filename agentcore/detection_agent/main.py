"""
Detection Agent — AgentCore Runtime HTTP Server (lightweight).

Uses Python stdlib http.server for fast cold start (<5s).
Heavy imports (pandas, numpy, networkx) are deferred to first invocation.

Endpoints:
  POST /invocations  — primary agent interaction endpoint
  GET  /ping         — health check

NHI Identity (detection-agent-role):
- CAN: Read transactions (S3/Kinesis), write detection results (DynamoDB)
- CANNOT: Invoke Bedrock, write SAR filings
"""
import json
import logging
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Maximum accepted request body size. A caller-declared
# Content-Length above this is rejected with 413 before any bytes are read,
# so one connection cannot read an unbounded body into memory.
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(1 * 1024 * 1024)))  # 1 MiB

AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(AGENT_DIR))

# Add lib/ subdirectory to path (dependencies are packaged there to avoid
# numpy source-tree detection conflicts when placed at zip root)
LIB_DIR = os.path.join(AGENT_DIR, "lib")
if os.path.isdir(LIB_DIR):
    sys.path.insert(0, LIB_DIR)
# Also check /var/task/lib (AgentCore extracts zip to /var/task/)
TASK_LIB = "/var/task/lib"
if os.path.isdir(TASK_LIB):
    sys.path.insert(0, TASK_LIB)

# governance_common ships at the zip root in a deployed runtime (already on
# sys.path); for local runs it lives at the repo root.
if os.path.isdir(os.path.join(PROJECT_ROOT, "governance_common")) and PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from governance_common import runtime_attestation  # noqa: E402
from governance_common.payload_limits import (  # noqa: E402
    INVALID_JSON,
    request_ref_ok,
    ConcurrencyGate,
    PayloadLimitError,
    concurrency_limit_from_env,
    parse_json_body,
)

# dataset_id shape accepted by the shim; the handler additionally requires a
# key of its DATASETS allowlist.
DATASET_ID_RE = re.compile(r"[a-z0-9-]{1,32}")

# Bounds concurrent handler work (graph detection is CPU/memory heavy); a
# full gate is a 429, never a queue. MAX_CONCURRENT_INVOCATIONS
# is set by the deploy script.
_GATE = ConcurrencyGate(concurrency_limit_from_env())

# Lazy-loaded handler — heavy imports (pandas, numpy, networkx) deferred
_detection_handler = None


def _get_handler():
    global _detection_handler
    if _detection_handler is None:
        logger.info("Loading detection handler (first invocation)...")
        try:
            sys.path.insert(0, os.path.join(PROJECT_ROOT, "lambdas", "detection_agent"))
            from handler import handler as h
            _detection_handler = h
        except ImportError:
            sys.path.insert(0, os.path.join(os.path.dirname(AGENT_DIR), "lambdas", "detection_agent"))
            try:
                from handler import handler as h
                _detection_handler = h
            except ImportError:
                from lambdas.detection_agent.handler import handler as h
                _detection_handler = h
        logger.info("Detection handler loaded.")
    return _detection_handler


class AgentHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for AgentCore protocol."""

    # Drop a stalled peer rather than letting it hold the worker forever.
    # Combined with ThreadingHTTPServer below, one slow
    # connection can no longer stall every other caller.
    timeout = int(os.environ.get("HANDLER_TIMEOUT", "10"))

    def _send_json(self, status, obj, extra_headers=()):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(json.dumps(obj, default=str).encode())

    def _read_body(self):
        """Read the request body with a hard size cap.

        Rejects a caller-declared Content-Length above MAX_BODY_BYTES with a
        413 BEFORE reading any bytes, and reads in bounded chunks so a slow or
        oversized peer cannot exhaust memory. Returns the body bytes, or None
        if an error response was already sent.
        """
        # The bounded reader relies on Content-Length, so a chunked body is
        # refused before any byte is read.
        if self.headers.get("Transfer-Encoding") is not None:
            self.close_connection = True
            self._send_json(411, {"error": "Length Required"})
            return None
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            content_length = 0
        if content_length > MAX_BODY_BYTES:
            self.close_connection = True
            self._send_json(413, {
                "error": "Payload Too Large",
                "max_bytes": MAX_BODY_BYTES,
            })
            return None
        remaining = content_length
        chunks = []
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def do_GET(self):
        if self.path == "/ping":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "Healthy"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/invocations":
            # Runtime self-check of the signed gate artifact:
            # a no-op outside a deployed runtime; /ping stays healthy.
            attestation_error = runtime_attestation.check_once(AGENT_DIR)
            if attestation_error is not None:
                self.close_connection = True
                self._send_json(503, {"error": attestation_error})
                return
            body = self._read_body()
            if body is None:
                return  # error response already sent by _read_body
            if not _GATE.try_acquire():
                logger.info("Rejected invocation: concurrency limit reached")
                self._send_json(429, {"error": "Too Many Requests"}, (("Retry-After", "2"),))
                return
            try:
                self._invoke(body)
            finally:
                _GATE.release()
        else:
            self.send_response(404)
            self.end_headers()

    def _invoke(self, body):
        """Parse and dispatch one /invocations body (called inside the gate)."""
        try:
            payload = parse_json_body(body)
        except PayloadLimitError as e:
            # Never echo the parser message: it reflects caller bytes.
            logger.info("Rejected invocation: %s", e.code)
            if e.code == INVALID_JSON:
                self._send_json(400, {"error": "Invalid JSON"})
            else:
                self._send_json(413, {"error": "Payload structure exceeds limits", "code": e.code})
            return

        # A caller can never name a file: datasets are selected
        # by an allowlisted id that the handler resolves server-side.
        if "transaction_file" in payload:
            self._send_json(400, {"error": "transaction_file is not accepted; use dataset_id"})
            return
        dataset_id = payload.get("dataset_id")
        if dataset_id is not None and not (
                isinstance(dataset_id, str) and DATASET_ID_RE.fullmatch(dataset_id)):
            self._send_json(400, {"error": "invalid dataset_id"})
            return
        # Optional correlation reference to the console's operator-audit
        # record; never used for authorization.
        request_ref = payload.get("request_ref")
        # A PAN-shaped uuid is refused like any malformed ref: request_ref
        # is stored in the audit tables and sealed in the WORM archive.
        if request_ref is not None and not request_ref_ok(request_ref):
            self._send_json(400, {"error": "invalid request_ref"})
            return

        # Support simple prompt-based invocations
        if "prompt" in payload and "mode" not in payload:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "response": "FSI Detection Agent v2.0. Send a transaction payload to run detection.",
                "status": "ready",
            }).encode())
            return

        # Build event and invoke handler. The execution mode is pinned
        # SERVER-SIDE from the AGENT_MODE env var (set by the deploy
        # script), never read from the request body — a caller can no
        # longer select mode=local to short-circuit the PAN filter and
        # audit write. Defaults to "cpu" for local dev.
        event = {"mode": os.environ.get("AGENT_MODE", "cpu")}
        if dataset_id is not None:
            event["dataset_id"] = dataset_id
        if request_ref is not None:
            event["request_ref"] = request_ref
        if "transactions_inline" in payload:
            event["transactions_inline"] = payload["transactions_inline"]

        try:
            handler = _get_handler()
            result = handler(event)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result, default=str).encode())
        except Exception as e:
            # Do not echo str(e) to the caller — it leaks a path/errno
            # oracle for probed filesystem paths. Log the
            # detail server-side and return only a generic error id.
            error_id = str(uuid.uuid4())
            logger.error("Detection agent error [%s]: %s", error_id, e, exc_info=True)
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "AGENT_ERROR",
                "error_id": error_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }).encode())

    def log_message(self, format, *args):
        # Suppress per-request logging for /ping (too noisy)
        if "/ping" not in (args[0] if args else ""):
            logger.info(format, *args)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    # Bind loopback by default. The dev server has no caller
    # authentication, so an all-interfaces bind would let anyone who can
    # reach the host drive real detection using the host's AWS credentials.
    # The managed AgentCore runtime sets its own network placement; this
    # bind governs only `make dev-detection`. BIND_HOST can be overridden
    # for container/orchestrator setups that publish via a controlled proxy.
    host = os.environ.get("BIND_HOST", "127.0.0.1")
    server = ThreadingHTTPServer((host, port), AgentHandler)
    logger.info("Starting Detection Agent on %s:%d (stdlib http.server)", host, port)
    server.serve_forever()
