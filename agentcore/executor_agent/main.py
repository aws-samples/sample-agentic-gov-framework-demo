"""
Executor Agent — AgentCore Runtime HTTP Server (lightweight).

Uses Python stdlib http.server for fast cold start (<5s).
Heavy imports deferred to first invocation.

Endpoints:
  POST /invocations  — primary agent interaction endpoint
  GET  /ping         — health check

NHI Identity (executor-agent-role):
- CAN: Read compliance decisions, write SAR to S3, send to SQS, write audit
- CANNOT: Invoke Bedrock, modify detection/compliance data
"""
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Maximum accepted request body size.
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", str(1 * 1024 * 1024)))  # 1 MiB

AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(AGENT_DIR))

# Add lib/ subdirectory to path (dependencies packaged there)
_lib_dir = os.path.join(AGENT_DIR, "lib")
if os.path.isdir(_lib_dir):
    sys.path.insert(0, _lib_dir)
_task_lib = "/var/task/lib"
if os.path.isdir(_task_lib):
    sys.path.insert(0, _task_lib)

# governance_common ships at the zip root in a deployed runtime (already on
# sys.path); for local runs it lives at the repo root.
if os.path.isdir(os.path.join(PROJECT_ROOT, "governance_common")) and PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from governance_common import runtime_attestation  # noqa: E402
from governance_common.payload_limits import (  # noqa: E402
    INVALID_JSON,
    ConcurrencyGate,
    PayloadLimitError,
    concurrency_limit_from_env,
    parse_json_body,
)

# Bounds concurrent handler work; a full gate is a 429, never a queue.
# MAX_CONCURRENT_INVOCATIONS is set by the deploy script.
_GATE = ConcurrencyGate(concurrency_limit_from_env())

# Handler refusal codes -> HTTP status (fixed codes, no caller data);
# everything else is a 200.
_ERROR_STATUS = {
    "SOX_VIOLATION": 403,
    "PAYLOAD_TOO_LARGE": 413,
}

# Lazy-loaded handler
_executor_handler = None


def _get_handler():
    global _executor_handler
    if _executor_handler is None:
        logger.info("Loading executor handler (first invocation)...")
        try:
            sys.path.insert(0, os.path.join(PROJECT_ROOT, "lambdas", "executor_agent"))
            from handler import handler as h
            _executor_handler = h
        except ImportError:
            sys.path.insert(0, os.path.join(os.path.dirname(AGENT_DIR), "lambdas", "executor_agent"))
            try:
                from handler import handler as h
                _executor_handler = h
            except ImportError:
                from lambdas.executor_agent.handler import handler as h
                _executor_handler = h
        logger.info("Executor handler loaded.")
    return _executor_handler


class AgentHandler(BaseHTTPRequestHandler):
    # Drop a stalled peer rather than letting it hold a worker.
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
        Returns body bytes, or None if an error response was already sent."""
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
                return
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

        if "prompt" in payload and "compliance_output" not in payload:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "response": "FSI Executor Agent v2.0. Send a compliance_output payload.",
                "status": "ready",
            }).encode())
            return

        # Mode is pinned SERVER-SIDE from AGENT_MODE (set by the deploy
        # script), never from the request body — a caller can no longer
        # select mode=local to skip the provenance check and live
        # audit/filing path. Defaults to "live".
        event = {
            "mode": os.environ.get("AGENT_MODE", "live"),
            "compliance_output": payload.get("compliance_output", {}),
        }
        # Pass through optional fields for SOX rejection testing. These
        # are deliberately forwarded so the executor's SOX gate can reject
        # them (the structured envelope check treats any key outside
        # {mode, compliance_output} as a smuggled override signal).
        if "action" in payload:
            event["action"] = payload["action"]
        if "payload" in payload:
            event["payload"] = payload["payload"]

        try:
            handler = _get_handler()
            result = handler(event)

            # SOX violation returns 403; the cluster cap 413.
            self.send_response(_ERROR_STATUS.get(result.get("error"), 200))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result, default=str).encode())
        except Exception as e:
            # Return a generic error id, not str(e).
            error_id = str(uuid.uuid4())
            logger.error("Executor agent error [%s]: %s", error_id, e, exc_info=True)
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "AGENT_ERROR",
                "error_id": error_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }).encode())

    def log_message(self, format, *args):
        if "/ping" not in (args[0] if args else ""):
            logger.info(format, *args)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    # Loopback by default — the dev server has no caller auth.
    host = os.environ.get("BIND_HOST", "127.0.0.1")
    server = ThreadingHTTPServer((host, port), AgentHandler)
    logger.info("Starting Executor Agent on %s:%d (stdlib http.server)", host, port)
    server.serve_forever()
