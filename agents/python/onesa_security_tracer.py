"""Onesa Security: bounded metadata-only AI agent execution tracing (preview).

No raw prompts, tool arguments, retrieved content or model responses are collected.
This is not a security policy executor. Production telemetry needs an approved
collector, a verified mTLS ingress and independently enforced guardrails.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
from queue import Empty, Full, Queue
import re
import ssl
from threading import Event, Thread
from time import perf_counter_ns, monotonic, sleep
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, OpenerDirector, Request, build_opener
from uuid import uuid4

_SAFE_AGENT = re.compile(r"^[A-Za-z0-9_.:-]{3,120}$")
_PHASES = frozenset({"inference", "retrieval", "planning", "policy", "tool_review", "response"})


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise RuntimeError("Unexpected telemetry redirect")


class AgentTracer:
    """Send trace metadata off the hot path through a bounded worker queue.

    sender is an isolated-test injection only. In production a TLS client
    certificate and private key are mandatory and a fixed HTTPS origin is used.
    """

    def __init__(self, *, endpoint: str, collector_token: str, certfile: str | None = None,
                 keyfile: str | None = None, ca_bundle: str | None = None,
                 queue_limit: int = 128, timeout_s: float = 2.0, sender=None):
        parsed = urlsplit(endpoint)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path != "/v1/collector/ai/agent-traces"
                or parsed.port not in (None, 443)):
            raise ValueError("Exact HTTPS collector trace endpoint required")
        if not (16 <= len(collector_token) <= 300) or any(c in collector_token for c in "\r\n\x00"):
            raise ValueError("Invalid collector token")
        if not isinstance(queue_limit, int) or not 1 <= queue_limit <= 4096:
            raise ValueError("Invalid trace buffer")
        if not 0.1 <= timeout_s <= 5.0:
            raise ValueError("Invalid telemetry timeout")
        if sender is None:
            if not certfile or not keyfile:
                raise ValueError("Client TLS certificate/key required")
            context = ssl.create_default_context(cafile=ca_bundle)
            context.load_cert_chain(certfile, keyfile)
            opener = build_opener(HTTPSHandler(context=context), _NoRedirect())
            def send(event):
                raw = json.dumps(event, separators=(",", ":")).encode("utf8")
                request = Request(endpoint, data=raw, method="POST", headers={
                    "Content-Type": "application/json",
                    "Authorization": "Collector " + collector_token,
                    "Accept": "application/json",
                })
                with opener.open(request, timeout=timeout_s) as response:
                    if response.status != 201:
                        raise RuntimeError("Collector telemetry not accepted")
                    response.read(1024)
            self._sender = send
        else:
            self._sender = sender
        self._queue = Queue(maxsize=queue_limit)
        self._closed = Event()
        self._worker = Thread(target=self._work, daemon=True, name="onesa-agent-trace")
        self._worker.start()
        self.sent = 0
        self.dropped = 0

    def _work(self):
        while not self._closed.is_set() or not self._queue.empty():
            try:
                item = self._queue.get(timeout=0.05)
            except Empty:
                continue
            try:
                self._sender(item)
                self.sent += 1
            except Exception:
                # Never expose credentials or request bodies in logs.
                self.dropped += 1
            finally:
                self._queue.task_done()

    def record(self, *, trace_id: str, span_id: str, agent_ref: str, phase: str,
               outcome: str, elapsed_us: int, parent_span_id: str | None = None) -> bool:
        if not _SAFE_AGENT.fullmatch(agent_ref) or phase not in _PHASES:
            raise ValueError("Invalid agent metadata")
        if outcome not in {"success", "denied", "error", "timeout"}:
            raise ValueError("Invalid outcome")
        if not 0 <= elapsed_us <= 60_000_000:
            raise ValueError("Invalid elapsed time")
        if self._closed.is_set():
            return False
        item = {
            "trace_id": str(trace_id), "span_id": str(span_id), "parent_span_id": parent_span_id,
            "agent_ref": agent_ref, "phase": phase, "outcome": outcome,
            "elapsed_us": elapsed_us, "occurred_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            self._queue.put_nowait(item)
            return True
        except Full:
            self.dropped += 1
            return False

    @contextmanager
    def span(self, *, agent_ref: str, phase: str, trace_id: str | None = None,
             parent_span_id: str | None = None):
        trace = str(trace_id or uuid4())
        span_id = str(uuid4())
        started = perf_counter_ns()
        try:
            yield {"trace_id": trace, "span_id": span_id}
        except BaseException as e:
            outcome = "timeout" if isinstance(e, TimeoutError) else (
                "denied" if isinstance(e, PermissionError) else "error")
            raise
        else:
            outcome = "success"
        finally:
            duration = min(60_000_000, (perf_counter_ns() - started) // 1000)
            self.record(trace_id=trace, span_id=span_id, parent_span_id=parent_span_id,
                        agent_ref=agent_ref, phase=phase, outcome=outcome, elapsed_us=duration)

    def flush(self, timeout_s: float = 2.0) -> bool:
        deadline = monotonic() + max(0, timeout_s)
        while monotonic() < deadline:
            if self._queue.unfinished_tasks == 0:
                return True
            sleep(0.005)
        return self._queue.unfinished_tasks == 0

    def close(self):
        self._closed.set()
        self._worker.join(timeout=2.0)
