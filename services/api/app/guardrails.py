"""Deterministic baseline. Heuristics are NOT a complete prompt-injection defense."""
import re
from dataclasses import dataclass

INJECTION = re.compile(
    r"(?i)\b(?:ignore\s+(?:all\s+)?(?:prior|previous|system|developer)\s+instructions|"
    r"reveal\s+(?:the\s+)?(?:system\s+prompt|secret\s+keys?)|"
    r"override\s+(?:your\s+)?(?:safety|security)\s+(?:rules?|policies)|"
    r"disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions)\b"
)
CREDENTIAL = re.compile(r"(?i)(?:\bsk-[A-Za-z0-9_-]{16,}\b|\bAKIA[A-Z0-9]{16}\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)")
EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")


@dataclass(frozen=True)
class Decision:
    action: str
    reason_code: str
    effective_text: str | None


def inspect_text(text: str, *, block_injection: bool = True, redact_pii: bool = True,
                 action_type: str = "message") -> Decision:
    # All tool executions are intentionally prohibited in this slice; never authorize tools by LLM text.
    if action_type != "message":
        return Decision("Block", "TOOL_EXECUTION_NOT_ENABLED", None)
    if CREDENTIAL.search(text):
        return Decision("Block", "CREDENTIAL_DETECTED", None)
    if block_injection and INJECTION.search(text):
        return Decision("Block", "INJECTION_PATTERN", None)
    clean = EMAIL.sub("[REDACTED_EMAIL]", text) if redact_pii else text
    if clean != text:
        return Decision("Redact", "EMAIL_REDACTED", clean)
    return Decision("Allow", "BASELINE_ACCEPTED", text)


def sanitize_model_output(text: str) -> Decision:
    if CREDENTIAL.search(text):
        return Decision("Block", "CREDENTIAL_IN_MODEL_OUTPUT", None)
    clean = EMAIL.sub("[REDACTED_EMAIL]", text)
    return Decision("Redact" if clean != text else "Allow", "OUTPUT_INSPECTED", clean)


def inspect_with_budget(text: str, *, max_us: int = 20_000, **kwargs) -> tuple[Decision, int]:
    """Bound measured synchronous inspection overhead; fail closed if the budget is exceeded.

    This limit does not pre-empt Python execution. Callers must additionally enforce
    upstream timeouts and benchmark P95/P99 under their own production workloads.
    """
    from time import perf_counter_ns
    start = perf_counter_ns()
    result = inspect_text(text, **kwargs)
    elapsed_us = (perf_counter_ns() - start) // 1000
    if elapsed_us > max_us:
        return Decision("Block", "GUARDRAIL_EXECUTION_BUDGET_EXCEEDED", None), elapsed_us
    return result, elapsed_us
