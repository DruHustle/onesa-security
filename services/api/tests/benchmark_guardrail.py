"""Standalone deterministic guardrail overhead budget gate for CI.

Uses synthetic benign input only and reports local timing, not deployment SLO.
"""
import statistics
import time
from app.guardrails import inspect_with_budget

def main():
    data = "A routine AI request about preventive maintenance." * 10
    for _ in range(100):
        inspect_with_budget(data)
    samples = []
    for _ in range(300):
        start = time.perf_counter_ns()
        decision, elapsed = inspect_with_budget(data)
        duration = (time.perf_counter_ns() - start) / 1000
        if decision.action != "Allow":
            raise SystemExit("Unexpected guardrail rejection on benign fixture")
        samples.append(duration)
    p95 = sorted(samples)[int(len(samples) * .95) - 1]
    p99 = sorted(samples)[int(len(samples) * .99) - 1]
    print(f"Measured benchmark p95={p95:.0f}us p99={p99:.0f}us median={statistics.median(samples):.0f}us; budget p99<=20000us")
    if p99 > 20000:
        raise SystemExit("Guardrail overhead p99 exceeds 20ms synthetic CI budget")

if __name__ == "__main__":
    main()
