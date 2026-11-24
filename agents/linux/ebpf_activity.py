#!/usr/bin/env python3
"""Capture one aggregate Linux process-execution sample with a fixed eBPF probe."""

import argparse
import json
import re
import subprocess
import sys


SAMPLE_SECONDS = 10
PROBE = f"""
tracepoint:sched:sched_process_exec {{ @process_exec = count(); }}
interval:s:{SAMPLE_SECONDS} {{ printf("onesa_window_complete\\n"); exit(); }}
"""
COMPLETE = "onesa_window_complete"
COUNT = re.compile(r"@process_exec: (0|[1-9][0-9]{0,19})")


def read_sample(output: str) -> int:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines or lines[0] != COMPLETE or len(lines) > 2:
        raise ValueError("The eBPF capture did not produce a complete sample")
    if len(lines) == 1:
        # bpftrace omits an empty map from the final dump.
        return 0
    match = COUNT.fullmatch(lines[1])
    if match is None or int(match[1]) >= 2**64:
        raise ValueError("The eBPF capture returned an invalid count")
    return int(match[1])


def capture() -> dict[str, int | str]:
    if sys.platform != "linux":
        raise RuntimeError("The eBPF capture requires Linux")
    try:
        result = subprocess.run(
            ["/usr/bin/bpftrace", "-q", "-e", PROBE],
            cwd="/",
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=SAMPLE_SECONDS + 15,
            check=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Install bpftrace from the Linux distribution") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("The eBPF capture timed out before completion") from exc
    except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
        raise RuntimeError("bpftrace could not complete the capture; check host permissions and tracepoint support") from exc
    if result.stderr.strip():
        raise RuntimeError("bpftrace reported a warning or error; the sample was discarded")
    return {
        "schema": "onesa.linux.process-exec.v1",
        "sample_seconds": SAMPLE_SECONDS,
        "process_exec_count": read_sample(result.stdout),
    }


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        print(json.dumps(capture()))
    except (RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
