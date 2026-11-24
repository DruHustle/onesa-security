from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import ebpf_activity as activity


class ActivityTest(unittest.TestCase):
    def test_verified_stdout_is_an_aggregate_only(self):
        response = subprocess.CompletedProcess([], 0, f"{activity.COMPLETE}\n\n@process_exec: 42\n", "")
        with patch.object(activity.sys, "platform", "linux"), patch.object(activity.subprocess, "run", return_value=response) as run:
            sample = activity.capture()
        self.assertEqual(sample, {
            "schema": "onesa.linux.process-exec.v1",
            "sample_seconds": 10,
            "process_exec_count": 42,
        })
        self.assertEqual(run.call_args.args[0], ["/usr/bin/bpftrace", "-q", "-e", activity.PROBE])
        self.assertTrue(run.call_args.kwargs["check"])
        self.assertEqual(run.call_args.kwargs["timeout"], 25)

    def test_only_completed_empty_capture_counts_as_zero(self):
        self.assertEqual(activity.read_sample(f"{activity.COMPLETE}\n"), 0)
        for invalid in ("", "@process_exec: 4", f"{activity.COMPLETE}\n@process_exec: -1",
                        f"{activity.COMPLETE}\n@process_exec: {2**64}",
                        f"{activity.COMPLETE}\n@process_exec: 4\n@process_exec: 5"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                activity.read_sample(invalid)

    def test_does_not_publish_partial_or_failed_capture(self):
        failures = (FileNotFoundError(), subprocess.CalledProcessError(1, ["bpftrace"]),
                    subprocess.TimeoutExpired(["bpftrace"], 25))
        with patch.object(activity.sys, "platform", "linux"):
            for failure in failures:
                with self.subTest(failure=failure), patch.object(activity.subprocess, "run", side_effect=failure):
                    with self.assertRaises(RuntimeError):
                        activity.capture()
            warning = subprocess.CompletedProcess([], 0, activity.COMPLETE, "dropped tracing event")
            with patch.object(activity.subprocess, "run", return_value=warning), self.assertRaises(RuntimeError):
                activity.capture()

    def test_cli_disallows_arbitrary_probe_arguments(self):
        result = subprocess.run([sys.executable, str(Path(activity.__file__)), "--probe", "custom"],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
