import unittest
from pathlib import Path
from unittest.mock import patch
import tempfile
import collector


class CollectorTests(unittest.TestCase):
    @patch("collector.sys.platform", "linux")
    def test_reads_actual_host_with_hashed_identifier(self):
        with tempfile.NamedTemporaryFile(mode="w") as f:
            f.write("secret-machine-identifier")
            f.flush()
            with patch("collector.Path", return_value=Path(f.name)):
                result = collector.snapshot()
            self.assertNotIn("secret-machine-identifier", str(result))
            self.assertEqual(result["category"], "endpoint")
            self.assertTrue(result["external_ref"].startswith("linux-"))


    @unittest.skipUnless(__import__("sys").platform.startswith("linux"), "Linux collector CLI")
    def test_read_only_posture_cli_invokes_registered_helper(self):
        # Exercise the actual CLI entrypoint with an isolated response, not a
        # production collector or an external API. A helper defined after the
        # __main__ invocation would raise NameError at this point.
        import runpy
        import sys
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            credential = Path(directory) / "synthetic-collector-token"
            credential.write_text("test-only-token", encoding="utf-8")
            credential.chmod(0o600)
            argv = [
                "collector.py", "--api", "https://security.example.invalid",
                "--credential-file", str(credential), "--read-only-ssh-posture",
            ]
            with patch.object(sys, "argv", argv), patch("urllib.request.urlopen") as request:
                request.return_value.__enter__.return_value.status = 200
                runpy.run_path(str(Path(collector.__file__)), run_name="__main__")
                self.assertGreaterEqual(request.call_count, 1)



if __name__ == "__main__":
    unittest.main()
