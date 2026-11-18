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



    def test_refuses_unsafe_collector_origins_before_loading_credentials(self):
        untrusted = [
            "http://security.example.invalid",
            "https://user@security.example.invalid",
            "https://user:pass@security.example.invalid",
            "https://security.example.invalid/?debug=1",
            "https://security.example.invalid/#fragment",
            "https://security.example.invalid/other",
        ]
        for origin in untrusted:
            with self.subTest(origin=origin), patch("collector.urlopen") as network:
                with self.assertRaises(ValueError):
                    collector.send(origin, "no-such-credential-file", None)
                network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
