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


if __name__ == "__main__":
    unittest.main()
