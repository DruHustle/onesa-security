import tempfile
import unittest
from pathlib import Path
from collector import inspect_sshd_baseline


class ReadOnlyPostureTests(unittest.TestCase):
    def test_explicit_insecure_file_hints_without_configuration_content(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'sshd_config'
            cfg.write_text('# PermitRootLogin yes\nPermitRootLogin yes\nPasswordAuthentication no\n')
            found = inspect_sshd_baseline(cfg)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]['severity'], 'high')
            self.assertNotIn('PermitRootLogin yes', str(found))
            self.assertIn('may be overridden', found[0]['limitations'])

    def test_missing_file_returns_no_claims(self):
        self.assertEqual(inspect_sshd_baseline('/this/path/does-not-exist-onesa'), [])
