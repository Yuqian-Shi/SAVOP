import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from evidence_paths import evidence_parent, validate_evidence_root


class EvidencePathTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.parent = Path(self.temp.name).resolve()
        self.env = patch.dict(os.environ, {"SAVOP_EVIDENCE_PARENT": str(self.parent)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_fresh_custom_parent(self):
        root = self.parent / "k5-ts01-bgp01-test"
        self.assertEqual(validate_evidence_root(root, "k5-ts01-bgp01-", must_exist=False), root)

    def test_existing_root_required(self):
        root = self.parent / "k5-capacity-test"
        with self.assertRaises(FileNotFoundError):
            validate_evidence_root(root, "k5-capacity-")
        root.mkdir()
        self.assertEqual(validate_evidence_root(root, "k5-capacity-"), root)
        with self.assertRaises(ValueError):
            validate_evidence_root(root, "k5-capacity-", must_exist=False)

    def test_wrong_parent_and_prefix(self):
        for root in (self.parent / "unrelated", self.parent / "child" / "k5-capacity-test"):
            with self.assertRaises((ValueError, FileNotFoundError)):
                validate_evidence_root(root, "k5-capacity-", must_exist=False)

    def test_relative_and_parent_traversal(self):
        for root in (Path("k5-capacity-test"), self.parent / ".." / "k5-capacity-test"):
            with self.assertRaises(ValueError):
                validate_evidence_root(root, "k5-capacity-", must_exist=False)

    def test_symlink_refused(self):
        link = self.parent / "k5-capacity-link"
        try:
            link.symlink_to(self.parent, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation not available")
        with self.assertRaises(ValueError):
            validate_evidence_root(link, "k5-capacity-")

    def test_filesystem_root_refused(self):
        with patch.dict(os.environ, {"SAVOP_EVIDENCE_PARENT": "/"}):
            with self.assertRaises(ValueError):
                evidence_parent()


if __name__ == "__main__":
    unittest.main()
