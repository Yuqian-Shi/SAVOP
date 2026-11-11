import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import fetch_reference


class ReferenceFetchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.payload = b"pinned reference\n"
        self.lock = {"revision": "a" * 40, "files": {
            "sav_agent/common/__init__.py": hashlib.sha256(self.payload).hexdigest()}}
        self.lock_path = self.root / "reference-lock.json"
        self.lock_path.write_text(json.dumps(self.lock))
        self.file_patch = patch.object(fetch_reference, "__file__", str(self.root / "fetch_reference.py"))
        self.file_patch.start()
        self.output = self.root / "reference"

    def tearDown(self):
        self.file_patch.stop()
        self.temp.cleanup()

    def test_verified_fetch_and_cached_recheck(self):
        with patch.object(fetch_reference.urllib.request, "urlopen", return_value=io.BytesIO(self.payload)) as request:
            fetch_reference.fetch(self.output)
            self.assertIn("a" * 40, request.call_args.args[0])
        with patch.object(fetch_reference.urllib.request, "urlopen", side_effect=AssertionError("network not needed")):
            fetch_reference.fetch(self.output)

    def test_download_mismatch_not_installed(self):
        with patch.object(fetch_reference.urllib.request, "urlopen", return_value=io.BytesIO(b"changed")):
            with self.assertRaises(ValueError):
                fetch_reference.fetch(self.output)
        self.assertFalse(self.output.exists())

    def test_existing_corruption_preserved_and_rejected(self):
        path = self.output / "sav_agent/common/__init__.py"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"corrupt")
        with self.assertRaises(ValueError):
            fetch_reference.fetch(self.output)
        self.assertEqual(path.read_bytes(), b"corrupt")

    def test_traversal_and_mutable_revision_rejected(self):
        for update in ({"revision": "main"}, {"files": {"../outside.py": "a" * 64}}):
            self.lock_path.write_text(json.dumps(dict(self.lock, **update)))
            with self.assertRaises(ValueError):
                fetch_reference.fetch(self.output)


if __name__ == "__main__":
    unittest.main()
