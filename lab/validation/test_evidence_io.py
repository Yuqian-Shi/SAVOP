import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from evidence_io import compact_chunks, write_json


class EvidenceIOTests(unittest.TestCase):
    def test_semantic_equality_and_unicode(self):
        data = [{'node': 1, 'fib': [{'dst': 'fd42::/64', 'metric': 4294967295}],
                 'error': '中文\nquote" slash\\', 'auto': {'hash': 18446744073709551615},
                 'extra': [None, True, False, 0.00000000001]}, {'node': 2, 'fib': []}]
        with tempfile.TemporaryDirectory() as directory:
            for mode in ('pretty', 'compact'):
                path = Path(directory)/mode
                write_json(path, data, encoding=mode)
                self.assertEqual(json.loads(path.read_text(encoding='utf-8')), data)
                self.assertTrue(path.read_bytes().endswith(b'\n'))
            pretty = (Path(directory)/'pretty').read_text(encoding='utf-8')
            self.assertEqual(pretty, json.dumps(data, indent=2, ensure_ascii=False)+'\n')

    def test_chunks_are_one_record_not_whole_snapshot(self):
        rows = [{'node': n, 'fib': ['x'*100]*50} for n in range(30)]
        chunks = list(compact_chunks(rows))
        self.assertEqual(json.loads(''.join(chunks)), rows)
        self.assertLess(max(map(len, chunks)), len(''.join(chunks))/20)

    def test_empty_and_scalar(self):
        for value in ([], {}, None, [[], {}, ''], 1, '文字'):
            self.assertEqual(json.loads(''.join(compact_chunks(value))), value)

    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'existing'
            path.write_text('sentinel')
            with self.assertRaises(FileExistsError):
                write_json(path, [])
            self.assertEqual(path.read_text(), 'sentinel')

    def test_encoding_failure_propagates(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(TypeError):
                write_json(Path(directory)/'invalid', [object()])

    def test_write_failure_propagates(self):
        with patch.object(Path, 'open', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                write_json('unused', [])

    def test_invalid_mode_does_not_create(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'invalid'
            with self.assertRaises(ValueError):
                write_json(path, [], encoding='unknown')
            self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()
