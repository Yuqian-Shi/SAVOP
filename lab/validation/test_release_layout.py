import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class ReleaseLayoutTests(unittest.TestCase):
    def test_required_router_source_header_retained(self):
        self.assertIn('_BIRD_CONFIG_H_', (ROOT / 'router/sysdep/config.h').read_text())

    def test_prepare_precedes_parallel_build(self):
        script = (ROOT / 'lab/build_router.sh').read_text()
        self.assertLess(script.index('make prepare'), script.index('make -j "$JOBS" all'))

    def test_original_attribution_and_license_texts(self):
        self.assertIn('Copyright (c) 2024 NASP', (ROOT / 'LICENSES/MIT.txt').read_text())
        for name in ('GPL-2.0.txt', 'LGPL-2.0.txt', 'LGPL-2.1.txt'):
            self.assertGreater((ROOT / 'LICENSES' / name).stat().st_size, 10000)

    def test_public_spec_separates_history(self):
        spec = json.loads((ROOT / 'lab/validation/scenarios/ts01-bgp-01.json').read_text())
        self.assertFalse(any(key.startswith('runtime_') for key in spec))
        self.assertEqual(spec['scope']['as_count'], 5)
        self.assertEqual(spec['scope']['router_nodes'], 50)


if __name__ == '__main__':
    unittest.main()
