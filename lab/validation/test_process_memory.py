import unittest

from process_memory import parse_memory_status


class ProcessMemoryTests(unittest.TestCase):
    def test_pre_exec_counter_does_not_become_post_exec_peak(self):
        value = parse_memory_status('Name: python\nVmHWM: 20480 kB\nVmRSS: 16384 kB\n', 262144)
        self.assertEqual(value['post_exec_peak_rss_mib'],20)
        self.assertEqual(value['current_rss_mib'],16)
        self.assertEqual(value['lifetime_rusage_peak_rss_mib'],256)

    def test_missing_field_rejected(self):
        with self.assertRaisesRegex(ValueError,'Missing'):
            parse_memory_status('VmRSS: 1024 kB\n',1024)

    def test_invalid_units_or_value_rejected(self):
        for text in ('VmHWM: 1024 MB\nVmRSS: 512 kB', 'VmHWM: -1 kB\nVmRSS: 0 kB'):
            with self.assertRaises(ValueError):
                parse_memory_status(text,1024)


if __name__=='__main__':
    unittest.main()
