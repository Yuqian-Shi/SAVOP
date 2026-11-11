import copy
import unittest
from run_five_as import validate_namespace
from run_dynamic_five_as import StableWindow, selected_origin
from packet_probe import checksum


class RuntimeGuards(unittest.TestCase):
    def setUp(self):
        self.state = {"State": {"Running": True, "Pid": 111}, "HostConfig": {"NetworkMode": "none", "Privileged": False}}

    def test_owned_isolated_namespace(self):
        validate_namespace(self.state, 111, 222, 222, 333)

    def test_stopped_and_recycled_pid(self):
        for field, value in (("Running", False), ("Pid", 112), ("Pid", 0)):
            state = copy.deepcopy(self.state)
            state["State"][field] = value
            with self.assertRaises(RuntimeError):
                validate_namespace(state, 111, 222, 222, 333)

    def test_host_and_privileged_namespace(self):
        for field, value in (("NetworkMode", "host"), ("NetworkMode", "bridge"), ("Privileged", True)):
            state = copy.deepcopy(self.state)
            state["HostConfig"][field] = value
            with self.assertRaises(RuntimeError):
                validate_namespace(state, 111, 222, 222, 333)

    def test_inode_mismatch_and_host_inode(self):
        for actual, host in ((444, 333), (222, 222)):
            with self.assertRaises(RuntimeError):
                validate_namespace(self.state, 111, 222, actual, host)

    def test_common_stable_window(self):
        window = StableWindow(3)
        self.assertFalse(window.update(0, True, {"n1": 1, "n2": 1}))
        self.assertFalse(window.update(2, True, {"n1": 1, "n2": 2}))
        self.assertFalse(window.update(4, True, {"n1": 1, "n2": 2}))
        self.assertTrue(window.update(5, True, {"n1": 1, "n2": 2}))

    def test_not_ready_resets_window(self):
        window = StableWindow(3)
        window.update(0, True, "same")
        self.assertFalse(window.update(10, False, "same"))
        self.assertFalse(window.update(11, True, "same"))
        self.assertFalse(window.update(13, True, "same"))
        self.assertTrue(window.update(14, True, "same"))

    def test_time_regression_rejected(self):
        window = StableWindow()
        window.update(10, True, "same")
        with self.assertRaises(ValueError):
            window.update(9, True, "same")

    def test_selected_origin_is_explicit(self):
        self.assertEqual(selected_origin("  BGP.as_path: 4200000002 4200000004\n"), 4200000004)
        for text in ("", "BGP.as_path: \n", "BGP.as_path: 1 2\nBGP.as_path: 1 3\n"):
            with self.assertRaises(ValueError):
                selected_origin(text)

    def test_checksum_reference(self):
        self.assertEqual(checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220d)
        self.assertEqual(checksum(bytes.fromhex("0001f203f4f5f6f7220d")), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
