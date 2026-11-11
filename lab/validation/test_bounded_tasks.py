import threading
import time
import unittest

from bounded_tasks import run_bounded


class BoundedTaskTests(unittest.TestCase):
    def test_serial_order(self):
        completed = []
        run_bounded(completed.append, range(20), 1)
        self.assertEqual(completed, list(range(20)))

    def test_empty(self):
        run_bounded(lambda x:self.fail('No work expected'), [], 8)

    def test_worker_bound_and_complete_join(self):
        for workers in (2, 4, 8):
            lock, active, peak, completed = threading.Lock(), 0, 0, []
            def task(n):
                nonlocal active, peak
                with lock:
                    active += 1
                    peak = max(peak,active)
                time.sleep(.01)
                with lock:
                    active -= 1
                    completed.append(n)
            run_bounded(task, range(24), workers)
            self.assertLessEqual(peak,workers)
            self.assertGreater(peak,1)
            self.assertEqual(active,0)
            self.assertEqual(sorted(completed),list(range(24)))

    def test_failure_joins_started_tasks_and_stops_new_launches(self):
        entered, finished, lock = [], [], threading.Lock()
        barrier = threading.Barrier(4)
        def task(n):
            with lock:
                entered.append(n)
            barrier.wait(timeout=2)
            if n == 0:
                raise RuntimeError('injected creation failure')
            time.sleep(.05)
            with lock:
                finished.append(n)
        with self.assertRaisesRegex(RuntimeError,'injected'):
            run_bounded(task,range(100),4)
        self.assertEqual(sorted(entered),[0,1,2,3])
        self.assertEqual(sorted(finished),[1,2,3])

    def test_iterator_failure_joins_already_started_task(self):
        entered, finished = threading.Event(), threading.Event()
        def items():
            yield 1
            self.assertTrue(entered.wait(timeout=2))
            raise RuntimeError('iterator failed')
        def task(n):
            entered.set()
            time.sleep(.02)
            finished.set()
        with self.assertRaisesRegex(RuntimeError,'iterator'):
            run_bounded(task,items(),2)
        self.assertTrue(finished.is_set())

    def test_serial_failure_does_not_continue(self):
        entered = []
        def task(n):
            entered.append(n)
            raise OSError('failure')
        with self.assertRaises(OSError):
            run_bounded(task,range(10),1)
        self.assertEqual(entered,[0])

    def test_invalid_workers(self):
        for workers in (True,0,-1,3,16,None):
            with self.assertRaises(ValueError):
                run_bounded(lambda x:None,[1],workers)


if __name__ == '__main__':
    unittest.main()
