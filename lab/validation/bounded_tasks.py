"""Bounded launch scheduling: stop submitting on failure, join live work first."""
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait


def run_bounded(function, items, workers):
    if isinstance(workers, bool) or workers not in (1, 2, 4, 8):
        raise ValueError('workers must be one of 1, 2, 4, 8')
    if workers == 1:
        for item in items:
            function(item)
        return
    iterator = iter(items)
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='k5-create') as pool:
        pending = set()
        def submit_one():
            try:
                item = next(iterator)
            except StopIteration:
                return False
            pending.add(pool.submit(function, item))
            return True
        try:
            for _ in range(workers):
                if not submit_one():
                    break
            while pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                # Inspect every completed result BEFORE replenishing the queue.
                for future in done:
                    future.result()
                for _ in done:
                    if not submit_one():
                        break
        except BaseException:
            for future in pending:
                future.cancel()
            # Executor exit joins all started tasks. The caller may safely
            # clean up their complete ownership registry only AFTER this return.
            raise
