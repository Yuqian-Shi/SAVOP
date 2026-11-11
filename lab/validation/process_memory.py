"""Separate Linux post-exec memory estimates from lifetime getrusage counters."""
from pathlib import Path


def parse_memory_status(text, lifetime_rss_kib):
    values = {}
    for line in text.splitlines():
        if line.startswith(('VmHWM:', 'VmRSS:')):
            key, amount, unit = line.split()
            if unit != 'kB' or int(amount) < 0:
                raise ValueError('Unexpected Linux memory units/value')
            values[key.rstrip(':')] = int(amount)/1024
    if set(values) != {'VmHWM','VmRSS'}:
        raise ValueError('Missing process memory fields')
    return dict(post_exec_peak_rss_mib=values['VmHWM'], current_rss_mib=values['VmRSS'],
                lifetime_rusage_peak_rss_mib=lifetime_rss_kib/1024,
                accounting='Linux /proc/self/status VmHWM estimate for this executable; lifetime getrusage can include pre-exec memory; excludes router containers')


def snapshot():
    import resource
    return parse_memory_status(Path('/proc/self/status').read_text(),
                               resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
