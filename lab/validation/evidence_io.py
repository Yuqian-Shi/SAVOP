"""Lossless, bounded-top-level-record JSON encoding for observation evidence.

The compact path materializes at most one node record, not the whole list.
Exclusive creation and synchronous errors preserve the previous writer's
no-overwrite/error behavior. Flush-on-close is unchanged; neither mode fsyncs.
"""
import json
from pathlib import Path


def compact_chunks(value):
    if isinstance(value, (list, tuple)):
        yield '['
        for index, row in enumerate(value):
            if index:
                yield ','
            yield json.dumps(row, ensure_ascii=False, separators=(',', ':'))
        yield ']'
    else:
        yield json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def write_json(path, value, *, encoding='compact'):
    if encoding not in ('pretty', 'compact'):
        raise ValueError('Unknown evidence encoding')
    with Path(path).open('x', encoding='utf-8') as stream:
        if encoding == 'pretty':
            json.dump(value, stream, indent=2, ensure_ascii=False)
        else:
            for chunk in compact_chunks(value):
                stream.write(chunk)
        stream.write('\n')
