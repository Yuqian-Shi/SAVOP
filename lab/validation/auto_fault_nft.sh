#!/bin/sh
# Only the AS3 Agent PATH contains this wrapper; probes use the real binary.
if [ "$1" = "-f" ]; then
    if [ -f /node/fault-nft-timeout ]; then exec /bin/sleep 30; fi
    if [ -f /node/fault-nft-invalid ]; then
        { /bin/cat "$2"; echo "add rule inet savop missing_fault_chain counter drop"; } | /usr/sbin/nft -f -
        exit $?
    fi
fi
if [ "$1" = "delete" ] && [ -f /node/fault-nft-delete ]; then
    echo "injected nft deletion failure" >&2
    exit 74
fi
exec /usr/sbin/nft "$@"
