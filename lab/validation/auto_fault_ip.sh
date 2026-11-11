#!/bin/sh
# Only the AS3 Agent PATH contains this wrapper; never installed on the host.
if [ -f /node/fault-ip-timeout ]; then exec /bin/sleep 30; fi
if [ -f /node/fault-ip-error ]; then echo "injected FIB read failure" >&2; exit 73; fi
if [ -f /node/fault-ip-malformed ]; then echo '{"invalid":"not a route array"}'; exit 0; fi
exec /usr/sbin/ip "$@"
