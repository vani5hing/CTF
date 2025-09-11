#!/bin/sh

# Initialize flag from GZCTF_FLAG if provided
if [ -n "$GZCTF_FLAG" ]; then
    printf '%s' "$GZCTF_FLAG" > ./flag.txt 2>/dev/null || true
    chmod 444 ./flag.txt 2>/dev/null || true
    unset GZCTF_FLAG 2>/dev/null || true
fi

# Start the challenge service via socat
exec socat -T 300 -d -d TCP-LISTEN:7272,reuseaddr,fork EXEC:"./chall",pty,raw,echo=0 