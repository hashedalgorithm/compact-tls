#!/usr/bin/env bash
set -euo pipefail

ROLE="${1:-client}"

case "$ROLE" in
    client)
        cmake -B "build/client" -DCTLS_CLIENT=ON -DCTLS_SERVER=OFF
        cmake --build "build/client"
        ;;
    server)
        cmake -B "build/server" -DCTLS_CLIENT=OFF -DCTLS_SERVER=ON
        cmake --build "build/server"
        ;;
    *)
        echo "Usage: $0 [client|server]" >&2
        exit 1
        ;;
esac
