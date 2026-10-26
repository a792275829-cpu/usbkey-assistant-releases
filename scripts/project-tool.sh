#!/bin/sh
# Compile local development tools only when their source changes.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE="$ROOT/scripts/ProjectTools.swift"
BINARY="$ROOT/build/tools/project-tool"
if [ ! -x "$BINARY" ] || [ "$SOURCE" -nt "$BINARY" ]; then
    mkdir -p "$ROOT/build/tools"
    TEMP=$(mktemp "$ROOT/build/tools/project-tool.XXXXXX")
    trap 'rm -f "$TEMP"' EXIT HUP INT TERM
    /usr/bin/xcrun swiftc "$SOURCE" -O -o "$TEMP"
    chmod 755 "$TEMP"
    mv "$TEMP" "$BINARY"
fi
cd "$ROOT"
exec "$BINARY" "$@"
