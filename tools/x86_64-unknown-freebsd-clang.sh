#!/bin/sh

SYS_ROOT="$TOOLCHAINS_ROOT/x86_64-unknown-freebsd/sysroot"
if [ ! -d "$SYS_ROOT" ]; then
    >&2 echo "Toolchain root not found: $TOOLCHAINS_ROOT"
    exit 1
fi

exec clang "--sysroot=$SYS_ROOT" "$@"
