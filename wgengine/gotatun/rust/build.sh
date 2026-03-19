#!/bin/bash
# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause

# build.sh builds the gotatun Rust FFI library as a static archive.
#
# Usage:
#   ./build.sh                    # Build for host platform
#   ./build.sh --target aarch64-apple-ios  # Cross-compile for iOS
#   ./build.sh --release          # Release build (default)
#   ./build.sh --debug            # Debug build
#
# The output is a static library at:
#   target/<target>/release/libgotatun_ffi.a

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CARGO_ARGS=("build")
BUILD_TYPE="release"
TARGET=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET="$2"
            CARGO_ARGS+=("--target" "$2")
            shift 2
            ;;
        --debug)
            BUILD_TYPE="debug"
            shift
            ;;
        --release)
            BUILD_TYPE="release"
            shift
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

if [[ "$BUILD_TYPE" == "release" ]]; then
    CARGO_ARGS+=("--release")
fi

echo "Building gotatun FFI library..."
echo "  Build type: $BUILD_TYPE"
echo "  Target: ${TARGET:-host}"

cargo "${CARGO_ARGS[@]}"

# Determine output path
if [[ -n "$TARGET" ]]; then
    LIB_PATH="target/$TARGET/$BUILD_TYPE/libgotatun_ffi.a"
else
    LIB_PATH="target/$BUILD_TYPE/libgotatun_ffi.a"
fi

if [[ -f "$LIB_PATH" ]]; then
    echo "Built: $LIB_PATH"
    ls -lh "$LIB_PATH"
else
    echo "Error: expected output not found at $LIB_PATH" >&2
    exit 1
fi
