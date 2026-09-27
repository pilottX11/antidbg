#!/usr/bin/env bash
# One-command build for Linux/macOS. Builds the library, examples, and tests,
# then runs the tests.
set -euo pipefail

cd "$(dirname "$0")"

BUILD_DIR="${BUILD_DIR:-build}"

echo ">> configuring ($BUILD_DIR)"
cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release "$@"

echo ">> building"
cmake --build "$BUILD_DIR" --config Release

echo ">> testing"
ctest --test-dir "$BUILD_DIR" --build-config Release --output-on-failure

echo ">> done. binaries are in $BUILD_DIR/"
