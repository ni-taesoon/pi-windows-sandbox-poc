#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BIN=$(mktemp)
trap 'rm -f "$BIN"' EXIT
c++ -std=c++17 -Wall -Wextra -Werror -pedantic "$ROOT/tests/supervisor-contract/contract.cpp" -o "$BIN"
"$BIN"
