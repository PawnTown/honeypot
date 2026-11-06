#!/usr/bin/env bash
# Runs the tests with coverage and fails unless every line, branch and
# function of lib/ is covered.
set -euo pipefail
cd "$(dirname "$0")/.."
dart run coverage:test_with_coverage --function-coverage --branch-coverage
awk -F'[:,]' '
  /^DA:/   { lt++; if ($3 > 0) lh++ }
  /^BRDA:/ { bt++; if ($5 != "-" && $5 > 0) bh++ }
  /^FNF:/  { ft += $2 } /^FNH:/ { fh += $2 }
  END {
    printf "lines %d/%d, branches %d/%d, functions %d/%d\n", lh, lt, bh, bt, fh, ft
    if (lh != lt || bh != bt || fh != ft) { print "coverage below 100%"; exit 1 }
  }' coverage/lcov.info
