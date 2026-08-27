#!/usr/bin/env bash
# derive-sources-prefix.sh <symbols.so> <crate-src-suffix>
#
# Print the SourcesOriginalPath that will actually match the coverage profile.
#
# The cover task keys every LCOV line on the DWARF compile-unit path (prefixed by
# DW_AT_comp_dir when one is present) and then runs the equivalent of
# `Info.Has(SourcesOriginalPath)`. If nothing carries that prefix it FAILS the
# whole task -- "SourcesOriginalPath ... does not match any source file in the
# coverage profile" -- and the project renders lines_found: 0 with every CI step
# still green.
#
# Guessing the prefix does not work. Observed on real SBF artifacts:
#   * comp_dir is frequently ABSENT entirely, so "read comp_dir and prepend it"
#     silently degrades to a bare relative guess;
#   * unit paths are a MIX -- `programs/<crate>/src/lib.rs`, bare `src/lib.rs`
#     (dependencies), and `program-libs/...` -- in one artifact;
#   * whether the program's own units are repo-relative or absolute depends on
#     how it was built (`--debug` vs a plain release build), so the same
#     hardcoded prefix is right one day and wrong the next.
#
# So: read the unit paths and find the prefix EMPIRICALLY. Print nothing and exit
# non-zero when no unit matches, so the caller can fail instead of shipping a
# bundle whose coverage silently renders empty.
set -euo pipefail

so="${1:?usage: derive-sources-prefix.sh <symbols.so> <crate-src-suffix>}"
suffix="${2:?missing crate src suffix, e.g. programs/shielded-pool/src/}"

dd=""
command -v llvm-dwarfdump >/dev/null 2>&1 && dd=llvm-dwarfdump
[ -z "$dd" ] && command -v dwarfdump >/dev/null 2>&1 && dd=dwarfdump
# Debian's `llvm` package installs a VERSIONED binary and no unsuffixed alias, so
# `command -v llvm-dwarfdump` finds nothing on a runner that did install llvm.
if [ -z "$dd" ]; then
  for c in /usr/lib/llvm-*/bin/llvm-dwarfdump /usr/bin/llvm-dwarfdump-*; do
    [ -x "$c" ] && dd="$c" && break
  done
fi
[ -n "$dd" ] || { echo "no llvm-dwarfdump available" >&2; exit 2; }

"$dd" --debug-info "$so" 2>/dev/null | awk -v suffix="$suffix" '
  match($0, /DW_AT_comp_dir[ \t]*\("[^"]*"\)/) {
    s = substr($0, RSTART, RLENGTH); gsub(/.*\("|"\)/, "", s); comp = s; next
  }
  match($0, /DW_AT_name[ \t]*\("[^"]*\.rs[^"]*"\)/) {
    s = substr($0, RSTART, RLENGTH); gsub(/.*\("|"\)/, "", s)
    sub(/\/@\/.*$/, "", s)                      # strip the codegen-unit suffix
    full = (comp != "" ? comp "/" s : s)
    i = index(full, suffix)
    if (i > 0) print substr(full, 1, i + length(suffix) - 1)
  }
' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}'
