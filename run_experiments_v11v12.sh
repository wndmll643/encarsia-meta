#!/usr/bin/env bash
# TTB experiment runner for the v11 / v12 comparison.
#
# Compares 10 fuzzers — v6a, v6b, v9a, v6a_pfuzz, v11a, v11b, v12a, v12b,
# difuzzrtl, processorfuzz — against the same bug list `encarsia_exp5` ran
# (an EnCorpus directory the caller points at via -d).
#
# Defaults: 10 runs per (bug × fuzzer), both rocket and boom hosts,
# single-process execution. All flags forward to multi_run_ttb.py.
#
# The four new variants (v11a/v11b/v12a/v12b) need the matching Yosys
# passes (hierfuzz_instrument_v11a etc., registered in
# encarsia-yosys/passes/hierfuzz/instrument_hierfuzz.cc) compiled into the
# Yosys binary at YOSYS_PATH. The preflight check below confirms each new
# pass is loadable before the long fuzz starts — if it errors here, rebuild
# Yosys at the remote and retry.
#
# Usage:
#   ./run_experiments_v11v12.sh -d <ENCORPUS_DIR>
#   ./run_experiments_v11v12.sh -d <ENCORPUS_DIR> -p 8 -N 10 -H rocket boom
#   ./run_experiments_v11v12.sh -d <ENCORPUS_DIR> --phase0-only
#   ./run_experiments_v11v12.sh -d <ENCORPUS_DIR> --aggregate-only
#
# Flags forwarded to multi_run_ttb.py:
#   -d / --directory           required, EnCorpus root
#   -H / --hosts               default "rocket boom"
#   -p / --processes           default 1
#   -N / --n-runs              default 10
#   --results-dir              default out/ttb_results
#   --fuzzers                  default 10-way comparison list
#   --phase0-only              compile only, exit
#   --skip-phase0              skip compile phase
#   --aggregate-only           reparse existing results into CSV, exit

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default 10-way fuzzer list. Override with --fuzzers if you want a subset.
DEFAULT_FUZZERS=(
  hierfuzz_data_bucket           # was hierfuzz_v6a
  hierfuzz_ctrl_bucket           # was hierfuzz_v6b
  hierfuzz_ctrl_fold             # was hierfuzz_v9a
  hierfuzz_data_bucket_pfuzz     # was hierfuzz_v6a_pfuzz
  hierfuzz_v11a                  # legacy
  hierfuzz_ctrl_bucket_tree      # was hierfuzz_v11b
  hierfuzz_v12a                  # legacy
  hierfuzz_v12b                  # legacy
  ttb_difuzzrtl
  ttb_processorfuzz
)

# Forward args verbatim to multi_run_ttb.py, with defaults filled in.
DIRECTORY=""
HOSTS=()
PROCESSES=1
N_RUNS=10
RESULTS_DIR="out/ttb_results"
FUZZERS=()
PHASE0_ONLY=0
SKIP_PHASE0=0
AGGREGATE_ONLY=0
PASSTHROUGH=()

# Simple flag loop (not argparse-perfect; matches the multi_run_ttb.py CLI shape).
# Unknown flags get forwarded to multi_run_ttb.py untouched so its own argparse
# can handle them (covers -D/--driver-bugs, -M/--mux-bugs, --early-stop, …).
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--directory)        DIRECTORY="$2"; shift 2 ;;
    -H|--hosts)            shift; while [[ $# -gt 0 && "$1" != -* ]]; do HOSTS+=("$1"); shift; done ;;
    -p|--processes)        PROCESSES="$2"; shift 2 ;;
    -N|--n-runs)           N_RUNS="$2"; shift 2 ;;
    --results-dir)         RESULTS_DIR="$2"; shift 2 ;;
    --fuzzers)             shift; while [[ $# -gt 0 && "$1" != -* ]]; do FUZZERS+=("$1"); shift; done ;;
    --phase0-only)         PHASE0_ONLY=1; shift ;;
    --skip-phase0)         SKIP_PHASE0=1; shift ;;
    --aggregate-only)      AGGREGATE_ONLY=1; shift ;;
    -h|--help)             sed -n '1,30p' "$0"; exit 0 ;;
    # Flags with nargs='+' on the inner argparse — slurp following positional
    # values until the next dash-flag.
    -D|--driver-bugs|-M|--mux-bugs|--multiplexer-bugs)
      PASSTHROUGH+=("$1"); shift
      while [[ $# -gt 0 && "$1" != -* ]]; do PASSTHROUGH+=("$1"); shift; done
      ;;
    # Single-value pass-throughs (--early-stop, etc.):
    *)                     PASSTHROUGH+=("$1"); shift ;;
  esac
done

if [[ -z "$DIRECTORY" ]]; then
  echo "ERROR: -d/--directory <ENCORPUS_DIR> is required." >&2
  echo "Run with -h for usage." >&2
  exit 1
fi

if [[ ${#HOSTS[@]} -eq 0 ]]; then
  HOSTS=(rocket boom)
fi

if [[ ${#FUZZERS[@]} -eq 0 ]]; then
  FUZZERS=("${DEFAULT_FUZZERS[@]}")
fi

# Locate the Python orchestrator.
MULTI_RUN_TTB="$SCRIPT_DIR/multi_run_ttb.py"
if [[ ! -f "$MULTI_RUN_TTB" ]]; then
  echo "ERROR: multi_run_ttb.py not found at $MULTI_RUN_TTB" >&2
  exit 1
fi

# Preflight: confirm the four new Yosys passes are loadable. Only needed
# when the fuzzer list actually contains v11/v12 — otherwise skip silently.
NEED_NEW_PASSES=()
for f in "${FUZZERS[@]}"; do
  case "$f" in
    hierfuzz_v11a) NEED_NEW_PASSES+=(hierfuzz_instrument_v11a) ;;
    hierfuzz_ctrl_bucket_tree) NEED_NEW_PASSES+=(hierfuzz_instrument_ctrl_bucket_tree) ;;
    hierfuzz_v12a) NEED_NEW_PASSES+=(hierfuzz_instrument_v12a) ;;
    hierfuzz_v12b) NEED_NEW_PASSES+=(hierfuzz_instrument_v12b) ;;
  esac
done

if [[ ${#NEED_NEW_PASSES[@]} -gt 0 && $AGGREGATE_ONLY -eq 0 ]]; then
  # Resolve the yosys binary the DUT classes will use. defines.py typically
  # has YOSYS_PATH = "yosys" (a bare command name), so the literal `test -x`
  # below would fail even when yosys is fully available via $PATH. Run it
  # through `command -v` when it doesn't contain a slash, so PATH lookup
  # works and the preflight actually fires inside the container.
  YOSYS_RAW="$(python3 -c "import sys; sys.path.insert(0, '$SCRIPT_DIR'); import defines; print(defines.YOSYS_PATH)" 2>/dev/null || true)"
  YOSYS_BIN=""
  if [[ -n "$YOSYS_RAW" ]]; then
    if [[ "$YOSYS_RAW" == */* ]]; then
      YOSYS_BIN="$YOSYS_RAW"
    else
      YOSYS_BIN="$(command -v "$YOSYS_RAW" 2>/dev/null || true)"
    fi
  fi

  if [[ -z "$YOSYS_BIN" || ! -x "$YOSYS_BIN" ]]; then
    echo "WARN: could not resolve defines.YOSYS_PATH ('$YOSYS_RAW') to an executable; skipping preflight." >&2
    echo "      If v11/v12 fuzzers fail with 'command not found', rebuild Yosys with the" >&2
    echo "      updated encarsia-yosys/passes/hierfuzz/instrument_hierfuzz.cc and retry." >&2
  else
    echo "Preflight: confirming Yosys passes ${NEED_NEW_PASSES[*]} are loadable via $YOSYS_BIN ..."
    HELP_CMD=""
    for p in "${NEED_NEW_PASSES[@]}"; do
      HELP_CMD+="help $p; "
    done
    if ! "$YOSYS_BIN" -p "$HELP_CMD" > /dev/null 2>&1; then
      echo "ERROR: Yosys at $YOSYS_BIN does not export one or more of: ${NEED_NEW_PASSES[*]}" >&2
      echo "       Rebuild Yosys with the updated instrument_hierfuzz.cc (or drop the v11/v12" >&2
      echo "       fuzzers from --fuzzers) and retry." >&2
      exit 1
    fi
    echo "Preflight OK."
  fi
fi

# Build the actual multi_run_ttb.py invocation.
ARGS=(
  python3 "$MULTI_RUN_TTB"
  -d "$DIRECTORY"
  -H "${HOSTS[@]}"
  -p "$PROCESSES"
  -N "$N_RUNS"
  --results-dir "$RESULTS_DIR"
  --fuzzers "${FUZZERS[@]}"
)
if [[ $PHASE0_ONLY -eq 1 ]];    then ARGS+=(--phase0-only); fi
if [[ $SKIP_PHASE0 -eq 1 ]];    then ARGS+=(--skip-phase0); fi
if [[ $AGGREGATE_ONLY -eq 1 ]]; then ARGS+=(--aggregate-only); fi
if [[ ${#PASSTHROUGH[@]} -gt 0 ]]; then ARGS+=("${PASSTHROUGH[@]}"); fi

echo "Launch: ${ARGS[*]}"
"${ARGS[@]}"
RC=$?

if [[ $RC -eq 0 ]]; then
  CSV="$RESULTS_DIR/ttb_summary.csv"
  if [[ -f "$CSV" ]]; then
    echo
    echo "Aggregated TTB CSV: $CSV"
  fi
fi
exit $RC
