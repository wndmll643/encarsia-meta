#!/usr/bin/env bash
# TTB experiment for the 4 Phase A/B hierCov variants:
#
#   hierfuzz_data_bucket_pfuzz_hcov         (was v6a_pfuzz, hierCov-gated)
#   hierfuzz_ctrl_bucket_tree_pfuzz_hcov    (was v11b_pfuzz, hierCov-gated)
#   hierfuzz_data_bucket_tree               (was v11c, plain DifuzzRTL)
#   hierfuzz_data_bucket_tree_pfuzz_hcov    (was v11c_pfuzz, hierCov-gated)
#
# Calls multi_run_ttb.py once per fuzzer so each fuzzer gets the entire
# `-p` worker pool to itself (i.e. all bugs of one fuzzer run in parallel,
# 15 at a time with default -p 15). When fuzzer N's bugs are all done,
# moves on to fuzzer N+1.
#
# Note: as of the fuzzer-major dispatch patch in multi_run_ttb.py, a
# single call with --fuzzers <list> also produces this behavior. This
# wrapper makes the ordering explicit, allows per-fuzzer results dirs if
# you want, and lets you Ctrl-C between fuzzers cleanly.
#
# Defaults: 10 runs per (bug × fuzzer), both rocket and boom, -p 15.
#
# Usage:
#   ./run_experiments_4variant.sh -d <ENCORPUS_DIR>
#   ./run_experiments_4variant.sh -d <ENCORPUS_DIR> -p 15 -N 10 -H rocket boom
#   ./run_experiments_4variant.sh -d <ENCORPUS_DIR> --aggregate-only
#   ./run_experiments_4variant.sh -d <ENCORPUS_DIR> --skip-fuzzer hierfuzz_data_bucket_tree
#
# Flags forwarded to multi_run_ttb.py (any unknown flags pass through):
#   -d / --directory           required, EnCorpus root
#   -H / --hosts               default "rocket boom"
#   -p / --processes           default 15
#   -N / --n-runs              default 10
#   --results-dir              default out/ttb_results_4variant
#   --early-stop K             default 10
#   --aggregate-only           reparse existing results into CSV, exit

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DEFAULT_FUZZERS=(
  hierfuzz_data_bucket_pfuzz_hcov
  hierfuzz_ctrl_bucket_tree_pfuzz_hcov
  hierfuzz_data_bucket_tree
  hierfuzz_data_bucket_tree_pfuzz_hcov
)

DIRECTORY=""
HOSTS=()
PROCESSES=15
N_RUNS=10
RESULTS_DIR="out/ttb_results_4variant"
SKIP_FUZZERS=()
AGGREGATE_ONLY=0
PASSTHROUGH=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--directory)        DIRECTORY="$2"; shift 2 ;;
    -H|--hosts)            shift; while [[ $# -gt 0 && "$1" != -* ]]; do HOSTS+=("$1"); shift; done ;;
    -p|--processes)        PROCESSES="$2"; shift 2 ;;
    -N|--n-runs)           N_RUNS="$2"; shift 2 ;;
    --results-dir)         RESULTS_DIR="$2"; shift 2 ;;
    --skip-fuzzer)         SKIP_FUZZERS+=("$2"); shift 2 ;;
    --aggregate-only)      AGGREGATE_ONLY=1; shift ;;
    -h|--help)             sed -n '1,40p' "$0"; exit 0 ;;
    -D|--driver-bugs|-M|--mux-bugs|--multiplexer-bugs)
      PASSTHROUGH+=("$1"); shift
      while [[ $# -gt 0 && "$1" != -* ]]; do PASSTHROUGH+=("$1"); shift; done
      ;;
    *)                     PASSTHROUGH+=("$1"); shift ;;
  esac
done

if [[ -z "$DIRECTORY" ]]; then
  echo "ERROR: -d/--directory <ENCORPUS_DIR> is required." >&2
  exit 1
fi

if [[ ${#HOSTS[@]} -eq 0 ]]; then
  HOSTS=(rocket boom)
fi

# Filter out skipped fuzzers.
FUZZERS=()
for f in "${DEFAULT_FUZZERS[@]}"; do
  skip=0
  for s in "${SKIP_FUZZERS[@]}"; do
    [[ "$s" == "$f" ]] && { skip=1; break; }
  done
  [[ $skip -eq 0 ]] && FUZZERS+=("$f")
done

if [[ ${#FUZZERS[@]} -eq 0 ]]; then
  echo "ERROR: no fuzzers left after applying --skip-fuzzer." >&2
  exit 1
fi

MULTI_RUN_TTB="$SCRIPT_DIR/multi_run_ttb.py"
if [[ ! -f "$MULTI_RUN_TTB" ]]; then
  echo "ERROR: multi_run_ttb.py not found at $MULTI_RUN_TTB" >&2
  exit 1
fi

echo "=== 4-variant TTB experiment ==="
echo "Fuzzers:       ${FUZZERS[*]}"
echo "Hosts:         ${HOSTS[*]}"
echo "EnCorpus:      $DIRECTORY"
echo "Results dir:   $RESULTS_DIR"
echo "Processes:     $PROCESSES (per fuzzer)"
echo "Runs per pair: $N_RUNS"
[[ ${#PASSTHROUGH[@]} -gt 0 ]] && echo "Passthrough:   ${PASSTHROUGH[*]}"
echo

ALL_RC=0
for FZ in "${FUZZERS[@]}"; do
  echo "=============================================================="
  echo "[ $(date +%H:%M:%S) ] Starting fuzzer: $FZ"
  echo "=============================================================="

  ARGS=(
    python3 "$MULTI_RUN_TTB"
    -d "$DIRECTORY"
    -H "${HOSTS[@]}"
    -p "$PROCESSES"
    -N "$N_RUNS"
    --results-dir "$RESULTS_DIR"
    --fuzzers "$FZ"
  )
  if [[ $AGGREGATE_ONLY -eq 1 ]]; then ARGS+=(--aggregate-only); fi
  if [[ ${#PASSTHROUGH[@]} -gt 0 ]]; then ARGS+=("${PASSTHROUGH[@]}"); fi

  echo "Launch: ${ARGS[*]}"
  if ! "${ARGS[@]}"; then
    echo "WARN: fuzzer $FZ exited non-zero. Continuing with next fuzzer."
    ALL_RC=1
  fi

  echo "[ $(date +%H:%M:%S) ] Finished fuzzer: $FZ"
  echo
done

# Final aggregate across all fuzzers in the unified results dir.
echo "=== Final aggregate ==="
python3 "$MULTI_RUN_TTB" \
    -d "$DIRECTORY" -H "${HOSTS[@]}" -p "$PROCESSES" -N "$N_RUNS" \
    --results-dir "$RESULTS_DIR" \
    --fuzzers "${FUZZERS[@]}" \
    --aggregate-only || true

CSV="$RESULTS_DIR/ttb_summary.csv"
[[ -f "$CSV" ]] && echo "Aggregated TTB CSV: $CSV"

exit $ALL_RC
