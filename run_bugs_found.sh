#!/usr/bin/env bash
# Bugs-found-per-fuzzer experiment driver.
#
# Designed to run inside the encarsia_hierfuzz:v3 container (e.g. encarsia_exp6).
# Steps map to /home/sinu/.claude/plans/smooth-doodling-storm.md:
#   1. inject  — generate ~1000 raw bugs per host
#   2. verify  — Yosys formal-verify filter (keeps non-equivalent bugs)
#   3. select  — sample down to N_BUGS per host
#   4. compile — Phase 0 compile of all (bug, fuzzer) pairs
#   5. fuzz_core4 / fuzz_full8 — multi-run fuzzing
#   6. aggregate — pivot to bugs_found.md
#
# Usage:
#   ./run_bugs_found.sh inject
#   ./run_bugs_found.sh verify
#   ./run_bugs_found.sh select
#   ./run_bugs_found.sh compile
#   ./run_bugs_found.sh fuzz_core4
#   ./run_bugs_found.sh fuzz_full8
#   ./run_bugs_found.sh aggregate
#   ./run_bugs_found.sh all          # runs everything sequentially

set -euo pipefail

CORPUS_DIR="${CORPUS_DIR:-out/LargeCorpus}"
RESULTS_DIR="${RESULTS_DIR:-out/large_bugs_results}"
HOSTS="${HOSTS:-rocket boom}"
PROCS="${PROCS:-30}"
FUZZ_PROCS="${FUZZ_PROCS:-15}"
N_RUNS="${N_RUNS:-3}"
EARLY_STOP="${EARLY_STOP:-2}"
N_BUGS="${N_BUGS:-250}"

CORE4=(hierfuzz_v6a hierfuzz_v9a ttb_difuzzrtl ttb_processorfuzz)
FULL8=(hierfuzz_v6a hierfuzz_v6b hierfuzz_v6a_pfuzz \
       hierfuzz_v9a hierfuzz_v9a_pfuzz ttb_difuzzrtl \
       ttb_processorfuzz filtered_cascade)

cd /encarsia-meta

inject() {
  echo "=== Step 1: inject raw bug pool into ${CORPUS_DIR} ==="
  python encarsia.py -d "${CORPUS_DIR}" -H ${HOSTS} -p "${PROCS}"
}

verify() {
  echo "=== Step 2: Yosys formal-verify filter ==="
  python encarsia.py -d "${CORPUS_DIR}" -H ${HOSTS} -p "${PROCS}" -Y
}

select_subset() {
  echo "=== Step 3: select ${N_BUGS}-bug deterministic subset per host ==="
  python select_bug_subset.py -d "${CORPUS_DIR}" -H ${HOSTS} -n "${N_BUGS}"
}

# Build -D / -M flag arrays from the selected_*_bugs.txt files.
# Populates SELECTED_DRIVER_BUGS / SELECTED_MUX_BUGS globals for reuse.
load_selected_args() {
  SELECTED_DRIVER_BUGS=()
  SELECTED_MUX_BUGS=()
  for h in ${HOSTS}; do
    local drv_file="${CORPUS_DIR}/${h}/selected_driver_bugs.txt"
    local mux_file="${CORPUS_DIR}/${h}/selected_mux_bugs.txt"
    if [[ -f "${drv_file}" ]]; then
      while IFS= read -r bug_id; do
        [[ -n "${bug_id}" ]] && SELECTED_DRIVER_BUGS+=("${bug_id}")
      done < "${drv_file}"
    fi
    if [[ -f "${mux_file}" ]]; then
      while IFS= read -r bug_id; do
        [[ -n "${bug_id}" ]] && SELECTED_MUX_BUGS+=("${bug_id}")
      done < "${mux_file}"
    fi
  done
}

compile_phase() {
  echo "=== Step 4: Phase 0 compile (all 8 fuzzers, parallel) ==="
  mkdir -p "${RESULTS_DIR}"
  load_selected_args
  python multi_run_ttb.py \
    -d "${CORPUS_DIR}" -H ${HOSTS} -p "${PROCS}" -N "${N_RUNS}" \
    --results-dir "${RESULTS_DIR}" \
    --fuzzers ${FULL8[@]} \
    "${SELECTED_DRIVER_BUGS[@]/#/-D}" \
    "${SELECTED_MUX_BUGS[@]/#/-M}" \
    --phase0-only
}

fuzz_core4() {
  echo "=== Step 5a: Core 4 fuzz sweep ==="
  mkdir -p "${RESULTS_DIR}"
  load_selected_args
  python multi_run_ttb.py \
    -d "${CORPUS_DIR}" -H ${HOSTS} -p "${FUZZ_PROCS}" -N "${N_RUNS}" \
    --early-stop "${EARLY_STOP}" --skip-phase0 \
    --results-dir "${RESULTS_DIR}" \
    --fuzzers ${CORE4[@]} \
    "${SELECTED_DRIVER_BUGS[@]/#/-D}" \
    "${SELECTED_MUX_BUGS[@]/#/-M}" \
    2>&1 | tee -a "${RESULTS_DIR}/core4.log"
}

fuzz_full8() {
  echo "=== Step 5b: Full 8 fuzz sweep (resumes Core 4) ==="
  mkdir -p "${RESULTS_DIR}"
  load_selected_args
  python multi_run_ttb.py \
    -d "${CORPUS_DIR}" -H ${HOSTS} -p "${FUZZ_PROCS}" -N "${N_RUNS}" \
    --early-stop "${EARLY_STOP}" --skip-phase0 \
    --results-dir "${RESULTS_DIR}" \
    --fuzzers ${FULL8[@]} \
    "${SELECTED_DRIVER_BUGS[@]/#/-D}" \
    "${SELECTED_MUX_BUGS[@]/#/-M}" \
    2>&1 | tee -a "${RESULTS_DIR}/full8.log"
}

aggregate() {
  echo "=== Step 6: aggregate + pivot ==="
  python multi_run_ttb.py --aggregate-only \
    -d "${CORPUS_DIR}" -H ${HOSTS} -N "${N_RUNS}" \
    --results-dir "${RESULTS_DIR}" \
    --fuzzers ${FULL8[@]}
  python pivot_bugs_found.py --results-dir "${RESULTS_DIR}"
}

case "${1:-}" in
  inject)      inject ;;
  verify)      verify ;;
  select)      select_subset ;;
  compile)     compile_phase ;;
  fuzz_core4)  fuzz_core4 ;;
  fuzz_full8)  fuzz_full8 ;;
  aggregate)   aggregate ;;
  all)
    inject
    verify
    select_subset
    compile_phase
    fuzz_core4
    aggregate
    fuzz_full8
    aggregate
    ;;
  *)
    echo "Usage: $0 {inject|verify|select|compile|fuzz_core4|fuzz_full8|aggregate|all}" >&2
    exit 2
    ;;
esac
