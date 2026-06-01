# Phase B — ProcessorFuzz re-gated on hierarchical coverage

## What's in this directory

| File | Container install path | Purpose |
|---|---|---|
| `Fuzzer_hcov.py` | `/encarsia-processorfuzz/Fuzzer/Fuzzer_hcov.py` | Forked Run() coroutine. Gates `mutator.add_corpus()` on `coverage > last_coverage` instead of `trns > 0`. Drops the `if trns==0: continue` early-skip. |
| `ProcessorFuzz_hcov.py` | `/encarsia-processorfuzz/Fuzzer/ProcessorFuzz_hcov.py` | Cocotb entry point. Identical to `ProcessorFuzz.py` except imports `Run` from `Fuzzer_hcov` instead of `Fuzzer`. Selected via `MODULE=ProcessorFuzz_hcov` in DUT classes. |
| `processorfuzz_RTLSim_host_hcov_patch.py` | (run during image build, not installed) | Idempotently patches `/encarsia-processorfuzz/Fuzzer/RTLSim/host.py:get_covsum()` so that when `HIERCOV_GATE=1` is set, it reads `io_hierCovSum` (or `io_hierCovSumTotal` if `HIER_COV_TOTAL=1`) instead of `io_covSum`. Without the env flag the behavior is unchanged. |
| `fuzzers/hierfuzz_data_bucket_pfuzz_hcov_dut.py` | `/encarsia-meta/fuzzers/` | DUT class: v6a-style instrumentation + pfuzz mutator + hierCov gate |
| `fuzzers/hierfuzz_ctrl_bucket_tree_pfuzz_hcov_dut.py` | `/encarsia-meta/fuzzers/` | v11b-style + pfuzz + hierCov gate (reads `io_hierCovSumTotal`) |
| `fuzzers/hierfuzz_data_bucket_tree_pfuzz_hcov_dut.py` | `/encarsia-meta/fuzzers/` | v11c-style + pfuzz + hierCov gate (reads `io_hierCovSumTotal`) |

`multi_run_ttb.py` and `encarsia.py` are already updated to import and
dispatch the 3 new variants.

## Building the new image

The existing `encarsia_hierfuzz:v2` image (used by `encarsia_exp5`) has:
- Old Yosys binary with `hierfuzz_instrument_v6a/v6b/v9a/v11b` etc.
- Unpatched `Fuzzer.py` / `RTLSim/host.py`

For the new variants to actually run, the image needs to be rebuilt with:
1. Yosys recompiled against `encarsia-yosys` HEAD (now has the renamed
   passes `hierfuzz_instrument_data_bucket / ctrl_bucket / ctrl_fold /
   ctrl_bucket_tree / data_bucket_tree`).
2. `Fuzzer_hcov.py` and `ProcessorFuzz_hcov.py` dropped into
   `/encarsia-processorfuzz/Fuzzer/`.
3. `processorfuzz_RTLSim_host_hcov_patch.py` executed against
   `/encarsia-processorfuzz/Fuzzer/RTLSim/host.py`.
4. The renamed DUT classes + new hcov DUT classes dropped into
   `/encarsia-meta/fuzzers/`.
5. Updated `multi_run_ttb.py`, `encarsia.py`, `host.py` placed in
   `/encarsia-meta/`.

Reuse the existing `encarsia_hierfuzz` Dockerfile structure. Suggested
tag: `encarsia_hierfuzz:v3`. The user typically runs the production
sweep on the target device per the saved memory rule
`feedback_separate_target_device`.

## Smoke test (after image build)

Run a 5-iteration smoke on 3 easy rocket-driver bugs across all 3 new
hcov-gated variants:

```bash
docker run --rm encarsia_hierfuzz:v3 python /encarsia-meta/multi_run_ttb.py \
    -d /encarsia-meta/out/EnCorpus -H rocket -p 3 -N 5 --early-stop 5 \
    --results-dir out/ttb_results_hcov_smoke \
    -D 144 293 347 \
    --fuzzers hierfuzz_data_bucket_pfuzz_hcov \
              hierfuzz_ctrl_bucket_tree_pfuzz_hcov \
              hierfuzz_data_bucket_tree_pfuzz_hcov
```

Verify in each variant's fuzz log:
- `Iteration: N, ..., Coverage: M, Transitions: K` — `Coverage` increases
  monotonically (proves the new gate reads a real hierCov value).
- `run_*.json` shows `DETECTED` with reasonable TTB on the easy bugs.

## Production run (after smoke validation)

On the **target device** at N=100 per pair, all 3 new variants on the
60-bug suite. Reuse existing exp5 baselines (renamed) for comparison.

Compute estimate: ~36–50 hours wall-clock at `-p 15`.

## Verification of the thesis

After the run completes, regenerate the 4-tables report including the
3 new hybrids. Add Table 5 entries comparing:

- `data_bucket_pfuzz_hcov` vs plain `ttb_processorfuzz` — does hcov-gate
  improve over Spike-CSR-gate?
- `data_bucket_pfuzz_hcov` vs `data_bucket_pfuzz` (dead-coverage baseline)
  — does the gate change matter, holding instrumentation constant?
- `ctrl_bucket_tree_pfuzz_hcov` vs `data_bucket_pfuzz_hcov` — does
  tree-sum (lossless) help vs bucketed (lossy)?
- `data_bucket_tree_pfuzz_hcov` vs `ctrl_bucket_tree_pfuzz_hcov` — does
  data-input sensitivity help, holding aggregation constant?

Success criteria from the original plan:
- ≥1 of the new variants beats plain pfuzz on geomean TTB across the
  28 common bugs (weakest acceptable form of the thesis).
- All 3 differ measurably from their dead-coverage `_pfuzz` predecessors.
