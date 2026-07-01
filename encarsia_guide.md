# Encarsia HierFuzz Setup Guide

## Overview

This guide covers how to run **HierFuzz** (with hierarchical coverage) in Encarsia, replacing the original DifuzzRTL register-coverage flow.

The key idea: HierFuzz instrumentation is added to each per-bug RTLIL by an **encarsia-yosys plugin pass** (`hierfuzz_instrument_data_bucket`, `_ctrl_bucket`, `_ctrl_fold`, or a tree variant), then the instrumented host module is concatenated with a DifuzzRTL benchmark wrapper (with the original host module stripped out) to form `dut.v`. The cocotb harness in `hierfuzz/` reads `io_hierCovSum` for normal variants and `io_hierCovSumTotal` for tree-sum variants.

There is **no firrtl2 pre-generation step**. Everything happens at the Yosys/RTLIL level inside the Encarsia container.

## Prerequisites

- `encarsia` Docker container image (`ethcomsec/encarsia-artifacts:latest`)
- The encarsia-yosys plugin built into the image (already shipped — exposes active passes such as `hierfuzz_instrument_data_bucket`, `_ctrl_bucket`, `_ctrl_fold`, `_data_bucket_tree`, and `_ctrl_bucket_tree`, plus legacy pass names for reproduction)
- The `encarsia-meta/`, `hierfuzz/`, and `hierfuzz/infos/` directories from this repo (mounted into the container)

## Step 1: Start the Encarsia container with mounts

```bash
docker run -it --name encarsia \
  -v $(pwd)/encarsia-meta:/encarsia-meta \
  -v $(pwd)/hierfuzz:/encarsia-hierfuzz/hierfuzz \
  ethcomsec/encarsia-artifacts:latest
```

| Host path | Container path | Purpose |
|-----------|----------------|---------|
| `encarsia-meta/` | `/encarsia-meta` | Encarsia orchestration scripts (this directory) |
| `hierfuzz/` | `/encarsia-hierfuzz/hierfuzz` | HierFuzz cocotb harness + Makefile |

If you want to run experiments without an interactive shell:

```bash
docker run -d --name encarsia \
  -v $(pwd)/encarsia-meta:/encarsia-meta \
  -v $(pwd)/hierfuzz:/encarsia-hierfuzz/hierfuzz \
  ethcomsec/encarsia-artifacts:latest \
  sleep infinity
docker exec -it encarsia bash
```

## Step 2: Run a single-bug smoke test (inside the container)

```bash
cd /encarsia-meta
python encarsia.py -d out/test -H rocket -p 1 -D 1 -F hierfuzz_ctrl_fold
```

| Flag | Meaning |
|------|---------|
| `-d out/test` | Output directory for results |
| `-H rocket` | Host design (rocket / boom / cva6 / ibex — HierFuzz only supports rocket and boom) |
| `-p 1` | One process |
| `-D 1` | One driver bug |
| `-F hierfuzz_ctrl_fold` | Fuzzer to evaluate |

Verify the per-bug `host.v` got hierCov ports added:

```bash
grep -c io_hierCovSum  out/test/rocket/driver/1/hierfuzz_ctrl_fold/host.v
grep -c io_hierCovHash out/test/rocket/driver/1/hierfuzz_ctrl_fold/host.v
```

Both should return non-zero counts.

## Step 3: Run a full coverage comparison

To compare the current best HierFuzz variants against the DifuzzRTL / ProcessorFuzz baselines (matches the EnCorpus benchmark style):

```bash
cd /encarsia-meta
python encarsia.py \
  -d out/EnCorpus \
  -H rocket boom \
  -p 30 \
  -F difuzzrtl processorfuzz hierfuzz_data_bucket hierfuzz_ctrl_bucket hierfuzz_ctrl_fold no_cov_hierfuzz
```

Available HierFuzz fuzzers (current best variants in **bold**):

- **`hierfuzz_data_bucket`** — data-input hash + ctrl-reg core hash (was v6a)
- **`hierfuzz_ctrl_bucket`** — ctrl-input hash + ctrl-reg core hash (was v6b)
- **`hierfuzz_ctrl_fold`** — direct-or-fold hash, recommended default (was v9a)
- **`hierfuzz_data_bucket_tree`** / **`hierfuzz_ctrl_bucket_tree`** — tree-sum variants that expose `io_hierCovSumTotal`
- `hierfuzz_v7`, `hierfuzz_v6a_long`, `hierfuzz_v6a_pfuzz`, `hierfuzz_v6a_covwt` — experimental, currently being evaluated
- `no_cov_hierfuzz` — random baseline (`NO_GUIDE=1`, same harness, no coverage feedback)

For a quick subset:

```bash
python encarsia.py -d out/test -H rocket -p 4 -F difuzzrtl hierfuzz_data_bucket hierfuzz_ctrl_fold
```

## How it actually works

For each bug, Encarsia produces `host.rtlil` (the buggy host module) and `reference.rtlil` (the bug-free reference) in the per-bug directory. Then for each HierFuzz variant the orchestration in `host.py` generates a Yosys TCL export script:

```tcl
yosys "read_rtlil ../host.rtlil"
yosys "hierfuzz_instrument_ctrl_fold"
yosys "write_verilog host.v"
```

Running it produces a `host.v` with `io_hierCovSum`, `io_hierCovHash`, `metaAssert`, `metaReset` ports added to every module.

`fuzzers/hierfuzz_ctrl_fold_dut.py` then:

1. Runs the Yosys export to get `host.v`
2. Builds `dut.v` by concatenating the **DifuzzRTL benchmark wrapper** (`/encarsia-difuzz-rtl/Benchmarks/Verilog/RocketTile_encarsia.v` or `SmallBoomTile_encarsia.v`) — with the original host module regex-stripped — and the freshly instrumented `host.v`
3. Drives `make -C /encarsia-hierfuzz/hierfuzz sim MODULE=hierfuzz_entry VERILOG_SOURCES=dut.v ...`
4. Repeats for `reference.v` to build `reference_dut.v` and re-runs every mismatch input from the buggy run against the reference, flagging real bug detections

The receptor (DifuzzRTL benchmark wrapper) is variant-independent — only the host module's coverage instrumentation differs across variants.

## Troubleshooting

### `io_hierCovSum` not found in `host.v`

The Yosys export step failed silently, or you ran an older variant whose pass name doesn't exist in your encarsia-yosys build. Check:

1. The pass exists: `yosys -h hierfuzz_instrument_ctrl_fold` inside the container should print help
2. The TCL script exists: `cat encarsia-meta/.../hierfuzz_ctrl_fold_export.tcl`
3. Force regen: `rm out/<run>/<host>/driver/<N>/hierfuzz_ctrl_fold/{host.v,dut.v}` and re-run

### `Warning: skipping hierfuzz_ctrl_fold for bug ...`

The wrapper sets `compile_failed = True` whenever the bug-injected `host.rtlil` is missing for a particular bug — Encarsia's bug-injection sometimes fails for individual bugs. Check `out/<run>/<host>/<driver|multiplexer>/<N>/host.rtlil`.

### BOOM host module name is `BoomCore`, not `Boom`

`config.boom_config.host_module = "BoomCore"`. The receptor regex strips `BoomCore` (not `Boom`) when building `hierfuzz_receptor.v`. If you add a new BOOM-based config, make sure `host_module` matches the actual top module emitted by Chipyard.

### Stale `host.v` / `dut.v` after changing the instrumentation pass

The wrappers use `if not os.path.exists(...)` guards to avoid redundant Yosys runs. After editing `host.py`'s TCL generators or adding a new variant, delete the per-bug intermediates:

```bash
find out -name 'host.v'        -path '*/hierfuzz_ctrl_fold/*' -delete
find out -name 'dut.v'         -path '*/hierfuzz_ctrl_fold/*' -delete
find out -name 'reference.v'   -path '*/hierfuzz_ctrl_fold/*' -delete
find out -name 'reference_dut.v' -path '*/hierfuzz_ctrl_fold/*' -delete
```

### Adding a new variant

1. Confirm the Yosys pass is registered in `encarsia-yosys/passes/hierfuzz/instrument_hierfuzz.cc`.
2. In `host.py`'s `create_hierfuzz_export_script()`, add a new `("variant_name", "hierfuzz_instrument_variant_name")` entry to `active_variants`.
3. Copy the closest active wrapper, for example `fuzzers/hierfuzz_ctrl_fold_dut.py`, to `fuzzers/hierfuzz_variant_name_dut.py` and update the directory name, class name, and `host.hierfuzz_<variant_name>_*` attributes.
4. In `encarsia.py`, add the import and a new `elif fuzzer == "hierfuzz_variant_name":` branch following the matching active variant pattern.

## File reference

| File | Role |
|------|------|
| `defines.py` | Constants: `YOSYS_PATH`, `HIERFUZZ_FUZZER`, etc. |
| `config.py` | `EncarsiaConfig` per host (rocket / boom / cva6 / ibex), incl. `host_module` and `hierfuzz_receptor_sources` |
| `host.py` | Generates per-bug Yosys TCL scripts (`create_hierfuzz_export_script`) and the receptor (`create_hierfuzz_receptor`) |
| `fuzzers/hierfuzz_data_bucket_dut.py`, `_ctrl_bucket_dut.py`, `_ctrl_fold_dut.py`, ... | Per-variant wrapper: runs Yosys export → concatenates with receptor → drives `make -C hierfuzz sim` |
| `encarsia.py` | CLI dispatch: maps `-F` arguments to wrapper classes |
