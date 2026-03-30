# Encarsia HierFuzz Setup Guide

## Overview

This guide covers how to run HierFuzz with **true hierarchical coverage** (`io_hierCovSum` / `io_hierCovHash`) in Encarsia, replacing the old Yosys `difuzzrtl_instrument` register coverage.

The approach: generate hierCov-instrumented Verilog **locally** via firrtl2, then mount it into the Docker container. Yosys bug injection preserves the hierCov ports through the pipeline.

## Prerequisites

- `encarsia` Docker container image (`ethcomsec/encarsia-artifacts:latest`)
- firrtl2 built locally (`firrtl2/utils/bin/firrtl`)
- Environment set up: `source ./env.sh`

## Step 1: Start the Encarsia container (temporary)

You need the container running briefly to copy out the FIRRTL source files.

```bash
docker run -it --name encarsia ethcomsec/encarsia-artifacts:latest
```

Leave it running (or start it detached with `-d`).

## Step 2: Generate hierCov Verilog locally

```bash
source ./env.sh
bash encarsia-meta/gen_hiercov.sh
```

This script:
1. Copies `.top.fir` files from the Docker container (Rocket + BOOM)
2. Converts FIRRTL 3 syntax to FIRRTL 1.2 (`scripts/firrtl3_to_1.py`)
3. Lowers to Low FIRRTL via firrtl2
4. Applies `hier_cov.hierCoverage_v6a` pass, emitting instrumented Verilog
5. Generates receptor files (hierCov Verilog with host module stripped)

Output goes to `hiercov_build/`:
```
hiercov_build/
  rocket_hiercov_v6a.v          # Rocket with hierCov ports
  rocket_hiercov_receptor.v     # RocketTile wrapper (Rocket stripped)
  boom_hiercov_v6a.v            # BOOM with hierCov ports
  boom_hiercov_receptor.v       # BoomTile wrapper (BoomCore stripped)
```

### Verify the output

```bash
grep -c 'io_hierCovSum' hiercov_build/rocket_hiercov_v6a.v
grep -c 'io_hierCovHash' hiercov_build/rocket_hiercov_v6a.v
```

Both should return non-zero counts.

## Step 3: Stop the temporary container

```bash
docker stop encarsia
docker rm encarsia
```

## Step 4: Restart with mounts

```bash
docker run -it --name encarsia \
  -v $(pwd)/encarsia-meta:/encarsia-meta \
  -v $(pwd)/hierfuzz:/encarsia-hierfuzz/hierfuzz \
  -v $(pwd)/hiercov_build:/encarsia-hierfuzz/hiercov_build \
  ethcomsec/encarsia-artifacts:latest
```

The three mounts:
| Host path | Container path | Purpose |
|-----------|---------------|---------|
| `encarsia-meta/` | `/encarsia-meta` | Encarsia orchestration scripts |
| `hierfuzz/` | `/encarsia-hierfuzz/hierfuzz` | HierFuzz fuzzer code |
| `hiercov_build/` | `/encarsia-hierfuzz/hiercov_build` | Pre-generated hierCov Verilog + receptors |

## Step 5: Run a single-bug test

Inside the container:

```bash
cd /encarsia-meta
python encarsia.py -d out/test -H rocket -p 1 -D 1 -F hierfuzz_v6a
```

## Step 6: Verify hierCov is active

Check that the exported `host.v` contains hierCov ports (not just `io_covSum`):

```bash
grep 'io_hierCovSum' out/test/rocket/driver/1/hierfuzz_v6a/host.v
```

If this returns matches, hierarchical coverage is working.

## Step 7: Run a full coverage comparison

To compare all coverage metrics (matching the EnCorpus benchmark style), run all fuzzers together:

```bash
cd /encarsia-meta
python encarsia.py -d out/EnCorpus -H rocket boom -p 30 -F difuzzrtl processorfuzz hierfuzz_v6a hierfuzz_v6b no_cov_hierfuzz
```

| Flag | Meaning |
|------|---------|
| `-d out/EnCorpus` | Output directory for all results |
| `-H rocket boom` | Run on both Rocket and BOOM host designs |
| `-p 30` | 30 parallel processes |
| `-F ...` | Fuzzers to evaluate (all run on each host) |

Fuzzers in the comparison:
- `difuzzrtl` — register coverage baseline (DifuzzRTL)
- `processorfuzz` — ProcessorFuzz baseline
- `hierfuzz_v6a` — HierFuzz with hierarchical coverage v6a
- `hierfuzz_v6b` — HierFuzz with hierarchical coverage v6b
- `no_cov_hierfuzz` — HierFuzz random baseline (`NO_GUIDE=1`, same harness, no coverage feedback)

For a quick single-host smoke test:

```bash
python encarsia.py -d out/test -H rocket -p 4 -F difuzzrtl hierfuzz_v6a hierfuzz_v6b
```

## Troubleshooting

### firrtl2 fails with SInt type error

If you see a FIRRTL type error about `UIntLiteral` applied to `SInt`, the design has SInt registers. Switch to the `_fix` variant:

Edit `gen_hiercov.sh` and change `-fct hier_cov.hierCoverage_v6a` to `-fct hier_cov.hierCoverage_v4_fix`.

### Yosys can't parse hierCov Verilog

firrtl2 emits Verilog-2001 which Yosys handles. If there are issues, check for unsupported constructs in the firrtl2 output and post-process if needed.

### `io_hierCovSum` not found in dut.v

Verify that:
1. `hiercov_build/rocket_hiercov_v6a.v` exists and contains `io_hierCovSum`
2. The mount is correct: `ls /encarsia-hierfuzz/hiercov_build/` inside Docker
3. `reference.v` was regenerated (delete `out/test/rocket/reference.v` to force rebuild)

### BOOM host module name

BOOM's host module is `BoomCore` (not `Boom`). The receptor strips `BoomCore`, keeping `BoomTile` as the toplevel with hierCov connections.

## File changes reference

| File | Change |
|------|--------|
| `defines.py` | Added `HIERCOV_BUILD`, `HIERCOV_*_REF`, `HIERCOV_*_RECEPTOR` paths |
| `config.py` | Added `hiercov_reference`, `hiercov_receptor` config params (rocket + boom) |
| `host.py` | `create_reference()` splices hierCov Verilog; `create_hierfuzz_receptor()` uses hierCov receptor; added `create_hierfuzz_export_script()` (plain export, no `difuzzrtl_instrument`) |
| `fuzzers/hierfuzz_v6a_dut.py` | Uses `hierfuzz_export_script` + `hierfuzz_reference_export` instead of `instrument_script` + `export_difuzzrtl_reference` |
| `fuzzers/hierfuzz_v6b_dut.py` | Same changes as v6a |
| `fuzzers/no_cov_hierfuzz_dut.py` | Same export changes (still passes `NO_GUIDE=1`) |
| `gen_receptor.py` | New: strips a module from Verilog to create receptor |
| `gen_hiercov.sh` | New: one-time local generation of hierCov artifacts |
