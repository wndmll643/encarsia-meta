# HierFuzz Experiment Variants

All variants share: DifuzzRTL receptor, cocotb testbench, Spike differential testing, `io_hierCovSum` feedback, `metaAssert`/`metaReset` ports.

## Variants

### hierfuzz_v6a (baseline)

- **Coverage pass**: `hierfuzz_instrument_v6a`
- **Register selection**: Control FFs (backward trace from mux selects), fixed 6-bit hash
- **Input hash**: Data input ports (non-control)
- **Mutator**: DifuzzRTL `rvMutator`, uniform corpus selection
- **Timeout**: 1800s
- **File**: `fuzzers/hierfuzz_v6a_dut.py`

### hierfuzz_v6b

- **Coverage pass**: `hierfuzz_instrument_v6b`
- **Register selection**: Same as v6a
- **Input hash**: Control input ports (mux-feeding) instead of data ports
- **Mutator**: DifuzzRTL `rvMutator`, uniform corpus selection
- **Timeout**: 1800s
- **File**: `fuzzers/hierfuzz_v6b_dut.py`
- **Research question**: Does hashing control inputs instead of data inputs improve coverage quality?

### no_cov_hierfuzz

- **Coverage pass**: `hierfuzz_instrument_v6a` (ports present for receptor compatibility)
- **Register selection**: Same as v6a (unused)
- **Input hash**: Same as v6a (unused)
- **Mutator**: DifuzzRTL `rvMutator`, `NO_GUIDE=1` (always generates fresh, never mutates corpus)
- **Timeout**: 1800s
- **File**: `fuzzers/no_cov_hierfuzz_dut.py`
- **Research question**: Is coverage guidance helping at all? (random baseline)

### hierfuzz_v7

- **Coverage pass**: `hierfuzz_instrument_v7`
- **Register selection**: Control FFs with dynamic hash sizing (log2-based, clamped [4,12]), raised maxRegBits (256 vs 64), extmodule proxy coverage via input ports
- **Input hash**: Data input ports, maxInputHashSize raised to 10
- **Mutator**: DifuzzRTL `rvMutator`, uniform corpus selection
- **Timeout**: 1800s
- **File**: `fuzzers/hierfuzz_v7_dut.py`
- **Research question**: Does dynamic hash sizing + extmodule proxy + raised caps improve over fixed v6a parameters?

### hierfuzz_v6a_pfuzz

- **Coverage pass**: `hierfuzz_instrument_v6a` (same instrumentation as v6a)
- **Register selection**: Same as v6a
- **Input hash**: Same as v6a
- **Mutator**: ProcessorFuzz mutator (different instruction generation and mutation strategy)
- **Timeout**: 1800s
- **File**: `fuzzers/hierfuzz_v6a_pfuzz_dut.py`
- **Fuzzer binary**: Runs under `/encarsia-processorfuzz/Fuzzer` instead of `/encarsia-hierfuzz/hierfuzz`
- **Research question**: Same coverage, but does ProcessorFuzz's smarter mutation strategy find more bugs?

### hierfuzz_v6a_covwt

- **Coverage pass**: `hierfuzz_instrument_v6a` (same instrumentation as v6a)
- **Register selection**: Same as v6a
- **Input hash**: Same as v6a
- **Mutator**: DifuzzRTL `rvMutator` with `COV_WEIGHTED=1` — corpus selection weighted by `cov_delta` (coverage points discovered by each seed) via `random.choices(weights=...)`
- **Timeout**: 1800s
- **File**: `fuzzers/hierfuzz_v6a_covwt_dut.py`
- **Research question**: Does preferring high-coverage seeds in mutation improve bug finding?

### hierfuzz_v6a_long

- **Coverage pass**: `hierfuzz_instrument_v6a` (same instrumentation as v6a)
- **Register selection**: Same as v6a
- **Input hash**: Same as v6a
- **Mutator**: DifuzzRTL `rvMutator`, uniform corpus selection
- **Timeout**: 3600s (2x default)
- **File**: `fuzzers/hierfuzz_v6a_long_dut.py`
- **Research question**: Does 2x more time help, or are there diminishing returns?

## Experimental Design

`hierfuzz_v6a` is the control. Each variant changes exactly one axis:

| Axis | Variant | Change from v6a |
|------|---------|-----------------|
| Input hash source | `hierfuzz_v6b` | Control ports instead of data ports |
| Coverage guidance | `no_cov_hierfuzz` | Disabled (random baseline) |
| Hash parameters | `hierfuzz_v7` | Dynamic sizing, extmod proxy, raised caps |
| Mutation strategy | `hierfuzz_v6a_pfuzz` | ProcessorFuzz mutator |
| Corpus selection | `hierfuzz_v6a_covwt` | Coverage-weighted selection |
| Time budget | `hierfuzz_v6a_long` | 2x timeout (3600s) |

## Comparison Baselines (non-hierfuzz)

| Fuzzer | Coverage | Mutator | Source |
|--------|----------|---------|--------|
| `difuzzrtl` | Register coverage (`difuzzrtl_instrument`) | DifuzzRTL | `/encarsia-difuzz-rtl/Fuzzer` |
| `processorfuzz` | Register coverage (`difuzzrtl_instrument`) | ProcessorFuzz | `/encarsia-processorfuzz/Fuzzer` |
| `no_cov_difuzzrtl` | None (random) | DifuzzRTL | `/encarsia-difuzz-rtl/Fuzzer` |
| `no_cov_processorfuzz` | None (random) | ProcessorFuzz | `/encarsia-processorfuzz/Fuzzer` |

## Running

```bash
# All hierfuzz variants + baselines on curated EnCorpus (30 bugs per host, ~10h)
cd /encarsia-meta
python encarsia.py -d out/EnCorpus -H rocket boom -p 30 \
  -F difuzzrtl processorfuzz \
     hierfuzz_v6a hierfuzz_v6b no_cov_hierfuzz \
     hierfuzz_v6a_long hierfuzz_v6a_pfuzz hierfuzz_v7 hierfuzz_v6a_covwt
```
