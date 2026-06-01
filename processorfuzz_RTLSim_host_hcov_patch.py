#!/usr/bin/env python3
"""Idempotent in-place patch for /encarsia-processorfuzz/Fuzzer/RTLSim/host.py.

Replaces the body of `rvRTLhost.get_covsum()` with an env-flag-driven version
so the ProcessorFuzz cocotb harness can read hierarchical-coverage signals
(`io_hierCovSum` or `io_hierCovSumTotal`) for the new hcov-gated DUT
variants without breaking existing pfuzz/v6a_pfuzz/v9a_pfuzz behavior.

Behavior matrix:
  HIERCOV_GATE=1, HIER_COV_TOTAL=1   -> read io_hierCovSumTotal
  HIERCOV_GATE=1, HIER_COV_TOTAL unset -> read io_hierCovSum
  HIERCOV_GATE unset                  -> read io_covSum (upstream behavior)

The patched method:

    def get_covsum(self):
        import os
        if os.environ.get("HIERCOV_GATE") == "1":
            if os.environ.get("HIER_COV_TOTAL") == "1" and hasattr(self.dut, "io_hierCovSumTotal"):
                sig = self.dut.io_hierCovSumTotal
            elif hasattr(self.dut, "io_hierCovSum"):
                sig = self.dut.io_hierCovSum
            else:
                sig = self.dut.io_covSum
        else:
            sig = self.dut.io_covSum
        cov_mask = (1 << len(sig)) - 1
        return sig.value & cov_mask

Usage (run inside the encarsia container, e.g. during image build):

    python3 /encarsia-meta/processorfuzz_RTLSim_host_hcov_patch.py

The patch is idempotent — re-running it is safe and prints a no-op message
if the file is already patched.
"""

import os
import re
import sys

TARGET = "/encarsia-processorfuzz/Fuzzer/RTLSim/host.py"

MARKER = "# === hierCov-gate patch ==="

PATCHED_GET_COVSUM = """\
    def get_covsum(self):
        # === hierCov-gate patch ===
        # Env-flag-driven so the cocotb host can read hierarchical-coverage
        # signals for the new hcov-gated DUT variants without changing
        # behavior for existing pfuzz/v6a_pfuzz/v9a_pfuzz variants.
        import os
        if os.environ.get("HIERCOV_GATE") == "1":
            if os.environ.get("HIER_COV_TOTAL") == "1" and hasattr(self.dut, "io_hierCovSumTotal"):
                sig = self.dut.io_hierCovSumTotal
            elif hasattr(self.dut, "io_hierCovSum"):
                sig = self.dut.io_hierCovSum
            else:
                sig = self.dut.io_covSum
        else:
            sig = self.dut.io_covSum
        cov_mask = (1 << len(sig)) - 1
        return sig.value & cov_mask
"""

ORIGINAL_GET_COVSUM_RE = re.compile(
    r"    def get_covsum\(self\):\n"
    r"        cov_mask = \(1 << len\(self\.dut\.io_covSum\)\) - 1\n"
    r"        return self\.dut\.io_covSum\.value & cov_mask\n"
)


def main():
    if not os.path.exists(TARGET):
        print(f"ERROR: target file not found: {TARGET}", file=sys.stderr)
        sys.exit(1)

    with open(TARGET, "r") as f:
        body = f.read()

    if MARKER in body:
        print(f"already patched: {TARGET}")
        return

    new_body, n = ORIGINAL_GET_COVSUM_RE.subn(PATCHED_GET_COVSUM, body, count=1)
    if n != 1:
        print(
            "ERROR: could not locate the original get_covsum() body to patch. "
            "Has the upstream file changed?",
            file=sys.stderr,
        )
        sys.exit(2)

    backup = TARGET + ".prepatch"
    if not os.path.exists(backup):
        with open(backup, "w") as f:
            f.write(body)

    with open(TARGET, "w") as f:
        f.write(new_body)
    print(f"patched: {TARGET} (backup at {backup})")


if __name__ == "__main__":
    main()
