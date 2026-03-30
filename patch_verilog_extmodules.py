#!/usr/bin/env python3
"""Add metaReset (input) and metaAssert (output) ports to Verilog modules.

hierCov adds these ports to all FIRRTL modules. Extmodule Verilog implementations
(plusarg_reader, SRAMs, ClockDividerN, etc.) need them too so Verilator doesn't
error on missing port connections.

Reads Verilog from a file, patches every module that lacks metaReset, prints to stdout.

Usage: python3 patch_verilog_extmodules.py <verilog_file>
"""

import re
import sys


def patch(verilog: str) -> str:
    def patch_module(match):
        full = match.group(0)
        # Skip modules that already have metaReset (from hierCov)
        if 'metaReset' in full:
            return full
        # Find the closing paren of the port list
        paren_match = re.search(r'\)\s*;', full)
        if not paren_match:
            return full
        insert_pos = paren_match.start()
        patched = (
            full[:insert_pos] +
            ',\n  input metaReset,\n  output metaAssert' +
            full[insert_pos:]
        )
        # Add assign metaAssert = 0 after the port list semicolon
        semi_match = re.search(r'\)\s*;', patched)
        if semi_match:
            after_semi = semi_match.end()
            patched = (
                patched[:after_semi] +
                "\n  assign metaAssert = 1'b0;" +
                patched[after_semi:]
            )
        return patched

    return re.sub(
        r'\bmodule\s+\w+\b.*?\bendmodule\b',
        patch_module,
        verilog,
        flags=re.MULTILINE | re.DOTALL
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <verilog_file>", file=sys.stderr)
        sys.exit(1)
    verilog = open(sys.argv[1]).read()
    print(patch(verilog))
