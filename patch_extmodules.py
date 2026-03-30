#!/usr/bin/env python3
"""Add metaAssert/metaReset ports to extmodule declarations in FIRRTL.

hierCoverage_v6a adds these ports to all modules, but can't modify extmodules.
This script patches extmodule declarations to include the expected ports so
firrtl2 type checking passes.

Usage: python3 patch_extmodules.py --input in.fir --output out.fir
"""

import argparse
import re


def patch(text: str) -> str:
    # Match extmodule declarations and add metaAssert/metaReset after existing ports
    # Pattern: find "extmodule <name> :" block, insert ports before defname/parameter lines
    def add_ports(match):
        block = match.group(0)
        lines = block.split('\n')
        result = []
        ports_inserted = False
        for line in lines:
            # Insert before the first defname or parameter line
            if not ports_inserted and re.match(r'\s+defname\s*=', line):
                indent = re.match(r'(\s+)', line).group(1)
                result.append(f"{indent}output metaAssert : UInt<1>")
                result.append(f"{indent}input metaReset : UInt<1>")
                ports_inserted = True
            result.append(line)
        # If no defname found (unlikely), append at end before closing
        if not ports_inserted:
            indent = "    "
            result.insert(-1, f"{indent}output metaAssert : UInt<1>")
            result.insert(-1, f"{indent}input metaReset : UInt<1>")
        return '\n'.join(result)

    # Match extmodule blocks (end at next module/extmodule/circuit or blank line before one)
    patched = re.sub(
        r'(\s+extmodule\s+\S+\s*:.*?)(?=\n\s+(?:ext)?module\s|\n\s+circuit\s|\Z)',
        add_ports,
        text,
        flags=re.DOTALL
    )
    return patched


def main():
    ap = argparse.ArgumentParser(description="Add metaAssert/metaReset to extmodule declarations.")
    ap.add_argument("--input", required=True, help="Input FIRRTL file")
    ap.add_argument("--output", required=True, help="Output FIRRTL file")
    args = ap.parse_args()

    with open(args.input, 'r') as f:
        text = f.read()

    patched = patch(text)

    with open(args.output, 'w') as f:
        f.write(patched)


if __name__ == "__main__":
    main()
