#!/usr/bin/env python3
"""Strip a named module from Verilog, keeping everything else as receptor."""

import re
import sys

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <verilog_file> <module_name>", file=sys.stderr)
    sys.exit(1)

verilog = open(sys.argv[1]).read()
module_name = sys.argv[2]
result = re.sub(
    r'\bmodule\s+' + module_name + r'\b.*?\bendmodule\b',
    "",
    verilog,
    flags=re.MULTILINE | re.DOTALL
)
print(result)
