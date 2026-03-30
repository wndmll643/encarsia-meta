# Copyright 2024 Matej Bölcskei, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

import os

YOSYS_PATH = "yosys"
SPIKE_DASM_PATH = "spike-dasm"
FUSESOC_PATH = "fusesoc"
DIFUZZRTL_FUZZER = "/encarsia-difuzz-rtl/Fuzzer"
DIFUZZRTL_VERILOG = "/encarsia-difuzz-rtl/Benchmarks/Verilog"
PROCESSORFUZZ_FUZZER = "/encarsia-processorfuzz/Fuzzer"
PROCESSORFUZZ_VERILOG = "/encarsia-processorfuzz/Benchmarks/Verilog"
CASCADE_PATH = "/encarsia-cascade/fuzzer/do_fuzzdesign.py"
PREFILTER_PATH = "/encarsia-cascade/fuzzer/do_testsingle.py"
JASPER = os.path.abspath("cds_jasper")
JASPER_SRCS = os.path.abspath("./jasper")
HIERFUZZ_FUZZER = "/encarsia-hierfuzz/hierfuzz"

HIERCOV_BUILD = "/encarsia-hierfuzz/hiercov_build"
HIERCOV_ROCKET_REF = os.path.join(HIERCOV_BUILD, "rocket_hiercov_v6a.v")
HIERCOV_ROCKET_RECEPTOR = os.path.join(HIERCOV_BUILD, "rocket_hiercov_receptor.v")
HIERCOV_BOOM_REF = os.path.join(HIERCOV_BUILD, "boom_hiercov_v6a.v")
HIERCOV_BOOM_RECEPTOR = os.path.join(HIERCOV_BUILD, "boom_hiercov_receptor.v")

FUZZING_TIMEOUT = 1800