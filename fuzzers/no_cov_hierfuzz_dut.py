import os
import subprocess
import random
import string
import time

import defines
from host import Host
from bug import Bug


class NoCovHierFuzzDUT():
    def __init__(self, host: Host, bug: Bug):
        self.directory = os.path.join(bug.directory, "no_cov_hierfuzz")
        os.makedirs(self.directory, exist_ok=True)
        self.host = host
        self.bug = bug
        self.name = self.bug.name + (''.join(random.choices(string.ascii_letters + string.digits, k=16)))
        self.env = os.environ.copy()
        self.env["SPIKE"] = "/encarsia-difuzz-rtl/Fuzzer/ISASim/riscv-isa-sim/build/spike"
        self.env["PYTHONPATH"] = (
            f"{defines.HIERFUZZ_FUZZER}"
            f":{defines.HIERFUZZ_FUZZER}/.."
            f":/encarsia-difuzz-rtl/Fuzzer/src"
            f":/encarsia-difuzz-rtl/Fuzzer/RTLSim/src"
        )
        self.env["COCOTB_RESULTS_FILE"] = os.path.join(defines.HIERFUZZ_FUZZER, "cocotb_results", self.name)
        self.compile_failed = False

    def create_dut(self):
        host_rtlil = os.path.join(self.bug.directory, "host.rtlil")
        if not os.path.exists(host_rtlil):
            self.compile_failed = True
            print(f"Warning: skipping no_cov_hierfuzz for bug {self.bug.name} (no host.rtlil)")
            return self

        self.module = os.path.join(self.directory, "host.v")
        if not os.path.exists(self.module):
            subprocess.run(
                [defines.YOSYS_PATH, '-c', self.host.hierfuzz_nocov_export_script],
                check=True,
                cwd=self.directory,
                stdout=subprocess.DEVNULL
            )

        self.dut_path = os.path.join(self.directory, "dut.v")
        if not os.path.exists(self.dut_path):
            with open(self.dut_path, 'w') as dut_file:
                with open(self.host.hierfuzz_nocov_receptor, 'r') as receptor_file:
                    dut_file.write(receptor_file.read())
                with open(self.module, 'r') as module_file:
                    dut_file.write(module_file.read())

        return self

    def create_reference(self):
        if self.compile_failed:
            return self
        self.reference = os.path.join(self.directory, "reference.v")
        if not os.path.exists(self.reference):
            subprocess.run(
                [defines.YOSYS_PATH, '-c', self.host.hierfuzz_nocov_ref_export],
                check=True,
                cwd=self.directory,
                stdout=subprocess.DEVNULL
            )

        self.reference_dut = os.path.join(self.directory, "reference_dut.v")
        if not os.path.exists(self.reference_dut):
            with open(self.reference_dut, 'w') as reference_dut_file:
                with open(self.host.hierfuzz_nocov_receptor, 'r') as receptor_file:
                    reference_dut_file.write(receptor_file.read())
                with open(self.reference, 'r') as reference_file:
                    reference_dut_file.write(reference_file.read())

        return self

    def compile_dut(self):
        if self.compile_failed:
            return self
        self.build_directory = os.path.join(self.directory, "build")
        self.out_directory = os.path.join(self.directory, "out")

        if not os.path.exists(self.out_directory):
            compile_log = os.path.join(self.directory, "compile_error.log")
            with open(compile_log, 'w') as log_file:
                subprocess.run(
                    [
                        "make",
                        "MODULE=hierfuzz_entry",
                        f"SIM_BUILD={os.path.relpath(self.build_directory, defines.HIERFUZZ_FUZZER)}",
                        f"VERILOG_SOURCES={self.dut_path}",
                        f"VERILOG_FILE={self.dut_path}",
                        f"TOPLEVEL={self.host.config.difuzzrtl_toplevel}",
                        f"NUM_ITER=1",
                        f"OUT={os.path.relpath(self.out_directory, defines.HIERFUZZ_FUZZER)}",
                        f"NO_GUIDE=1"
                    ],
                    check=True,
                    cwd=defines.HIERFUZZ_FUZZER,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    env=self.env
                )

        return self

    def fuzz(self):
        if self.compile_failed:
            return self
        self.fuzz_log = os.path.join(self.directory, "fuzz.log")
        if not os.path.exists(self.fuzz_log):
            with open(self.fuzz_log, 'w') as fuzz_log:
                process = subprocess.Popen(
                    [
                        "make",
                        "MODULE=hierfuzz_entry",
                        f"SIM_BUILD={os.path.relpath(self.build_directory, defines.HIERFUZZ_FUZZER)}",
                        f"VERILOG_SOURCES={self.dut_path}",
                        f"VERILOG_FILE={self.dut_path}",
                        f"TOPLEVEL={self.host.config.difuzzrtl_toplevel}",
                        f"NUM_ITER=10000000",
                        f"RECORD=1",
                        f"OUT={os.path.relpath(self.out_directory, defines.HIERFUZZ_FUZZER)}",
                        f"NO_GUIDE=1"
                    ],
                    cwd=defines.HIERFUZZ_FUZZER,
                    stdout=fuzz_log,
                    stderr=subprocess.DEVNULL,
                    env=self.env
                )
                time.sleep(defines.FUZZING_TIMEOUT)
                process.terminate()

        return self

    def compile_reference(self):
        if self.compile_failed:
            return self
        self.build_reference_directory = os.path.join(self.directory, "build_reference")
        self.out_reference_directory = os.path.join(self.directory, "out_reference")

        if not os.path.exists(self.out_reference_directory):
            subprocess.run(
                [
                    "make",
                    "MODULE=hierfuzz_entry",
                    f"SIM_BUILD={os.path.relpath(self.build_reference_directory, defines.HIERFUZZ_FUZZER)}",
                    f"VERILOG_SOURCES={self.reference_dut}",
                    f"VERILOG_FILE={self.reference_dut}",
                    f"TOPLEVEL={self.host.config.difuzzrtl_toplevel}",
                    f"NUM_ITER=1",
                    f"OUT={os.path.relpath(self.out_reference_directory, defines.HIERFUZZ_FUZZER)}",
                    f"NO_GUIDE=1"
                ],
                check=True,
                cwd=defines.HIERFUZZ_FUZZER,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=self.env
            )

        return self

    def check_mismatch(self):
        if self.compile_failed:
            self.check_summary = os.path.join(self.directory, "check_summary.log")
            with open(self.check_summary, 'w') as check_summary_file:
                check_summary_file.write("NOT DETECTED")
            return self
        mismatch_inputs = os.listdir(os.path.join(self.out_directory, "mismatch", "sim_input"))
        self.check_summary = os.path.join(self.directory, "check_summary.log")

        if not os.path.isdir(os.path.join(self.out_reference_directory, "mismatch", "check")):
            os.makedirs(os.path.join(self.out_reference_directory, "mismatch", "check"))

        for input in mismatch_inputs:
            log = os.path.join(self.out_reference_directory, "mismatch", "check", input[:-3] + ".log")
            if not os.path.exists(log):
                subprocess.run(
                    [
                        "make",
                        "MODULE=hierfuzz_entry",
                        f"SIM_BUILD={os.path.relpath(self.build_reference_directory, defines.HIERFUZZ_FUZZER)}",
                        f"VERILOG_SOURCES={self.reference_dut}",
                        f"VERILOG_FILE={self.reference_dut}",
                        f"TOPLEVEL={self.host.config.difuzzrtl_toplevel}",
                        f"NUM_ITER=1",
                        f"OUT={os.path.relpath(self.out_reference_directory, defines.HIERFUZZ_FUZZER)}",
                        f"IN_FILE={os.path.relpath(os.path.join(self.out_directory, 'mismatch', 'sim_input', input), defines.HIERFUZZ_FUZZER)}",
                        f"NO_GUIDE=1"
                    ],
                    check=True,
                    cwd=defines.HIERFUZZ_FUZZER,
                    stdout=open(log, 'w'),
                    stderr=subprocess.DEVNULL,
                    env=self.env
                )

            with open(log, 'r') as log_file:
                if "Bug --" not in log_file.read():
                    with open(self.check_summary, 'w') as check_summary_file:
                        check_summary_file.write("DETECTED: " + input)
                    return self

        with open(self.check_summary, 'w') as check_summary_file:
            check_summary_file.write("NOT DETECTED")

        return self
