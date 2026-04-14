"""Cascade with false-positive filtering.

Subclasses CascadeDUT and adds reference design compilation + re-run.
After cascade detects a bug ("Failed" in fuzz.log), the same fuzzer is
re-run on the unfaulted reference design. If the reference also fails,
it's a false positive (the failure is not caused by the injected fault).

This puts Cascade on equal footing with DifuzzRTL/ProcessorFuzz/HierFuzz,
which all filter false positives via reference replay.
"""

import os
import shutil
import signal
import subprocess
import time

import defines
from host import Host
from bug import Bug
from fuzzers.cascade_dut import CascadeDUT


class FilteredCascadeDUT(CascadeDUT):
    def __init__(self, host: Host, bug: Bug):
        super().__init__(host, bug)
        self.directory = os.path.join(bug.directory, "filtered_cascade")
        os.makedirs(self.directory, exist_ok=True)
        self.compile_failed = False

    def compile_dut(self):
        try:
            return super().compile_dut()
        except subprocess.CalledProcessError as e:
            self.compile_failed = True
            print(f"Warning: filtered_cascade compile_dut failed for bug {self.bug.name}: {e}")
            return self

    def fuzz(self):
        if self.compile_failed:
            self.fuzz_log = os.path.join(self.directory, "fuzz.log")
            open(self.fuzz_log, 'w').close()
            self.check_summary = os.path.join(self.directory, "check_summary.log")
            with open(self.check_summary, 'w') as f:
                f.write("NOT DETECTED")
            return self
        result = super().fuzz()
        # CascadeDUT.fuzz() creates check_summary.log prematurely (crash-based
        # detection without reference replay). Delete it so check_mismatch()
        # can create the real one after filtering false positives.
        premature_summary = os.path.join(self.directory, "check_summary.log")
        if os.path.exists(premature_summary):
            os.remove(premature_summary)
        return result

    def create_reference(self):
        if self.compile_failed:
            return self
        self.reference = os.path.join(self.directory, "reference.v")
        if not os.path.exists(self.reference):
            subprocess.run(
                [defines.YOSYS_PATH, '-c', self.host.export_cascade_reference],
                check=True,
                cwd=self.directory,
                stdout=subprocess.DEVNULL
            )

        self.reference_dut = os.path.join(self.directory, "reference_dut.v")
        if not os.path.exists(self.reference_dut):
            with open(self.reference_dut, 'w') as reference_dut_file:
                with open(self.host.cascade_receptor, 'r') as receptor_file:
                    reference_dut_file.write(receptor_file.read())
                with open(self.reference, 'r') as reference_file:
                    reference_dut_file.write(reference_file.read())

        return self

    def compile_reference(self):
        if self.compile_failed:
            return self
        self.reference_verilator_executable = os.path.join(
            self.directory,
            "reference_" + self.host.config.cascade_executable
        )
        if not os.path.exists(self.reference_verilator_executable):
            ref_name = self.name + "_ref"
            try:
                with open(os.path.join(self.host.config.cascade_directory, "run_vanilla_notrace.core"), 'r') as core_source:
                    core = core_source.read()
                    core = core.replace("run_vanilla_notrace", ref_name)
                    core = core.replace("generated/out/vanilla.sv", self.reference_dut)
                    with open(os.path.join(self.host.config.cascade_directory, ref_name + ".core"), 'w') as core_destination:
                        core_destination.write(core)

                if self.host.name == "ibex":
                    subprocess.run(
                        [defines.FUSESOC_PATH, '--cores-root=/encarsia-cellift/external-dependencies/cellift-opentitan', 'run', '--build', ref_name],
                        check=True,
                        cwd=self.host.config.cascade_directory,
                        env=self.env,
                        stdout=open(os.path.join(self.directory, "build_reference.log"), 'w'),
                        stderr=subprocess.DEVNULL,
                    )
                else:
                    subprocess.run(
                        [defines.FUSESOC_PATH, 'run', '--build', ref_name],
                        check=True,
                        cwd=self.host.config.cascade_directory,
                        env=self.env,
                        stdout=open(os.path.join(self.directory, "build_reference.log"), 'w'),
                        stderr=subprocess.DEVNULL,
                    )

                shutil.copy(
                    os.path.join(self.host.config.cascade_directory, "build", ref_name + "_0.1", "default-verilator", self.host.config.cascade_executable),
                    self.reference_verilator_executable
                )
                shutil.rmtree(os.path.join(self.host.config.cascade_directory, "build", ref_name + "_0.1"))
                os.remove(os.path.join(self.host.config.cascade_directory, ref_name + ".core"))
            except subprocess.CalledProcessError as e:
                self.compile_failed = True
                print(f"Warning: filtered_cascade compile_reference failed for bug {self.bug.name}: {e}")
                # Clean up .core file if it was created
                core_path = os.path.join(self.host.config.cascade_directory, ref_name + ".core")
                if os.path.exists(core_path):
                    os.remove(core_path)

        return self

    def check_mismatch(self):
        if self.compile_failed:
            self.check_summary = os.path.join(self.directory, "check_summary.log")
            if not os.path.exists(self.check_summary):
                with open(self.check_summary, 'w') as f:
                    f.write("NOT DETECTED")
            return self
        self.check_summary = os.path.join(self.directory, "check_summary.log")
        if os.path.exists(self.check_summary):
            return self

        # Check if the buggy design failed
        with open(self.fuzz_log, 'r') as f:
            buggy_contents = f.read()
        buggy_failed = "Failed" in buggy_contents or "Starting" not in buggy_contents

        if not buggy_failed:
            with open(self.check_summary, 'w') as f:
                f.write("NOT DETECTED")
            return self

        # Re-run cascade fuzzer on the REFERENCE executable
        ref_fuzz_log = os.path.join(self.directory, "reference_fuzz.log")
        if not os.path.exists(ref_fuzz_log):
            ref_env = self.env.copy()
            ref_env["CASCADE_DATADIR"] = os.path.join(self.directory, "experimental-data-reference")
            with open(ref_fuzz_log, 'w') as log:
                process = subprocess.Popen(
                    ["python", defines.CASCADE_PATH, self.host.name, "1", "0", "1", "0",
                     self.reference_verilator_executable],
                    cwd=self.host.config.cascade_directory,
                    stdout=log,
                    stderr=subprocess.DEVNULL,
                    env=ref_env
                )
                time.sleep(defines.FUZZING_TIMEOUT)
                process.terminate()

        # Compare: if reference also fails → false positive
        with open(ref_fuzz_log, 'r') as f:
            ref_contents = f.read()
        ref_failed = "Failed" in ref_contents or "Starting" not in ref_contents

        if ref_failed:
            with open(self.check_summary, 'w') as f:
                f.write("NOT DETECTED (false positive: reference also failed)")
        else:
            with open(self.check_summary, 'w') as f:
                f.write("DETECTED")

        return self
