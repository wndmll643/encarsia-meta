"""ProcessorFuzz with TTB (Time to Bug) recording.

Subclasses ProcessorfuzzDUT. Records fuzz start timestamp and computes
TTB = mismatch_file_mtime - fuzz_start_time for the first confirmed
detection. Writes "DETECTED: {input} TTB: {seconds}" to check_summary.

Also overrides fuzz() with safe DEVNULL + process-group kill.
"""

import os
import shutil
import signal
import subprocess
import time

import defines
from host import Host
from bug import Bug
from fuzzers.processorfuzz_dut import ProcessorfuzzDUT


class TTBProcessorfuzzDUT(ProcessorfuzzDUT):
    def __init__(self, host: Host, bug: Bug):
        super().__init__(host, bug)
        self.directory = os.path.join(bug.directory, "ttb_processorfuzz")
        os.makedirs(self.directory, exist_ok=True)

    def fuzz(self):
        self.fuzz_log = os.path.join(self.directory, "fuzz.log")
        ts_path = os.path.join(self.directory, "fuzz_start.timestamp")
        if not os.path.exists(self.fuzz_log):
            self.fuzz_start_time = time.time()
            with open(ts_path, 'w') as f:
                f.write(str(self.fuzz_start_time))
            process = subprocess.Popen(
                [
                    "make",
                    f"SIM_BUILD={os.path.relpath(self.build_directory, defines.PROCESSORFUZZ_FUZZER)}",
                    f"VFILE={os.path.relpath(self.dut_path[:-2], defines.PROCESSORFUZZ_VERILOG)}",
                    f"TOPLEVEL={self.host.config.difuzzrtl_toplevel}",
                    f"NUM_ITER=10000000",
                    f"OUT={os.path.relpath(self.out_directory, defines.PROCESSORFUZZ_FUZZER)}",
                    f"ALL_CSR=0",
                    f"FP_CSR=0"
                ],
                cwd=defines.PROCESSORFUZZ_FUZZER,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=self.env,
                preexec_fn=os.setsid
            )
            time.sleep(defines.FUZZING_TIMEOUT)
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait()
            trace_dir = os.path.join(self.out_directory, "trace")
            if os.path.isdir(trace_dir):
                shutil.rmtree(trace_dir)
            open(self.fuzz_log, 'w').close()
        else:
            if os.path.exists(ts_path):
                with open(ts_path, 'r') as f:
                    self.fuzz_start_time = float(f.read().strip())
            else:
                self.fuzz_start_time = None

        return self

    def _compute_ttb(self, mismatch_filename):
        if self.fuzz_start_time is None:
            return None
        mismatch_path = os.path.join(self.out_directory, "mismatch", "sim_input", mismatch_filename)
        if os.path.exists(mismatch_path):
            return os.path.getmtime(mismatch_path) - self.fuzz_start_time
        return None

    def check_mismatch(self):
        mismatch_inputs = os.listdir(os.path.join(self.out_directory, "mismatch", "sim_input"))
        self.check_summary = os.path.join(self.directory, "check_summary.log")

        if not os.path.isdir(os.path.join(self.out_reference_directory, "mismatch", "check")):
            os.makedirs(os.path.join(self.out_reference_directory, "mismatch", "check"))

        if not os.path.isdir(os.path.join(self.out_replay_directory, "mismatch", "check")):
            os.makedirs(os.path.join(self.out_replay_directory, "mismatch", "check"))

        for input in mismatch_inputs:
            # Stage 1: replay on buggy DUT to confirm reproducibility
            log_replay = os.path.join(self.out_replay_directory, "mismatch", "check", input[:-3] + "_replay.log")
            if not os.path.exists(log_replay):
                subprocess.run(
                    [
                        "make",
                        f"SIM_BUILD={os.path.relpath(self.build_directory, defines.PROCESSORFUZZ_FUZZER)}",
                        f"VFILE={os.path.relpath(self.dut_path[:-2], defines.PROCESSORFUZZ_VERILOG)}",
                        f"TOPLEVEL={self.host.config.difuzzrtl_toplevel}",
                        f"NUM_ITER=1",
                        f"OUT={os.path.relpath(self.out_replay_directory, defines.PROCESSORFUZZ_FUZZER)}",
                        f"IN_FILE={os.path.relpath(os.path.join(self.out_directory, 'mismatch', 'sim_input', input), defines.PROCESSORFUZZ_FUZZER)}",
                        f"ALL_CSR=0",
                        f"FP_CSR=0"
                    ],
                    check=True,
                    cwd=defines.PROCESSORFUZZ_FUZZER,
                    stdout=open(log_replay, 'w'),
                    stderr=subprocess.DEVNULL,
                    env=self.env
                )
            with open(log_replay, 'r') as log_file:
                contents = log_file.read()
                if "MISMATCH:" not in contents and "Bug --" not in contents:
                    continue

            # Stage 2: replay on reference
            log = os.path.join(self.out_reference_directory, "mismatch", "check", input[:-3] + ".log")
            if not os.path.exists(log):
                subprocess.run(
                    [
                        "make",
                        f"SIM_BUILD={os.path.relpath(self.build_reference_directory, defines.PROCESSORFUZZ_FUZZER)}",
                        f"VFILE={os.path.relpath(self.reference_dut[:-2], defines.PROCESSORFUZZ_VERILOG)}",
                        f"TOPLEVEL={self.host.config.difuzzrtl_toplevel}",
                        f"NUM_ITER=1",
                        f"OUT={os.path.relpath(self.out_reference_directory, defines.PROCESSORFUZZ_FUZZER)}",
                        f"IN_FILE={os.path.relpath(os.path.join(self.out_directory, 'mismatch', 'sim_input', input), defines.PROCESSORFUZZ_FUZZER)}",
                        f"ALL_CSR=0",
                        f"FP_CSR=0"
                    ],
                    check=True,
                    cwd=defines.PROCESSORFUZZ_FUZZER,
                    stdout=open(log, 'w'),
                    stderr=subprocess.DEVNULL,
                    env=self.env
                )

            with open(log, 'r') as log_file:
                contents = log_file.read()
                if "MISMATCH:" not in contents and "Bug --" not in contents:
                    ttb = self._compute_ttb(input)
                    with open(self.check_summary, 'w') as check_summary_file:
                        if ttb is not None:
                            check_summary_file.write(f"DETECTED: {input} TTB: {ttb:.1f}")
                        else:
                            check_summary_file.write("DETECTED: " + input)
                    return self

        with open(self.check_summary, 'w') as check_summary_file:
            check_summary_file.write("NOT DETECTED")

        return self
