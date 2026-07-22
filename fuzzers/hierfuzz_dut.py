"""HierFuzz — our full stack (genv2 generator/mutator + module-aware hier_cov).

This is the single "hierfuzz" arm added to the BASELINE Encarsia lineup for the
bug-capture experiment (single run/bug, # bugs, not TTB).

Coverage instrumentation is the module-aware hier_cov Yosys pass, applied to the
HIERARCHICAL RTLIL (`host_hier.rtlil`, produced pre-flatten by the patched
`host.py` — a flat design would collapse the per-module tree).

Phase 1 (this file): guidance via the module-aware scalar tree-sum
`io_hierCovSumTotal` (`HIER_COV_TOTAL=1`) using the `data_bucket_tree`
instrumentation. genv2 runs its data-sensitive generation/mutation; module-aware
steering (covsteer) is inactive without the per-instance signal.
Phase 2 (later): swap to the per-instance `io_hierCovSumVec` vector + vector host
so covsteer steers per module. Only the coverage env changes here.

Distinguished from the other hierfuzz_* wrappers ONLY by `GEN=v2` (genv2) — those
run the v1 (DifuzzRTL-derived) generator.
"""

import os
import signal
import subprocess
import random
import string
import time

import defines
from host import Host
from bug import Bug


class HierFuzzDUT():
    def __init__(self, host: Host, bug: Bug):
        self.directory = os.path.join(bug.directory, "hierfuzz")
        os.makedirs(self.directory, exist_ok=True)
        self.host = host
        self.bug = bug
        self.name = self.bug.name + (''.join(random.choices(string.ascii_letters + string.digits, k=16)))
        self.env = os.environ.copy()
        # Use the BOOM-tuned ProcessorFuzz spike (1.0.1-dev, MAX_PADDR_BITS=32 +
        # data-inclusive +signature) with EMPTY args, exactly like the difuzz/
        # pfuzz baselines. The generic /opt/riscv spike (1.1.1) models a 55-bit
        # PA and a data-less +signature, which made the reference diverge from
        # BOOM on every test (pmpaddr WARL + the 6 _random_data sections). The
        # BOOM-tuned spike matches BOOM natively -> zero benign divergence. It
        # rejects --pmpregions, so HIERFUZZ_SPIKE_NO_PLATFORM strips those args
        # in utils.py. See error_tracking 20260720.
        self.env["SPIKE"] = "/encarsia-processorfuzz/processorfuzz_spike"
        self.env["HIERFUZZ_SPIKE_NO_PLATFORM"] = "1"
        self.env["PYTHONPATH"] = (
            f"{defines.HIERFUZZ_FUZZER}"
            f":{defines.HIERFUZZ_FUZZER}/.."
            f":/encarsia-difuzz-rtl/Fuzzer/src"
            f":/encarsia-difuzz-rtl/Fuzzer/RTLSim/src"
        )
        # genv2 generator/mutator (data-sensitive). Selected via GEN at
        # framework_strategy.py:230. This is the ONLY thing distinguishing this
        # arm from the v1 hierfuzz_* wrappers.
        self.env["GEN"] = "v2"
        # DUT-correct genv2 profile (RV64G, RVV off for both) so boundary/knob
        # gating matches the host; host.name is "rocket" or "boom".
        self.env["GENV2_PROFILE"] = self.host.name
        # Module-aware coverage. Scalar tree-sum (io_hierCovSumTotal) drives the
        # corpus-add gate; the per-instance vector (io_hierCovSumVec) drives
        # covsteer. HIERCOV_GATE=1 makes get_covsum read the hier total (not the
        # zeroed DifuzzRTL io_covSum). The io_hierCov* ports live on the inner
        # `core` instance (RocketTile/BoomTile receptor only exposes io_covSum).
        self.env["HIER_COV_TOTAL"] = "1"
        self.env["HIERCOV_GATE"] = "1"
        self.env["HIERCOV_CORE_PATH"] = "core"
        # Phase 2: per-instance vector + covsteer. The Yosys pass emits
        # io_hierCovSumVec + the layout manifest when HIERCOV_EMIT_SUMVEC=1;
        # covsteer reads the manifest (HIERCOV_VEC_MANIFEST) and the fuzzer reads
        # the port each test to learn per-module instruction-class credit.
        self.env["HIERCOV_EMIT_SUMVEC"] = "1"
        self.env["GENV2_STEER"] = "1"
        self.vec_manifest = os.path.join(self.directory, "hiercov_vec_manifest.json")
        self.env["HIERCOV_VEC_MANIFEST"] = self.vec_manifest
        self.env["COCOTB_RESULTS_FILE"] = os.path.join(defines.HIERFUZZ_FUZZER, "cocotb_results", self.name)
        os.makedirs(os.path.dirname(self.env["COCOTB_RESULTS_FILE"]), exist_ok=True)
        self.compile_failed = False

    def create_dut(self):
        host_rtlil = os.path.join(self.bug.directory, "host.rtlil")
        if not os.path.exists(host_rtlil):
            self.compile_failed = True
            print(f"Warning: skipping hierfuzz for bug {self.bug.name} (no host.rtlil)")
            return self

        self.module = os.path.join(self.directory, "host.v")
        if not os.path.exists(self.module):
            _env = dict(self.env)
            _env["HIERCOV_VEC_MANIFEST_OUT"] = self.vec_manifest
            subprocess.run(
                [defines.YOSYS_PATH, '-c', self.host.hierfuzz_data_bucket_tree_export_script],
                check=True,
                cwd=self.directory,
                stdout=subprocess.DEVNULL,
                env=_env
            )

        self.dut_path = os.path.join(self.directory, "dut.v")
        if not os.path.exists(self.dut_path):
            with open(self.dut_path, 'w') as dut_file:
                with open(self.host.hierfuzz_receptor, 'r') as receptor_file:
                    dut_file.write(receptor_file.read())
                with open(self.module, 'r') as module_file:
                    dut_file.write(module_file.read())

        return self

    def create_reference(self):
        if self.compile_failed:
            return self
        self.reference = os.path.join(self.directory, "reference.v")
        if not os.path.exists(self.reference):
            # Emit the vec port on the reference too (keeps the port list
            # symmetric with the buggy build) but write its manifest to a
            # throwaway path so the buggy DUT's manifest (used by the fuzzer)
            # is not clobbered. The reference is only checked for "Bug --".
            _env = dict(self.env)
            _env["HIERCOV_VEC_MANIFEST_OUT"] = os.path.join(
                self.directory, "hiercov_vec_manifest_ref.json")
            subprocess.run(
                [defines.YOSYS_PATH, '-c', self.host.hierfuzz_data_bucket_tree_ref_export],
                check=True,
                cwd=self.directory,
                stdout=subprocess.DEVNULL,
                env=_env
            )

        self.reference_dut = os.path.join(self.directory, "reference_dut.v")
        if not os.path.exists(self.reference_dut):
            with open(self.reference_dut, 'w') as reference_dut_file:
                with open(self.host.hierfuzz_receptor, 'r') as receptor_file:
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
                        f"OUT={os.path.relpath(self.out_directory, defines.HIERFUZZ_FUZZER)}"
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
        ts_path = os.path.join(self.directory, "fuzz_start.timestamp")
        if not os.path.exists(self.fuzz_log):
            self.fuzz_start_time = time.time()
            with open(ts_path, 'w') as f:
                f.write(str(self.fuzz_start_time))
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
                    f"OUT={os.path.relpath(self.out_directory, defines.HIERFUZZ_FUZZER)}"
                ],
                cwd=defines.HIERFUZZ_FUZZER,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=self.env,
                preexec_fn=os.setsid
            )
            time.sleep(defines.FUZZING_TIMEOUT)
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait()
            open(self.fuzz_log, 'w').close()
        else:
            if os.path.exists(ts_path):
                with open(ts_path, 'r') as f:
                    self.fuzz_start_time = float(f.read().strip())
            else:
                self.fuzz_start_time = None

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
                    f"OUT={os.path.relpath(self.out_reference_directory, defines.HIERFUZZ_FUZZER)}"
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
        _mm_dir = os.path.join(self.out_directory, "mismatch", "sim_input")
        # Replay ONLY the actual test inputs (.si). The mismatch dir also holds
        # .cause sidecars (~9-byte files containing the cause string, e.g.
        # "Mismatch"). Replaying a .cause makes mutator.read_siminput() try to
        # parse "Mismatch" as a template name -> ValueError, which aborts the
        # replay before any "Bug --" is printed -> check_mismatch then mis-reads
        # the absent "Bug --" as a genuine DETECTED (false positive that inflated
        # every mismatched bug to DETECTED). See error_tracking 20260720.
        mismatch_inputs = sorted([_f for _f in os.listdir(_mm_dir) if _f.endswith('.si')],
                                 key=lambda _f: os.path.getmtime(os.path.join(_mm_dir, _f)))
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
                        f"IN_FILE={os.path.relpath(os.path.join(self.out_directory, 'mismatch', 'sim_input', input), defines.HIERFUZZ_FUZZER)}"
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
