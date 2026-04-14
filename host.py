# Copyright 2024 Matej Bölcskei, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

import os
import re
import shutil
import subprocess
import datetime

import defines
import config


def _preprocess_verilog_for_yosys(content: str, output_path: str):
    """Remove unsynthesizable code from DifuzzRTL receptors for Yosys.

    Removes: `ifdef MULTICORE blocks, initial blocks, always blocks with system tasks.
    Preserves: all `ifdef/`endif balance, module/endmodule structure.
    """
    SYSTASKS = ['$fwrite', '$fopen', '$fclose', '$display', '$fdisplay',
                '$value$plusargs', '$readmemh', '$sformatf']
    lines = content.split('\n')
    result = []
    i = 0

    def count_begin_end(s):
        return len(re.findall(r'\bbegin\b', s)), len(re.findall(r'\bend\b', s))

    def skip_block(start):
        """Skip a begin/end block starting at line `start`. Return next line index.
        Preserves `ifdef/`endif directives to maintain balance."""
        s = lines[start].strip()
        opens, closes = count_begin_end(s)
        depth = opens - closes
        j = start + 1
        while j < len(lines) and depth > 0:
            s = lines[j].strip()
            o, c = count_begin_end(s)
            depth += o - c
            # Preserve preprocessor directives
            if re.match(r'\s*`(ifdef|ifndef|else|endif)\b', s):
                result.append(lines[j])
            j += 1
        return j

    def skip_ifdef_block(start):
        """Skip an `ifdef block. Return next line index."""
        depth = 1
        j = start + 1
        while j < len(lines) and depth > 0:
            s = lines[j].strip()
            if re.match(r'\s*`(ifdef|ifndef)\b', s):
                depth += 1
            elif re.match(r'\s*`endif\b', s):
                depth -= 1
            j += 1
        return j

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Skip `ifdef MULTICORE blocks entirely
        if re.match(r'\s*`ifdef\s+MULTICORE\b', stripped):
            i = skip_ifdef_block(i)
            continue

        # Skip initial begin blocks
        if re.match(r'\s*initial\s+begin\b', stripped):
            i = skip_block(i)
            continue

        # Skip always blocks containing system tasks
        if re.match(r'\s*always\s+@', stripped) and 'begin' in stripped:
            # Look ahead to collect the block and check for system tasks
            s = stripped
            depth = count_begin_end(s)[0] - count_begin_end(s)[1]
            j = i + 1
            while j < len(lines) and depth > 0:
                s = lines[j].strip()
                o, c = count_begin_end(s)
                depth += o - c
                j += 1
            block_text = '\n'.join(lines[i:j])
            if any(t in block_text for t in SYSTASKS):
                # Skip this always block, preserving ifdefs
                for k in range(i, j):
                    if re.match(r'\s*`(ifdef|ifndef|else|endif)\b', lines[k].strip()):
                        result.append(lines[k])
                i = j
                continue

        result.append(line)
        i += 1

    with open(output_path, 'w') as f:
        f.write('\n'.join(result))


class Host:
    def __init__(self, out_directory: str, name: str):
        self.name = name
        self.config = config.get_host_config(name)

        self.directory = os.path.join(out_directory, name)
        self.mux_directory = os.path.join(self.directory, "multiplexer")
        if not os.path.isdir(self.mux_directory):
            os.makedirs(self.mux_directory)
        self.driver_directory = os.path.join(self.directory, "driver")
        if not os.path.isdir(self.driver_directory):
            os.makedirs(self.driver_directory)

        self.create_reference()

        self.create_inject_script()
        self.create_prepare_scripts()
        self.create_miter_script()
        self.create_yosys_verify_script()

        self.create_export_script()
        self.create_instrument_script()

        self.create_cascade_receptor()
        self.create_difuzzrtl_receptor()
        self.create_processorfuzz_receptor()
        self.create_hierfuzz_receptor()
        self.create_hierfuzz_export_script()

    def create_reference(self):
        # Always plain — no hierCov. difuzzrtl/processorfuzz need a clean reference.
        self.reference_path = os.path.join(self.directory, "reference.v")
        if not os.path.exists(self.reference_path):
            reference = "\n".join(open(source, 'r').read() for source in self.config.reference_sources)
            for module in self.config.not_synthesizable:
                reference = re.sub(
                    pattern=r'\bmodule\s+' + module + r'\b.*?\bendmodule\b',
                    repl="",
                    string=reference,
                    flags=re.MULTILINE | re.DOTALL
                )
            with open(self.reference_path, 'w') as reference_file:
                reference_file.write(reference)

    def create_inject_script(self):
        self.inject_driver = os.path.join(self.directory, "inject_driver.tcl")
        if not os.path.exists(self.inject_driver):
            inject_driver = (
                f'yosys "read_verilog{" -defer" if self.name == "cva6" else ""} -sv {self.reference_path}"\n'
                f'yosys "hierarchy -check -top {self.config.host_module}"\n'
                f'yosys "setattr -unset always_comb p:*"\n'
                f'yosys "proc -norom"\n' +
                (f'yosys "opt_clean"\n' if self.name == "cva6" else "") +
                f'yosys "inject_driver -output-dir {self.driver_directory}"\n'
            )
            with open(self.inject_driver, 'w') as inject_driver_file:
                inject_driver_file.write(inject_driver)

        self.inject_multiplexer = os.path.join(self.directory, "inject_multiplexer.tcl")
        if not os.path.exists(self.inject_multiplexer):
            inject_multiplexer = (
                f'yosys "read_verilog{" -defer" if self.name == "cva6" else ""} -sv {self.reference_path}"\n'
                f'yosys "hierarchy -check -top {self.config.host_module}"\n'
                f'yosys "setattr -unset always_comb p:*"\n'
                f'yosys "proc -norom"\n' +
                # f'yosys "muxpack"\n' +
                (f'yosys "opt_clean"\n' if self.name == "cva6" else "") +
                f'yosys "inject -output-dir {self.mux_directory}"\n'
            )
            with open(self.inject_multiplexer, 'w') as inject_multiplexer_file:
                inject_multiplexer_file.write(inject_multiplexer)

        # HierCov injection no longer needed — Yosys pass instruments plain RTLIL on the fly

    def create_prepare_scripts(self):
        self.prepare_driver = os.path.join(self.directory, "prepare_driver.tcl")
        if not os.path.exists(self.prepare_driver):
            prepare_driver = (
                f'yosys "read_rtlil host_driver.rtlil"\n'
                f'yosys "flatten"\n'
                f'yosys "write_rtlil host.rtlil"\n'
                f'yosys "write_verilog host.v"\n'
                f'yosys "delete"\n'
                f'yosys "read_rtlil reference_driver.rtlil"\n'
                f'yosys "flatten"\n'
                f'yosys "write_rtlil reference.rtlil"\n'
            )
            with open(self.prepare_driver, 'w') as prepare_driver_file:
                prepare_driver_file.write(prepare_driver)

        self.prepare_multiplexer = os.path.join(self.directory, "prepare_multiplexer.tcl")
        if not os.path.exists(self.prepare_multiplexer):
            prepare_multiplexer = (
                f'yosys "read_rtlil host_amt.rtlil"\n'
                f'yosys "inject_map"\n'
                f'yosys "flatten"\n'
                f'yosys "write_rtlil host.rtlil"\n'
                f'yosys "write_verilog host.v"\n'
                f'yosys "delete"\n'
                f'yosys "read_rtlil ../reference.rtlil"\n'
                f'yosys "inject_map"\n'
                f'yosys "flatten"\n'
                f'yosys "write_rtlil reference.rtlil"\n'
            )
            with open(self.prepare_multiplexer, 'w') as prepare_multiplexer_file:
                prepare_multiplexer_file.write(prepare_multiplexer)

    def create_miter_script(self):
        self.miter_script = os.path.join(self.directory, "miter.tcl")
        if not os.path.exists(self.miter_script):
            observables = " \\\n".join(f"-observable {observable}" for observable in self.config.observables)
            miter_script = (
                f'yosys "read_rtlil host.rtlil"\n'
                f'yosys "rename {self.config.host_module} host"\n'
                f'yosys "read_rtlil reference.rtlil"\n'
                f'yosys "rename {self.config.host_module} reference"\n' +
                ('yosys "memory m:*rf*"\n' if self.name == "rocket" else "") +
                f'yosys "create_miter \\\n'
                f'{observables}"'
            )
            with open(self.miter_script, 'w') as miter_script_file:
                miter_script_file.write(miter_script)

    def create_yosys_verify_script(self):
        self.yosys_verify_script = os.path.join(self.directory, "yosys_verify_script.tcl")
        if not os.path.exists(self.yosys_verify_script):
            sets = " \\\n".join(f"-set {set}" for set in self.config.sets)
            yosys_verify_script = (
                f'yosys "read_rtlil miter.rtlil"\n'
                f'yosys "verify_miter \\\n'
                f'-max-sensitization {self.config.sensitization_cycles} \\\n'
                f'-max-propagation {self.config.propagation_cycles} \\\n'
                f'-timeout {self.config.timeout} \\\n'
                f'-set-init-zero \\\n'
                f'{sets} \\\n'
                f'-show-inputs \\\n'
                f'-show-outputs"'
            )
            with open(self.yosys_verify_script, 'w') as verify_file:
                verify_file.write(yosys_verify_script)

    def create_export_script(self):
        self.export_script = os.path.join(self.directory, "export.tcl")
        if not os.path.exists(self.export_script):
            export_script = (
                f'yosys "read_rtlil ../host.rtlil"\n'
                f'yosys "write_verilog host.v"\n'
            )
            with open(self.export_script, 'w') as export_script_file:
                export_script_file.write(export_script)

        self.export_cascade_reference = os.path.join(self.directory, "export_cascade_reference.tcl")
        if not os.path.exists(self.export_cascade_reference):
            export_cascade_reference_script = (
                f'yosys "read_rtlil ../reference.rtlil"\n'
                f'yosys "write_verilog reference.v"\n'
            )
            with open(self.export_cascade_reference, 'w') as f:
                f.write(export_cascade_reference_script)

    def create_instrument_script(self):
        self.instrument_script = os.path.join(self.directory, "instrument.tcl")
        if not os.path.exists(self.instrument_script):
            instrument_script = (
                f'yosys "read_rtlil ../host.rtlil"\n'
                f'yosys "difuzzrtl_instrument"\n'
                f'yosys "write_verilog host.v"\n'
            )
            with open(self.instrument_script, 'w') as instrument_script_file:
                instrument_script_file.write(instrument_script)

        self.export_difuzzrtl_reference = os.path.join(self.directory, "export_difuzzrtl_reference.tcl")
        if not os.path.exists(self.export_difuzzrtl_reference):
            export_difuzzrtl_reference_script = (
                f'yosys "read_rtlil ../reference.rtlil"\n'
                f'yosys "difuzzrtl_instrument"\n'
                f'yosys "write_verilog reference.v"\n'
            )
            with open(self.export_difuzzrtl_reference, 'w') as export_difuzzrtl_reference_file:
                export_difuzzrtl_reference_file.write(export_difuzzrtl_reference_script)

    def create_cascade_receptor(self):
        self.cascade_receptor = os.path.join(self.directory, "cascade_receptor.v")
        if not os.path.exists(self.cascade_receptor):
            cascade_receptor = "\n".join(open(source, 'r').read() for source in self.config.cascade_receptor_sources)
            for module in self.config.not_synthesizable + [self.config.host_module]:
                cascade_receptor = re.sub(
                    pattern=r'\bmodule\s+' + module + r'\b.*?\bendmodule\b',
                    repl="",
                    string=cascade_receptor,
                    flags=re.MULTILINE | re.DOTALL
                )
            with open(self.cascade_receptor, 'w') as cascade_receptor_file:
                cascade_receptor_file.write(cascade_receptor)

    def create_difuzzrtl_receptor(self):
        self.difuzzrtl_receptor = os.path.join(self.directory, "difuzzrtl_receptor.v")
        if not os.path.exists(self.difuzzrtl_receptor):
            difuzzrtl_receptor = re.sub(
                pattern=r'\bmodule\s+' + self.config.host_module + r'\b.*?\bendmodule\b',
                repl="",
                string="\n".join(open(source, 'r').read() for source in self.config.difuzzrtl_receptor_sources),
                flags=re.MULTILINE | re.DOTALL
            )
            with open(self.difuzzrtl_receptor, 'w') as difuzzrtl_receptor_file:
                difuzzrtl_receptor_file.write(difuzzrtl_receptor)

    def create_processorfuzz_receptor(self):
        self.processorfuzz_receptor = os.path.join(self.directory, "processorfuzz_receptor.v")
        if not os.path.exists(self.processorfuzz_receptor):
            processorfuzz_receptor = re.sub(
                pattern=r'\bmodule\s+' + self.config.host_module + r'\b.*?\bendmodule\b',
                repl="",
                string="\n".join(open(source, 'r').read() for source in self.config.processorfuzz_receptor_sources),
                flags=re.MULTILINE | re.DOTALL
            )
            with open(self.processorfuzz_receptor, 'w') as processorfuzz_receptor_file:
                processorfuzz_receptor_file.write(processorfuzz_receptor)

    def create_hierfuzz_receptor(self):
        # Use DifuzzRTL receptor directly (has auto_reset_vector_in, metaReset, io_covSum).
        # No Yosys processing needed — the per-bug host.v has matching ports
        # (io_covSum added as dummy zero by hierfuzz Yosys pass for compatibility).
        self.hierfuzz_receptor = os.path.join(self.directory, "hierfuzz_receptor.v")
        if not os.path.exists(self.hierfuzz_receptor):
            receptor_content = "\n".join(
                open(src, 'r').read() for src in self.config.hierfuzz_receptor_sources
            )
            receptor_content = re.sub(
                pattern=r'\bmodule\s+' + self.config.host_module + r'\b.*?\bendmodule\b',
                repl="",
                string=receptor_content,
                flags=re.MULTILINE | re.DOTALL
            )
            with open(self.hierfuzz_receptor, 'w') as f:
                f.write(receptor_content)

        # Plain receptor for no_cov_hierfuzz — same DifuzzRTL receptor
        self.hierfuzz_nocov_receptor = os.path.join(self.directory, "hierfuzz_nocov_receptor.v")
        if not os.path.exists(self.hierfuzz_nocov_receptor):
            nocov_content = "\n".join(
                open(src, 'r').read() for src in self.config.difuzzrtl_receptor_sources
            )
            nocov_content = re.sub(
                pattern=r'\bmodule\s+' + self.config.host_module + r'\b.*?\bendmodule\b',
                repl="",
                string=nocov_content,
                flags=re.MULTILINE | re.DOTALL
            )
            with open(self.hierfuzz_nocov_receptor, 'w') as f:
                f.write(nocov_content)

    def create_hierfuzz_export_script(self):
        # v6a: instrument plain RTLIL with Yosys hierfuzz pass (no pre-built hierCov needed)
        self.hierfuzz_v6a_export_script = os.path.join(self.directory, "hierfuzz_v6a_export.tcl")
        if not os.path.exists(self.hierfuzz_v6a_export_script):
            script = (
                f'yosys "read_rtlil ../host.rtlil"\n'
                f'yosys "hierfuzz_instrument_v6a"\n'
                f'yosys "write_verilog host.v"\n'
            )
            with open(self.hierfuzz_v6a_export_script, 'w') as f:
                f.write(script)

        self.hierfuzz_v6a_ref_export = os.path.join(self.directory, "hierfuzz_v6a_ref_export.tcl")
        if not os.path.exists(self.hierfuzz_v6a_ref_export):
            script = (
                f'yosys "read_rtlil ../reference.rtlil"\n'
                f'yosys "hierfuzz_instrument_v6a"\n'
                f'yosys "write_verilog reference.v"\n'
            )
            with open(self.hierfuzz_v6a_ref_export, 'w') as f:
                f.write(script)

        # v6b: same but with v6b pass
        self.hierfuzz_v6b_export_script = os.path.join(self.directory, "hierfuzz_v6b_export.tcl")
        if not os.path.exists(self.hierfuzz_v6b_export_script):
            script = (
                f'yosys "read_rtlil ../host.rtlil"\n'
                f'yosys "hierfuzz_instrument_v6b"\n'
                f'yosys "write_verilog host.v"\n'
            )
            with open(self.hierfuzz_v6b_export_script, 'w') as f:
                f.write(script)

        self.hierfuzz_v6b_ref_export = os.path.join(self.directory, "hierfuzz_v6b_ref_export.tcl")
        if not os.path.exists(self.hierfuzz_v6b_ref_export):
            script = (
                f'yosys "read_rtlil ../reference.rtlil"\n'
                f'yosys "hierfuzz_instrument_v6b"\n'
                f'yosys "write_verilog reference.v"\n'
            )
            with open(self.hierfuzz_v6b_ref_export, 'w') as f:
                f.write(script)

        # no_cov: still instrument with hierfuzz_instrument_v6a for port compatibility
        # with DifuzzRTL receptor (io_covSum, metaReset, metaAssert).
        # Coverage guidance is disabled via NO_GUIDE=1 in the fuzzer, not by skipping the pass.
        self.hierfuzz_nocov_export_script = os.path.join(self.directory, "hierfuzz_nocov_export.tcl")
        if not os.path.exists(self.hierfuzz_nocov_export_script):
            script = (
                f'yosys "read_rtlil ../host.rtlil"\n'
                f'yosys "hierfuzz_instrument_v6a"\n'
                f'yosys "write_verilog host.v"\n'
            )
            with open(self.hierfuzz_nocov_export_script, 'w') as f:
                f.write(script)

        self.hierfuzz_nocov_ref_export = os.path.join(self.directory, "hierfuzz_nocov_ref_export.tcl")
        if not os.path.exists(self.hierfuzz_nocov_ref_export):
            script = (
                f'yosys "read_rtlil ../reference.rtlil"\n'
                f'yosys "hierfuzz_instrument_v6a"\n'
                f'yosys "write_verilog reference.v"\n'
            )
            with open(self.hierfuzz_nocov_ref_export, 'w') as f:
                f.write(script)

        # v7: dynamic hash sizing + extmodule proxy + raised caps
        self.hierfuzz_v7_export_script = os.path.join(self.directory, "hierfuzz_v7_export.tcl")
        if not os.path.exists(self.hierfuzz_v7_export_script):
            script = (
                f'yosys "read_rtlil ../host.rtlil"\n'
                f'yosys "hierfuzz_instrument_v7"\n'
                f'yosys "write_verilog host.v"\n'
            )
            with open(self.hierfuzz_v7_export_script, 'w') as f:
                f.write(script)

        self.hierfuzz_v7_ref_export = os.path.join(self.directory, "hierfuzz_v7_ref_export.tcl")
        if not os.path.exists(self.hierfuzz_v7_ref_export):
            script = (
                f'yosys "read_rtlil ../reference.rtlil"\n'
                f'yosys "hierfuzz_instrument_v7"\n'
                f'yosys "write_verilog reference.v"\n'
            )
            with open(self.hierfuzz_v7_ref_export, 'w') as f:
                f.write(script)

        # v9a: direct concatenation / XOR-fold hash, v6b-style fixed sizing,
        # submodHashSize=16, maxAddrWidth=20, control input ports for input hash
        self.hierfuzz_v9a_export_script = os.path.join(self.directory, "hierfuzz_v9a_export.tcl")
        if not os.path.exists(self.hierfuzz_v9a_export_script):
            script = (
                f'yosys "read_rtlil ../host.rtlil"\n'
                f'yosys "hierfuzz_instrument_v9a"\n'
                f'yosys "write_verilog host.v"\n'
            )
            with open(self.hierfuzz_v9a_export_script, 'w') as f:
                f.write(script)

        self.hierfuzz_v9a_ref_export = os.path.join(self.directory, "hierfuzz_v9a_ref_export.tcl")
        if not os.path.exists(self.hierfuzz_v9a_ref_export):
            script = (
                f'yosys "read_rtlil ../reference.rtlil"\n'
                f'yosys "hierfuzz_instrument_v9a"\n'
                f'yosys "write_verilog reference.v"\n'
            )
            with open(self.hierfuzz_v9a_ref_export, 'w') as f:
                f.write(script)

    def inject(self):
        self.inject_multiplexer_log = os.path.join(self.directory, "inject_multiplexer.log")
        if not os.path.exists(self.inject_multiplexer_log):
            with open(self.inject_multiplexer_log, 'w') as f:
                f.write(datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S-%f"))
                f.flush()
                subprocess.run(
                    [defines.YOSYS_PATH, '-c', self.inject_multiplexer],
                    check=True,
                    stdout=f
                )
                f.flush()
                f.write(datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S-%f"))
                f.flush()

        self.inject_driver_log = os.path.join(self.directory, "inject_driver.log")
        if not os.path.exists(self.inject_driver_log):
            with open(self.inject_driver_log, 'w') as f:
                f.write(datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S-%f"))
                f.flush()
                subprocess.run(
                    [defines.YOSYS_PATH, '-c', self.inject_driver],
                    check=True,
                    stdout=f
                )

                f.flush()
                f.write(datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S-%f"))
                f.flush()

