# Copyright 2024 Matej Bölcskei, ETH Zurich.
# Licensed under the General Public License, Version 3.0, see LICENSE for details.
# SPDX-License-Identifier: GPL-3.0-only

import argparse
import os
import datetime
import multiprocessing
import subprocess

from host import Host
from bug import Bug
from fuzzers.cascade_dut import CascadeDUT
from fuzzers.difuzzrtl_dut import DifuzzRTLDUT
from fuzzers.no_cov_difuzzrtl_dut import NoCovDifuzzRTLDUT
from fuzzers.processorfuzz_dut import ProcessorfuzzDUT
from fuzzers.no_cov_processorfuzz_dut import NoCovProcessorfuzzDUT
from fuzzers.prefilter_dut import PrefilterDUT
from fuzzers.hierfuzz_v6a_dut import HierFuzzV6aDUT
from fuzzers.hierfuzz_v6b_dut import HierFuzzV6bDUT
from fuzzers.hierfuzz_v9a_dut import HierFuzzV9aDUT
from fuzzers.no_cov_hierfuzz_dut import NoCovHierFuzzDUT
from fuzzers.hierfuzz_v6a_long_dut import HierFuzzV6aLongDUT
from fuzzers.hierfuzz_v6a_pfuzz_dut import HierFuzzV6aPfuzzDUT
from fuzzers.hierfuzz_v7_dut import HierFuzzV7DUT
from fuzzers.hierfuzz_v6a_covwt_dut import HierFuzzV6aCovWtDUT
import plot

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--directory", type=str, default=os.path.join(os.getcwd(), "out", datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S")), help="Working directory.\nA new directory will be created if none is specified.")
parser.add_argument("-H", "--hosts", type=str, nargs='+', help="List of host devices")
parser.add_argument("-p", "--processes", type=int, default=32, help="Number of processes running in parallel")
parser.add_argument("-M", "--multiplexer-bugs", type=str, nargs='+', help="Multiplexer bugs to be verified and evaluated")
parser.add_argument("-D", "--driver-bugs", type=str, nargs='+', help="Driver bugs to be verified and evaluated")
parser.add_argument("-P", "--prefilter", action="store_true", help="Enable bug prefiltering")
parser.add_argument("-V", "--verify", action="store_true", help="Enable bug verification")
parser.add_argument("-Y", "--yosys-verify", action="store_true", help="Enable bug verification with Yosys")
parser.add_argument("-F", "--fuzzers", type=str, nargs='+', help="Fuzzers to be verified and evaluated")
args = parser.parse_args()
working_directory = os.path.abspath(args.directory)

if __name__ == "__main__":
    # TODO parallelize injection
    for host in [Host(working_directory, name) for name in args.hosts]:
        print(f"Injecting bugs into {host.name}")
        host.inject()
        mux_directories = [name for name in os.listdir(host.mux_directory) if os.path.isdir(os.path.join(host.mux_directory, name))]
        driver_directories = [name for name in os.listdir(host.driver_directory) if os.path.isdir(os.path.join(host.driver_directory, name))]
        plot.save_injection_results(host)

        if args.driver_bugs:
            for driver_bug in args.driver_bugs:
                if driver_bug not in driver_directories:
                    print(driver_directories)
                    raise Exception(f"Bug '{driver_bug}' not found in the working directory {working_directory}!")
            driver_directories = args.driver_bugs
        if args.multiplexer_bugs:
            for mux_bug in args.multiplexer_bugs:
                if mux_bug not in mux_directories:
                    print(mux_directories)
                    raise Exception(f"Bug '{mux_bug}' not found in the working directory {working_directory}!")
            mux_directories = args.multiplexer_bugs

        driver_bugs = [Bug(host, name, True) for name in driver_directories]
        mux_bugs = [Bug(host, name, False) for name in mux_directories]
        bugs = driver_bugs+mux_bugs
        with multiprocessing.Pool(processes=args.processes) as verifier_pool:
            bugs = verifier_pool.map(Bug.prepare, bugs)
            
            if args.prefilter:
                prefilter_duts = [PrefilterDUT(host, bug) for bug in bugs]
                print("Encapsulating buggy designs in wrapper modules for compatibility with the prefilter")
                prefilter_duts = verifier_pool.map(PrefilterDUT.create_dut, prefilter_duts)
                print("Compiling buggy designs for RTL simulation")
                prefilter_duts = verifier_pool.map(PrefilterDUT.compile_dut, prefilter_duts)
                print("Prefiltering")
                prefilter_duts = verifier_pool.map(PrefilterDUT.fuzz, prefilter_duts)
                subprocess.run(["stty", "echo"])

                prefiltered_bugs = []
                for bug in bugs:
                    prefilter_log_path = os.path.join(bug.directory, "prefilter", "fuzz.log")
                    if os.path.exists(prefilter_log_path):
                        with open(prefilter_log_path, 'r') as prefilter_log:
                            if "Success\n" in prefilter_log.read():
                                prefiltered_bugs.append(bug)

                bugs = prefiltered_bugs

            if args.verify:
                print("Creating miter circuits")
                bugs = verifier_pool.map(Bug.create_miter, bugs)
                print("Verifying bugs with JasperGold")
                bugs = verifier_pool.map(Bug.verify, bugs)
                bugs = [bug for bug in bugs if os.path.exists(bug.proof_path)]

            if args.yosys_verify:
                print("Creating miter circuits")
                bugs = verifier_pool.map(Bug.create_miter, bugs)
                print("Verifying bugs with Yosys")
                bugs = verifier_pool.map(Bug.yosys_verify, bugs)
                plot.save_verification_results(host, bugs)
                
                bugs = [bug for bug in bugs if os.path.exists(bug.yosys_proof_path)]

            if args.fuzzers:
                for fuzzer in args.fuzzers:
                    if fuzzer == "cascade":
                        print(f"Fuzzing {host.name} with Cascade")
                        duts = [CascadeDUT(host, bug) for bug in bugs]
                        print("Encapsulating buggy designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(CascadeDUT.create_dut, duts)
                        print("Compiling buggy designs for RTL simulation")
                        duts = verifier_pool.map(CascadeDUT.compile_dut, duts)
                        print("Fuzzing")
                        duts = verifier_pool.map(CascadeDUT.fuzz, duts)
                        subprocess.run(["stty", "echo"])
                        plot.save_fuzzing_results(host, fuzzer, duts)
                    elif fuzzer == "difuzzrtl":
                        if host.name == "ibex":
                            print("DifuzzRTL does not support Ibex, skipping!")
                            continue
                        print(f"Fuzzing {host.name} with DifuzzRTL")
                        duts = [DifuzzRTLDUT(host, bug) for bug in bugs]
                        print("Encapsulating buggy designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(DifuzzRTLDUT.create_dut, duts)
                        print("Compiling buggy designs for RTL simulation")
                        duts = verifier_pool.map(DifuzzRTLDUT.compile_dut, duts)
                        print("Fuzzing")
                        duts = verifier_pool.map(DifuzzRTLDUT.fuzz, duts)
                        print("Encapsulating reference designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(DifuzzRTLDUT.create_reference, duts)
                        print("Compiling reference designs for RTL simulation")
                        duts = verifier_pool.map(DifuzzRTLDUT.compile_reference, duts)
                        print("Filtering false positives")
                        duts = verifier_pool.map(DifuzzRTLDUT.check_mismatch, duts)
                        subprocess.run(["stty", "echo"])
                        plot.save_fuzzing_results(host, fuzzer, duts)
                    elif fuzzer == "no_cov_difuzzrtl":
                        if host.name == "ibex":
                            print("DifuzzRTL does not support Ibex, skipping!")
                            continue
                        print(f"Fuzzing {host.name} with DifuzzRTL (no coverage)")
                        duts = [NoCovDifuzzRTLDUT(host, bug) for bug in bugs]
                        print("Encapsulating buggy designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(NoCovDifuzzRTLDUT.create_dut, duts)
                        print("Compiling buggy designs for RTL simulation")
                        duts = verifier_pool.map(NoCovDifuzzRTLDUT.compile_dut, duts)
                        print("Fuzzing")
                        duts = verifier_pool.map(NoCovDifuzzRTLDUT.fuzz, duts)
                        print("Encapsulating reference designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(NoCovDifuzzRTLDUT.create_reference, duts)
                        print("Compiling reference designs for RTL simulation")
                        duts = verifier_pool.map(NoCovDifuzzRTLDUT.compile_reference, duts)
                        print("Filtering false positives")
                        duts = verifier_pool.map(NoCovDifuzzRTLDUT.check_mismatch, duts)
                        subprocess.run(["stty", "echo"])
                        plot.save_fuzzing_results(host, fuzzer, duts)
                    elif fuzzer == "processorfuzz":
                        if host.name == "ibex":
                            print("ProcessorFuzz does not support Ibex, skipping!")
                            continue
                        print(f"Fuzzing {host.name} with ProcessorFuzz")
                        duts = [ProcessorfuzzDUT(host, bug) for bug in bugs]
                        print("Encapsulating buggy designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(ProcessorfuzzDUT.create_dut, duts)
                        print("Compiling buggy designs for RTL simulation")
                        duts = verifier_pool.map(ProcessorfuzzDUT.compile_dut, duts)
                        print("Fuzzing")
                        duts = verifier_pool.map(ProcessorfuzzDUT.fuzz, duts)
                        print("Encapsulating reference designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(ProcessorfuzzDUT.create_reference, duts)
                        print("Compiling reference designs for RTL simulation")
                        duts = verifier_pool.map(ProcessorfuzzDUT.compile_reference, duts)
                        print("Filtering false positives")
                        duts = verifier_pool.map(ProcessorfuzzDUT.check_mismatch, duts)
                        subprocess.run(["stty", "echo"])
                        plot.save_fuzzing_results(host, fuzzer, duts)
                    elif fuzzer == "no_cov_processorfuzz":
                        if host.name == "ibex":
                            print("ProcessorFuzz does not support Ibex, skipping!")
                            continue
                        print(f"Fuzzing {host.name} with ProcessorFuzz (no coverage)")
                        duts = [NoCovProcessorfuzzDUT(host, bug) for bug in bugs]
                        print("Encapsulating buggy designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(NoCovProcessorfuzzDUT.create_dut, duts)
                        print("Compiling buggy designs for RTL simulation")
                        duts = verifier_pool.map(NoCovProcessorfuzzDUT.compile_dut, duts)
                        print("Fuzzing")
                        duts = verifier_pool.map(NoCovProcessorfuzzDUT.fuzz, duts)
                        print("Encapsulating reference designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(NoCovProcessorfuzzDUT.create_reference, duts)
                        print("Compiling reference designs for RTL simulation")
                        duts = verifier_pool.map(NoCovProcessorfuzzDUT.compile_reference, duts)
                        print("Filtering false positives")
                        duts = verifier_pool.map(NoCovProcessorfuzzDUT.check_mismatch, duts)
                        subprocess.run(["stty", "echo"])
                        plot.save_fuzzing_results(host, fuzzer, duts)
                    elif fuzzer == "hierfuzz_v6a":
                        if host.name in ["ibex", "cva6"]:
                            print(f"HierFuzz does not support {host.name}, skipping!")
                            continue
                        print(f"Fuzzing {host.name} with HierFuzz v6a")
                        duts = [HierFuzzV6aDUT(host, bug) for bug in bugs]
                        print("Encapsulating buggy designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(HierFuzzV6aDUT.create_dut, duts)
                        print("Compiling buggy designs for RTL simulation")
                        duts = verifier_pool.map(HierFuzzV6aDUT.compile_dut, duts)
                        print("Fuzzing")
                        duts = verifier_pool.map(HierFuzzV6aDUT.fuzz, duts)
                        print("Encapsulating reference designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(HierFuzzV6aDUT.create_reference, duts)
                        print("Compiling reference designs for RTL simulation")
                        duts = verifier_pool.map(HierFuzzV6aDUT.compile_reference, duts)
                        print("Filtering false positives")
                        duts = verifier_pool.map(HierFuzzV6aDUT.check_mismatch, duts)
                        subprocess.run(["stty", "echo"])
                        plot.save_fuzzing_results(host, fuzzer, duts)
                    elif fuzzer == "hierfuzz_v6b":
                        if host.name in ["ibex", "cva6"]:
                            print(f"HierFuzz does not support {host.name}, skipping!")
                            continue
                        print(f"Fuzzing {host.name} with HierFuzz v6b")
                        duts = [HierFuzzV6bDUT(host, bug) for bug in bugs]
                        print("Encapsulating buggy designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(HierFuzzV6bDUT.create_dut, duts)
                        print("Compiling buggy designs for RTL simulation")
                        duts = verifier_pool.map(HierFuzzV6bDUT.compile_dut, duts)
                        print("Fuzzing")
                        duts = verifier_pool.map(HierFuzzV6bDUT.fuzz, duts)
                        print("Encapsulating reference designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(HierFuzzV6bDUT.create_reference, duts)
                        print("Compiling reference designs for RTL simulation")
                        duts = verifier_pool.map(HierFuzzV6bDUT.compile_reference, duts)
                        print("Filtering false positives")
                        duts = verifier_pool.map(HierFuzzV6bDUT.check_mismatch, duts)
                        subprocess.run(["stty", "echo"])
                        plot.save_fuzzing_results(host, fuzzer, duts)
                    elif fuzzer == "hierfuzz_v9a":
                        if host.name in ["ibex", "cva6"]:
                            print(f"HierFuzz does not support {host.name}, skipping!")
                            continue
                        print(f"Fuzzing {host.name} with HierFuzz v9a")
                        duts = [HierFuzzV9aDUT(host, bug) for bug in bugs]
                        print("Encapsulating buggy designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(HierFuzzV9aDUT.create_dut, duts)
                        print("Compiling buggy designs for RTL simulation")
                        duts = verifier_pool.map(HierFuzzV9aDUT.compile_dut, duts)
                        print("Fuzzing")
                        duts = verifier_pool.map(HierFuzzV9aDUT.fuzz, duts)
                        print("Encapsulating reference designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(HierFuzzV9aDUT.create_reference, duts)
                        print("Compiling reference designs for RTL simulation")
                        duts = verifier_pool.map(HierFuzzV9aDUT.compile_reference, duts)
                        print("Filtering false positives")
                        duts = verifier_pool.map(HierFuzzV9aDUT.check_mismatch, duts)
                        subprocess.run(["stty", "echo"])
                        plot.save_fuzzing_results(host, fuzzer, duts)
                    elif fuzzer == "no_cov_hierfuzz":
                        if host.name in ["ibex", "cva6"]:
                            print(f"HierFuzz does not support {host.name}, skipping!")
                            continue
                        print(f"Fuzzing {host.name} with HierFuzz (no coverage)")
                        duts = [NoCovHierFuzzDUT(host, bug) for bug in bugs]
                        print("Encapsulating buggy designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(NoCovHierFuzzDUT.create_dut, duts)
                        print("Compiling buggy designs for RTL simulation")
                        duts = verifier_pool.map(NoCovHierFuzzDUT.compile_dut, duts)
                        print("Fuzzing")
                        duts = verifier_pool.map(NoCovHierFuzzDUT.fuzz, duts)
                        print("Encapsulating reference designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(NoCovHierFuzzDUT.create_reference, duts)
                        print("Compiling reference designs for RTL simulation")
                        duts = verifier_pool.map(NoCovHierFuzzDUT.compile_reference, duts)
                        print("Filtering false positives")
                        duts = verifier_pool.map(NoCovHierFuzzDUT.check_mismatch, duts)
                        subprocess.run(["stty", "echo"])
                        plot.save_fuzzing_results(host, fuzzer, duts)
                    elif fuzzer == "hierfuzz_v6a_long":
                        if host.name in ["ibex", "cva6"]:
                            print(f"HierFuzz does not support {host.name}, skipping!")
                            continue
                        print(f"Fuzzing {host.name} with HierFuzz v6a (long timeout)")
                        duts = [HierFuzzV6aLongDUT(host, bug) for bug in bugs]
                        print("Encapsulating buggy designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(HierFuzzV6aLongDUT.create_dut, duts)
                        print("Compiling buggy designs for RTL simulation")
                        duts = verifier_pool.map(HierFuzzV6aLongDUT.compile_dut, duts)
                        print("Fuzzing")
                        duts = verifier_pool.map(HierFuzzV6aLongDUT.fuzz, duts)
                        print("Encapsulating reference designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(HierFuzzV6aLongDUT.create_reference, duts)
                        print("Compiling reference designs for RTL simulation")
                        duts = verifier_pool.map(HierFuzzV6aLongDUT.compile_reference, duts)
                        print("Filtering false positives")
                        duts = verifier_pool.map(HierFuzzV6aLongDUT.check_mismatch, duts)
                        subprocess.run(["stty", "echo"])
                        plot.save_fuzzing_results(host, fuzzer, duts)
                    elif fuzzer == "hierfuzz_v6a_pfuzz":
                        if host.name in ["ibex", "cva6"]:
                            print(f"HierFuzz does not support {host.name}, skipping!")
                            continue
                        print(f"Fuzzing {host.name} with HierFuzz v6a + ProcessorFuzz mutator")
                        duts = [HierFuzzV6aPfuzzDUT(host, bug) for bug in bugs]
                        print("Encapsulating buggy designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(HierFuzzV6aPfuzzDUT.create_dut, duts)
                        print("Compiling buggy designs for RTL simulation")
                        duts = verifier_pool.map(HierFuzzV6aPfuzzDUT.compile_dut, duts)
                        print("Fuzzing")
                        duts = verifier_pool.map(HierFuzzV6aPfuzzDUT.fuzz, duts)
                        print("Encapsulating reference designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(HierFuzzV6aPfuzzDUT.create_reference, duts)
                        print("Compiling reference designs for RTL simulation")
                        duts = verifier_pool.map(HierFuzzV6aPfuzzDUT.compile_reference, duts)
                        print("Filtering false positives")
                        duts = verifier_pool.map(HierFuzzV6aPfuzzDUT.check_mismatch, duts)
                        subprocess.run(["stty", "echo"])
                        plot.save_fuzzing_results(host, fuzzer, duts)
                    elif fuzzer == "hierfuzz_v7":
                        if host.name in ["ibex", "cva6"]:
                            print(f"HierFuzz does not support {host.name}, skipping!")
                            continue
                        print(f"Fuzzing {host.name} with HierFuzz v7")
                        duts = [HierFuzzV7DUT(host, bug) for bug in bugs]
                        print("Encapsulating buggy designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(HierFuzzV7DUT.create_dut, duts)
                        print("Compiling buggy designs for RTL simulation")
                        duts = verifier_pool.map(HierFuzzV7DUT.compile_dut, duts)
                        print("Fuzzing")
                        duts = verifier_pool.map(HierFuzzV7DUT.fuzz, duts)
                        print("Encapsulating reference designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(HierFuzzV7DUT.create_reference, duts)
                        print("Compiling reference designs for RTL simulation")
                        duts = verifier_pool.map(HierFuzzV7DUT.compile_reference, duts)
                        print("Filtering false positives")
                        duts = verifier_pool.map(HierFuzzV7DUT.check_mismatch, duts)
                        subprocess.run(["stty", "echo"])
                        plot.save_fuzzing_results(host, fuzzer, duts)
                    elif fuzzer == "hierfuzz_v6a_covwt":
                        if host.name in ["ibex", "cva6"]:
                            print(f"HierFuzz does not support {host.name}, skipping!")
                            continue
                        print(f"Fuzzing {host.name} with HierFuzz v6a (coverage-weighted mutation)")
                        duts = [HierFuzzV6aCovWtDUT(host, bug) for bug in bugs]
                        print("Encapsulating buggy designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(HierFuzzV6aCovWtDUT.create_dut, duts)
                        print("Compiling buggy designs for RTL simulation")
                        duts = verifier_pool.map(HierFuzzV6aCovWtDUT.compile_dut, duts)
                        print("Fuzzing")
                        duts = verifier_pool.map(HierFuzzV6aCovWtDUT.fuzz, duts)
                        print("Encapsulating reference designs in wrapper modules for compatibility with the fuzzer")
                        duts = verifier_pool.map(HierFuzzV6aCovWtDUT.create_reference, duts)
                        print("Compiling reference designs for RTL simulation")
                        duts = verifier_pool.map(HierFuzzV6aCovWtDUT.compile_reference, duts)
                        print("Filtering false positives")
                        duts = verifier_pool.map(HierFuzzV6aCovWtDUT.check_mismatch, duts)
                        subprocess.run(["stty", "echo"])
                        plot.save_fuzzing_results(host, fuzzer, duts)
                    else:
                        raise Exception(f"Fuzzer '{fuzzer}' not found!")
                    
    plot.plot_injection()
    plot.plot_verification()
    plot.plot_fuzzing()