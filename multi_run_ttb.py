"""Multi-Run TTB (Time to Bug) Experiment Framework.

Runs N independent fuzz sessions per (bug, fuzzer) pair to collect
statistically meaningful TTB data. Reuses existing DUT classes for
compilation and detection logic.

Usage:
    python multi_run_ttb.py -d out/EnCorpus -H rocket boom -p 15 -N 100 \
        --early-stop 10 --results-dir out/ttb_results \
        --fuzzers hierfuzz_v6a hierfuzz_v6b hierfuzz_v6a_pfuzz \
                  hierfuzz_v9a hierfuzz_v9a_pfuzz ttb_difuzzrtl ttb_processorfuzz
"""

import argparse
import glob
import json
import multiprocessing
import os
import re
import shutil
import statistics
import sys
import time
import traceback

from host import Host
from bug import Bug
from fuzzers.hierfuzz_v6a_dut import HierFuzzV6aDUT
from fuzzers.hierfuzz_v6b_dut import HierFuzzV6bDUT
from fuzzers.hierfuzz_v9a_dut import HierFuzzV9aDUT
from fuzzers.hierfuzz_v6a_pfuzz_dut import HierFuzzV6aPfuzzDUT
from fuzzers.hierfuzz_v9a_pfuzz_dut import HierFuzzV9aPfuzzDUT
from fuzzers.ttb_difuzzrtl_dut import TTBDifuzzRTLDUT
from fuzzers.ttb_processorfuzz_dut import TTBProcessorfuzzDUT
from fuzzers.filtered_cascade_dut import FilteredCascadeDUT

FUZZER_MAP = {
    'hierfuzz_v6a': HierFuzzV6aDUT,
    'hierfuzz_v6b': HierFuzzV6bDUT,
    'hierfuzz_v9a': HierFuzzV9aDUT,
    'hierfuzz_v6a_pfuzz': HierFuzzV6aPfuzzDUT,
    'hierfuzz_v9a_pfuzz': HierFuzzV9aPfuzzDUT,
    'ttb_difuzzrtl': TTBDifuzzRTLDUT,
    'ttb_processorfuzz': TTBProcessorfuzzDUT,
    'filtered_cascade': FilteredCascadeDUT,
}

# Fuzzers that use out_replay/ (ProcessorFuzz-style two-stage check)
PFUZZ_FUZZERS = {'hierfuzz_v6a_pfuzz', 'hierfuzz_v9a_pfuzz', 'ttb_processorfuzz'}

# Cascade-based fuzzers (different directory structure, no out/mismatch)
CASCADE_FUZZERS = {'filtered_cascade'}


def clear_fuzz_outputs(dut, fuzzer_name):
    """Clear fuzz outputs to allow a fresh fuzz() run, preserving compiled binaries."""
    directory = dut.directory

    # Delete skip sentinels (common to all fuzzers)
    for fname in ("fuzz.log", "fuzz_start.timestamp", "check_summary.log"):
        path = os.path.join(directory, fname)
        if os.path.exists(path):
            os.remove(path)

    if fuzzer_name in CASCADE_FUZZERS:
        # Cascade: different structure — no out/mismatch, uses experimental-data dirs
        for fname in ("reference_fuzz.log",):
            path = os.path.join(directory, fname)
            if os.path.exists(path):
                os.remove(path)
        for data_dir in ("experimental-data", "experimental-data-reference"):
            path = os.path.join(directory, data_dir)
            if os.path.isdir(path):
                shutil.rmtree(path)
        return

    # Non-cascade fuzzers: clear mismatch/corpus/reference outputs
    out_dir = dut.out_directory

    # Clear mismatch output contents (keep parent dirs)
    for subdir in ("mismatch/sim_input", "mismatch/asm", "mismatch/elf", "mismatch/hex"):
        target = os.path.join(out_dir, subdir)
        if os.path.isdir(target):
            shutil.rmtree(target)
            os.makedirs(target, exist_ok=True)

    # Clear corpus
    corpus_dir = os.path.join(out_dir, "corpus")
    if os.path.isdir(corpus_dir):
        shutil.rmtree(corpus_dir)
        os.makedirs(corpus_dir, exist_ok=True)

    # Clear cov_log files
    for f in glob.glob(os.path.join(out_dir, "cov_log_*")):
        os.remove(f)

    # Clear temp working files
    for f in os.listdir(out_dir):
        if f.startswith((".input_", ".isa_sig_", ".rtl_sig_")):
            try:
                os.remove(os.path.join(out_dir, f))
            except OSError:
                pass

    # Clear reference check logs
    ref_check = os.path.join(dut.out_reference_directory, "mismatch", "check")
    if os.path.isdir(ref_check):
        shutil.rmtree(ref_check)
        os.makedirs(ref_check, exist_ok=True)

    # Clear replay check logs (pfuzz variants)
    if fuzzer_name in PFUZZ_FUZZERS and hasattr(dut, 'out_replay_directory'):
        replay_check = os.path.join(dut.out_replay_directory, "mismatch", "check")
        if os.path.isdir(replay_check):
            shutil.rmtree(replay_check)
            os.makedirs(replay_check, exist_ok=True)

    # Clear trace directory (pfuzz variants)
    trace_dir = os.path.join(out_dir, "trace")
    if os.path.isdir(trace_dir):
        shutil.rmtree(trace_dir)


def parse_check_summary(check_summary_path):
    """Parse check_summary.log and return result dict."""
    if not os.path.exists(check_summary_path):
        return {"status": "NOT_DETECTED"}

    with open(check_summary_path, 'r') as f:
        content = f.read().strip()

    if content.startswith("DETECTED"):
        result = {"status": "DETECTED"}
        # Parse "DETECTED: id_X.si TTB: 123.4"
        match = re.match(r'DETECTED:\s+(\S+)\s+TTB:\s+([\d.]+)', content)
        if match:
            result["input"] = match.group(1)
            result["ttb"] = float(match.group(2))
        else:
            # "DETECTED: id_X.si" without TTB
            match2 = re.match(r'DETECTED:\s+(\S+)', content)
            if match2:
                result["input"] = match2.group(1)
        return result
    else:
        return {"status": "NOT_DETECTED"}


def multi_run_worker(args):
    """Worker function: run N fuzz sessions for one (bug, fuzzer) pair."""
    (corpus_dir, host_name, bug_name, is_driver, fuzzer_name,
     n_runs, early_stop, results_base) = args

    # Build result directory path
    category = "driver" if is_driver else "multiplexer"
    results_dir = os.path.join(results_base, host_name, category, bug_name, fuzzer_name)
    os.makedirs(results_dir, exist_ok=True)

    # Reconstruct DUT
    try:
        host = Host(corpus_dir, host_name)
        bug = Bug(host, bug_name, is_driver)
        DUTClass = FUZZER_MAP[fuzzer_name]
        dut = DUTClass(host, bug)

        # Initialize paths — compile steps are no-ops if already done
        dut.create_dut()
        dut.compile_dut()
        dut.create_reference()
        dut.compile_reference()

        if getattr(dut, 'compile_failed', False):
            # Write a single result indicating compile failure
            result_file = os.path.join(results_dir, "run_000.json")
            if not os.path.exists(result_file):
                with open(result_file, 'w') as f:
                    json.dump({"run": 0, "status": "COMPILE_FAILED"}, f)
            return (host_name, category, bug_name, fuzzer_name, "COMPILE_FAILED")

    except Exception as e:
        err_file = os.path.join(results_dir, "error.txt")
        with open(err_file, 'w') as f:
            f.write(traceback.format_exc())
        return (host_name, category, bug_name, fuzzer_name, f"INIT_ERROR: {e}")

    # Count existing completed runs (for resume)
    consec_fails = 0
    last_completed = -1
    for run_idx in range(n_runs):
        result_file = os.path.join(results_dir, f"run_{run_idx:03d}.json")
        if os.path.exists(result_file):
            try:
                with open(result_file, 'r') as f:
                    r = json.load(f)
                last_completed = run_idx
                if r.get("status") == "DETECTED":
                    consec_fails = 0
                elif r.get("status") == "EARLY_STOP":
                    # Already early-stopped in a previous session
                    return (host_name, category, bug_name, fuzzer_name, "RESUMED_EARLY_STOP")
                else:
                    consec_fails += 1
            except (json.JSONDecodeError, KeyError):
                # Corrupt file, will be re-done
                os.remove(result_file)
                break
        else:
            break

    start_run = last_completed + 1
    if start_run > 0:
        print(f"  [{host_name}/{category}/{bug_name}/{fuzzer_name}] "
              f"Resuming from run {start_run}/{n_runs}")

    # Main multi-run loop
    for run_idx in range(start_run, n_runs):
        result_file = os.path.join(results_dir, f"run_{run_idx:03d}.json")

        # Early termination
        if consec_fails >= early_stop:
            print(f"  [{host_name}/{category}/{bug_name}/{fuzzer_name}] "
                  f"Early stop at run {run_idx} ({consec_fails} consecutive non-detections)")
            for ri in range(run_idx, n_runs):
                rf = os.path.join(results_dir, f"run_{ri:03d}.json")
                if not os.path.exists(rf):
                    with open(rf, 'w') as f:
                        json.dump({"run": ri, "status": "EARLY_STOP"}, f)
            break

        # 1. Clear outputs for fresh run
        clear_fuzz_outputs(dut, fuzzer_name)

        # 2. Fuzz (triggers fresh run since fuzz.log was deleted)
        try:
            dut.fuzz()
        except Exception as e:
            with open(result_file, 'w') as f:
                json.dump({"run": run_idx, "status": "FUZZ_ERROR", "error": str(e)}, f)
            consec_fails += 1
            continue

        # 3. Check mismatches
        try:
            dut.check_mismatch()
        except Exception as e:
            with open(result_file, 'w') as f:
                json.dump({"run": run_idx, "status": "CHECK_ERROR", "error": str(e)}, f)
            consec_fails += 1
            continue

        # 4. Parse result
        result = parse_check_summary(dut.check_summary)
        result["run"] = run_idx

        # 5. Save
        with open(result_file, 'w') as f:
            json.dump(result, f)

        # 6. Update counter
        if result["status"] == "DETECTED":
            consec_fails = 0
            print(f"  [{host_name}/{category}/{bug_name}/{fuzzer_name}] "
                  f"Run {run_idx}: DETECTED TTB={result.get('ttb', '?'):.1f}s")
        else:
            consec_fails += 1

    return (host_name, category, bug_name, fuzzer_name, "DONE")


def phase0_compile_worker(args):
    """Phase 0 worker: compile DUT and reference for one (bug, fuzzer) pair."""
    corpus_dir, host_name, bug_name, is_driver, fuzzer_name = args

    host = Host(corpus_dir, host_name)
    bug = Bug(host, bug_name, is_driver)
    bug.prepare()

    DUTClass = FUZZER_MAP[fuzzer_name]
    dut = DUTClass(host, bug)
    dut.create_dut()
    dut.compile_dut()
    dut.create_reference()
    dut.compile_reference()

    category = "driver" if is_driver else "multiplexer"
    failed = getattr(dut, 'compile_failed', False)
    return (host_name, category, bug_name, fuzzer_name, "FAILED" if failed else "OK")


def aggregate_results(results_dir, n_runs):
    """Phase 2: aggregate per-run results into summary CSV."""
    summary_rows = []

    for host_name in sorted(os.listdir(results_dir)):
        host_path = os.path.join(results_dir, host_name)
        if not os.path.isdir(host_path):
            continue
        for category in ("driver", "multiplexer"):
            cat_path = os.path.join(host_path, category)
            if not os.path.isdir(cat_path):
                continue
            for bug_name in sorted(os.listdir(cat_path), key=lambda x: int(x) if x.isdigit() else x):
                bug_path = os.path.join(cat_path, bug_name)
                if not os.path.isdir(bug_path):
                    continue
                for fuzzer_name in sorted(os.listdir(bug_path)):
                    fuzzer_path = os.path.join(bug_path, fuzzer_name)
                    if not os.path.isdir(fuzzer_path):
                        continue

                    ttb_values = []
                    detected = 0
                    total = 0
                    early_stopped = False

                    for run_file in sorted(glob.glob(os.path.join(fuzzer_path, "run_*.json"))):
                        try:
                            with open(run_file) as f:
                                r = json.load(f)
                        except (json.JSONDecodeError, IOError):
                            continue

                        status = r.get("status", "UNKNOWN")
                        if status == "EARLY_STOP":
                            early_stopped = True
                            continue
                        if status in ("COMPILE_FAILED", "FUZZ_ERROR", "CHECK_ERROR"):
                            continue

                        total += 1
                        if status == "DETECTED":
                            detected += 1
                            ttb = r.get("ttb")
                            if ttb is not None:
                                ttb_values.append(ttb)

                    if total == 0:
                        continue

                    det_rate = detected / total
                    row = {
                        "host": host_name,
                        "bug_type": category,
                        "bug_id": bug_name,
                        "fuzzer": fuzzer_name,
                        "total_runs": total,
                        "detections": detected,
                        "detection_rate": f"{det_rate:.3f}",
                        "early_stopped": early_stopped,
                    }

                    if ttb_values:
                        row["mean_ttb"] = f"{statistics.mean(ttb_values):.1f}"
                        row["median_ttb"] = f"{statistics.median(ttb_values):.1f}"
                        row["min_ttb"] = f"{min(ttb_values):.1f}"
                        row["max_ttb"] = f"{max(ttb_values):.1f}"
                        if len(ttb_values) >= 2:
                            row["std_ttb"] = f"{statistics.stdev(ttb_values):.1f}"
                        else:
                            row["std_ttb"] = "N/A"
                    else:
                        for k in ("mean_ttb", "median_ttb", "min_ttb", "max_ttb", "std_ttb"):
                            row[k] = "N/A"

                    summary_rows.append(row)

    # Write CSV
    if not summary_rows:
        print("No results to aggregate.")
        return

    csv_path = os.path.join(results_dir, "ttb_summary.csv")
    fields = ["host", "bug_type", "bug_id", "fuzzer", "total_runs", "detections",
              "detection_rate", "mean_ttb", "median_ttb", "std_ttb", "min_ttb",
              "max_ttb", "early_stopped"]
    with open(csv_path, 'w') as f:
        f.write(",".join(fields) + "\n")
        for row in summary_rows:
            f.write(",".join(str(row.get(k, "")) for k in fields) + "\n")
    print(f"Summary written to {csv_path} ({len(summary_rows)} rows)")

    # Per-fuzzer aggregate
    fuzzer_stats = {}
    for row in summary_rows:
        fz = row["fuzzer"]
        if fz not in fuzzer_stats:
            fuzzer_stats[fz] = {"total_bugs": 0, "detected_bugs": 0,
                                "det_rates": [], "median_ttbs": []}
        fuzzer_stats[fz]["total_bugs"] += 1
        det_rate = float(row["detection_rate"])
        fuzzer_stats[fz]["det_rates"].append(det_rate)
        if det_rate > 0:
            fuzzer_stats[fz]["detected_bugs"] += 1
        if row["median_ttb"] != "N/A":
            fuzzer_stats[fz]["median_ttbs"].append(float(row["median_ttb"]))

    fuzzer_csv = os.path.join(results_dir, "ttb_by_fuzzer.csv")
    with open(fuzzer_csv, 'w') as f:
        f.write("fuzzer,total_bugs,detected_bugs,mean_detection_rate,mean_median_ttb\n")
        for fz in sorted(fuzzer_stats):
            s = fuzzer_stats[fz]
            mean_dr = statistics.mean(s["det_rates"]) if s["det_rates"] else 0
            mean_mttb = statistics.mean(s["median_ttbs"]) if s["median_ttbs"] else 0
            f.write(f"{fz},{s['total_bugs']},{s['detected_bugs']},"
                    f"{mean_dr:.3f},{mean_mttb:.1f}\n")
    print(f"Per-fuzzer summary written to {fuzzer_csv}")


def main():
    parser = argparse.ArgumentParser(description="Multi-Run TTB Experiment")
    parser.add_argument("-d", "--directory", type=str, required=True,
                        help="EnCorpus working directory")
    parser.add_argument("-H", "--hosts", type=str, nargs='+', required=True,
                        help="Hardware targets (e.g., rocket boom)")
    parser.add_argument("-p", "--processes", type=int, default=15,
                        help="Number of parallel workers")
    parser.add_argument("-N", "--n-runs", type=int, default=100,
                        help="Number of runs per (bug, fuzzer) pair")
    parser.add_argument("--early-stop", type=int, default=10,
                        help="Stop after K consecutive non-detections")
    parser.add_argument("--results-dir", type=str, default="out/ttb_results",
                        help="Directory for TTB results")
    parser.add_argument("--fuzzers", type=str, nargs='+', required=True,
                        help="Fuzzers to run")
    parser.add_argument("-D", "--driver-bugs", type=str, nargs='+',
                        help="Specific driver bug IDs to run")
    parser.add_argument("-M", "--mux-bugs", type=str, nargs='+',
                        help="Specific multiplexer bug IDs to run")
    parser.add_argument("--aggregate-only", action="store_true",
                        help="Only aggregate existing results, don't run")
    parser.add_argument("--phase0-only", action="store_true",
                        help="Only compile, don't fuzz")
    parser.add_argument("--skip-phase0", action="store_true",
                        help="Skip compilation phase")
    args = parser.parse_args()

    corpus_dir = os.path.abspath(args.directory)
    results_dir = os.path.abspath(args.results_dir)
    os.makedirs(results_dir, exist_ok=True)

    # Validate fuzzers
    for fz in args.fuzzers:
        if fz not in FUZZER_MAP:
            print(f"Error: Unknown fuzzer '{fz}'. Available: {list(FUZZER_MAP.keys())}")
            sys.exit(1)

    # Aggregate-only mode
    if args.aggregate_only:
        aggregate_results(results_dir, args.n_runs)
        return

    # Enumerate bugs
    all_pairs = []
    for host_name in args.hosts:
        host = Host(corpus_dir, host_name)

        # Driver bugs
        driver_dir = host.driver_directory
        if os.path.isdir(driver_dir):
            driver_bugs = sorted([d for d in os.listdir(driver_dir)
                                  if os.path.isdir(os.path.join(driver_dir, d))],
                                 key=lambda x: int(x) if x.isdigit() else x)
            if args.driver_bugs:
                driver_bugs = [b for b in driver_bugs if b in args.driver_bugs]
            for bug_name in driver_bugs:
                for fz in args.fuzzers:
                    all_pairs.append((corpus_dir, host_name, bug_name, True, fz))

        # Multiplexer bugs
        mux_dir = host.mux_directory
        if os.path.isdir(mux_dir):
            mux_bugs = sorted([d for d in os.listdir(mux_dir)
                               if os.path.isdir(os.path.join(mux_dir, d))],
                              key=lambda x: int(x) if x.isdigit() else x)
            if args.mux_bugs:
                mux_bugs = [b for b in mux_bugs if b in args.mux_bugs]
            for bug_name in mux_bugs:
                for fz in args.fuzzers:
                    all_pairs.append((corpus_dir, host_name, bug_name, False, fz))

    print(f"Total (bug, fuzzer) pairs: {len(all_pairs)}")
    print(f"Runs per pair: {args.n_runs}")
    print(f"Early stop after: {args.early_stop} consecutive non-detections")
    print(f"Parallel workers: {args.processes}")
    print(f"Results dir: {results_dir}")

    # Phase 0: Compile
    if not args.skip_phase0:
        print("\n=== Phase 0: Compiling DUTs and references ===")
        with multiprocessing.Pool(processes=args.processes) as pool:
            compile_results = pool.map(phase0_compile_worker, all_pairs)
        failed = sum(1 for r in compile_results if r[4] == "FAILED")
        print(f"Compilation done: {len(compile_results) - failed} OK, {failed} failed")

        if args.phase0_only:
            print("Phase 0 complete (--phase0-only). Exiting.")
            return

    # Phase 1: Multi-run fuzzing
    print(f"\n=== Phase 1: Multi-run TTB ({args.n_runs} runs per pair) ===")
    worker_args = [
        (corpus_dir, host_name, bug_name, is_driver, fz,
         args.n_runs, args.early_stop, results_dir)
        for (corpus_dir, host_name, bug_name, is_driver, fz) in all_pairs
    ]

    with multiprocessing.Pool(processes=args.processes) as pool:
        results = pool.map(multi_run_worker, worker_args)

    done = sum(1 for r in results if r[4] == "DONE")
    early = sum(1 for r in results if r[4] == "RESUMED_EARLY_STOP")
    errors = sum(1 for r in results if "ERROR" in str(r[4]))
    print(f"\nPhase 1 complete: {done} done, {early} early-stopped, {errors} errors")

    # Phase 2: Aggregate
    print("\n=== Phase 2: Aggregating results ===")
    aggregate_results(results_dir, args.n_runs)


if __name__ == "__main__":
    main()
