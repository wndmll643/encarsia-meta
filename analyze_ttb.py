"""Retroactive TTB (Time to Bug) analysis from filesystem metadata.

Walks the EnCorpus output directory and computes TTB for each detected bug
using file modification times. Works on existing experiment data without
re-running any fuzzer.

Usage:
    python analyze_ttb.py -d out/EnCorpus
"""

import argparse
import os
import re
import statistics


def get_fuzz_start_time(fuzzer_dir, fuzzer_name):
    """Get fuzzing start time from filesystem metadata."""
    # For fuzzers that write fuzz.log before fuzzing (difuzzrtl, processorfuzz):
    # fuzz.log creation time = fuzz start
    fuzz_log = os.path.join(fuzzer_dir, "fuzz.log")

    # For hierfuzz variants that create fuzz.log as empty sentinel AFTER fuzzing:
    # use fuzz_start.timestamp if present, else fall back to out/ directory mtime
    ts_path = os.path.join(fuzzer_dir, "fuzz_start.timestamp")
    if os.path.exists(ts_path):
        with open(ts_path, 'r') as f:
            return float(f.read().strip())

    if os.path.exists(fuzz_log):
        stat = os.stat(fuzz_log)
        fsize = stat.st_size
        # If fuzz.log is non-empty, it was written during fuzzing (difuzzrtl/processorfuzz style)
        # Use its mtime as start time approximation (file opened before Popen)
        if fsize > 0:
            return stat.st_mtime
        # Empty fuzz.log = hierfuzz sentinel, not useful for start time
        # Fall back to out/ directory creation
        out_dir = os.path.join(fuzzer_dir, "out")
        if os.path.isdir(out_dir):
            return os.stat(out_dir).st_mtime

    return None


def get_cascade_ttb(fuzzer_dir):
    """Parse cascade fuzz.log for first 'Failed' relative timestamp."""
    fuzz_log = os.path.join(fuzzer_dir, "fuzz.log")
    if not os.path.exists(fuzz_log):
        return None
    with open(fuzz_log, 'r') as f:
        for line in f:
            if "Failed" in line:
                # Try to parse relative timestamp like "0:00:00.920371"
                m = re.search(r'(\d+):(\d+):(\d+(?:\.\d+)?)', line)
                if m:
                    h, mi, s = float(m.group(1)), float(m.group(2)), float(m.group(3))
                    return h * 3600 + mi * 60 + s
                # If no timestamp pattern, can't determine TTB
                return None
    return None


def analyze_directory(base_dir):
    """Analyze all fuzzer results under the EnCorpus directory."""
    results = []

    for host_name in sorted(os.listdir(base_dir)):
        host_dir = os.path.join(base_dir, host_name)
        if not os.path.isdir(host_dir):
            continue

        for bug_type in ["driver", "multiplexer"]:
            type_dir = os.path.join(host_dir, bug_type)
            if not os.path.isdir(type_dir):
                continue

            for bug_id in sorted(os.listdir(type_dir), key=lambda x: int(x) if x.isdigit() else 0):
                bug_dir = os.path.join(type_dir, bug_id)
                if not os.path.isdir(bug_dir):
                    continue

                for fuzzer_name in sorted(os.listdir(bug_dir)):
                    fuzzer_dir = os.path.join(bug_dir, fuzzer_name)
                    if not os.path.isdir(fuzzer_dir):
                        continue

                    check_summary = os.path.join(fuzzer_dir, "check_summary.log")
                    if not os.path.exists(check_summary):
                        continue

                    with open(check_summary, 'r') as f:
                        content = f.read().strip()

                    if "NOT DETECTED" in content:
                        continue

                    # Check for baked-in TTB first
                    m = re.search(r"TTB:\s+([\d.]+)", content)
                    if m:
                        ttb = float(m.group(1))
                        results.append((host_name, bug_type, bug_id, fuzzer_name, ttb))
                        continue

                    # Cascade: parse fuzz.log for timestamps
                    if fuzzer_name == "cascade":
                        ttb = get_cascade_ttb(fuzzer_dir)
                        if ttb is not None:
                            results.append((host_name, bug_type, bug_id, fuzzer_name, ttb))
                        continue

                    # Other fuzzers: use filesystem metadata
                    # Parse mismatch filename from check_summary
                    m_file = re.search(r"DETECTED:\s+(\S+)", content)
                    if not m_file:
                        continue
                    mismatch_file = m_file.group(1)

                    mismatch_path = os.path.join(fuzzer_dir, "out", "mismatch", "sim_input", mismatch_file)
                    if not os.path.exists(mismatch_path):
                        continue

                    start_time = get_fuzz_start_time(fuzzer_dir, fuzzer_name)
                    if start_time is None:
                        continue

                    mismatch_mtime = os.path.getmtime(mismatch_path)
                    ttb = mismatch_mtime - start_time
                    if ttb < 0:
                        continue  # Clock skew or reused directory

                    results.append((host_name, bug_type, bug_id, fuzzer_name, ttb))

    return results


def print_results(results):
    """Print TTB results as a table."""
    if not results:
        print("No TTB data found.")
        return

    # Per-bug table
    print(f"\n{'Host':<8} {'Type':<12} {'Bug':<6} {'Fuzzer':<30} {'TTB (s)':>10}")
    print("-" * 70)
    for host, btype, bug_id, fuzzer, ttb in results:
        print(f"{host:<8} {btype:<12} {bug_id:<6} {fuzzer:<30} {ttb:>10.1f}")

    # Summary by fuzzer
    fuzzer_ttbs = {}
    for host, btype, bug_id, fuzzer, ttb in results:
        key = fuzzer
        if key not in fuzzer_ttbs:
            fuzzer_ttbs[key] = []
        fuzzer_ttbs[key].append(ttb)

    print(f"\n{'Fuzzer':<30} {'Count':>6} {'Mean (s)':>10} {'Median (s)':>12} {'Min (s)':>10} {'Max (s)':>10}")
    print("-" * 80)
    for fuzzer in sorted(fuzzer_ttbs.keys()):
        vals = fuzzer_ttbs[fuzzer]
        mean = statistics.mean(vals)
        median = statistics.median(vals)
        print(f"{fuzzer:<30} {len(vals):>6} {mean:>10.1f} {median:>12.1f} {min(vals):>10.1f} {max(vals):>10.1f}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Retroactive TTB analysis")
    parser.add_argument("-d", "--directory", type=str, default="out/EnCorpus",
                        help="EnCorpus output directory")
    args = parser.parse_args()

    results = analyze_directory(args.directory)
    print_results(results)
