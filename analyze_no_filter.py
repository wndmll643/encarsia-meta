"""Retroactive no-filter detection analysis.

For each bug/fuzzer, checks if out/mismatch/sim_input/ has ANY files.
If yes, the bug would be DETECTED without the false-positive filter.
Compares against the filtered result in check_summary.log to quantify
how many real detections are lost to the filter.

Usage:
    python analyze_no_filter.py -d out/EnCorpus
"""

import argparse
import os


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

                    filtered_detected = "NOT DETECTED" not in content

                    # Check raw mismatch count
                    mismatch_dir = os.path.join(fuzzer_dir, "out", "mismatch", "sim_input")
                    if os.path.isdir(mismatch_dir):
                        mismatch_count = len(os.listdir(mismatch_dir))
                    else:
                        mismatch_count = 0

                    no_filter_detected = mismatch_count > 0

                    # For cascade: detection is in fuzz.log, no mismatch dir
                    if fuzzer_name == "cascade":
                        no_filter_detected = filtered_detected  # same (no filter exists)
                        mismatch_count = -1  # N/A

                    results.append((host_name, bug_type, bug_id, fuzzer_name,
                                    filtered_detected, no_filter_detected, mismatch_count))

    return results


def print_results(results):
    """Print comparison table."""
    if not results:
        print("No data found.")
        return

    # Summary by fuzzer
    fuzzer_stats = {}
    for host, btype, bug_id, fuzzer, filtered, no_filter, mcount in results:
        key = (host, fuzzer)
        if key not in fuzzer_stats:
            fuzzer_stats[key] = {"total": 0, "filtered": 0, "no_filter": 0, "lost": 0}
        fuzzer_stats[key]["total"] += 1
        if filtered:
            fuzzer_stats[key]["filtered"] += 1
        if no_filter:
            fuzzer_stats[key]["no_filter"] += 1
        if no_filter and not filtered:
            fuzzer_stats[key]["lost"] += 1

    print(f"\n{'Host':<8} {'Fuzzer':<30} {'Total':>6} {'Filtered':>10} {'No-filter':>11} {'Lost':>6}")
    print("-" * 75)
    for (host, fuzzer) in sorted(fuzzer_stats.keys()):
        s = fuzzer_stats[(host, fuzzer)]
        nf_str = f"{s['no_filter']}/{s['total']}" if fuzzer != "cascade" else "N/A"
        print(f"{host:<8} {fuzzer:<30} {s['total']:>6} {s['filtered']:>5}/{s['total']:<4} {nf_str:>11} {s['lost']:>6}")

    # Per-bug details for bugs where filter removed detection
    lost_bugs = [(h, bt, bid, f, mc) for h, bt, bid, f, filt, nf, mc in results
                 if nf and not filt]
    if lost_bugs:
        print(f"\n\nBugs detected without filter but lost to filter:")
        print(f"{'Host':<8} {'Type':<12} {'Bug':<6} {'Fuzzer':<30} {'Mismatches':>10}")
        print("-" * 70)
        for host, btype, bug_id, fuzzer, mcount in lost_bugs:
            print(f"{host:<8} {btype:<12} {bug_id:<6} {fuzzer:<30} {mcount:>10}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="No-filter detection analysis")
    parser.add_argument("-d", "--directory", type=str, default="out/EnCorpus",
                        help="EnCorpus output directory")
    args = parser.parse_args()

    results = analyze_directory(args.directory)
    print_results(results)
