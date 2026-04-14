"""Pivot ttb_summary.csv into a per-fuzzer "bugs found" Markdown table.

Reads multi_run_ttb.py's ttb_summary.csv (one row per (host, bug, fuzzer) with
detection_rate). A bug counts as DETECTED for a fuzzer if detection_rate > 0
in any of its N runs — same rule as aggregate_results() at multi_run_ttb.py:392.

Usage:
    python pivot_bugs_found.py --results-dir out/large_bugs_results \\
        --out out/large_bugs_results/bugs_found.md
"""

import argparse
import csv
import os
from collections import defaultdict


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--out", default=None,
                        help="Output Markdown path (default: <results-dir>/bugs_found.md)")
    args = parser.parse_args()

    csv_path = os.path.join(args.results_dir, "ttb_summary.csv")
    if not os.path.exists(csv_path):
        raise SystemExit(f"Missing {csv_path}; run multi_run_ttb.py --aggregate-only first.")

    out_path = args.out or os.path.join(args.results_dir, "bugs_found.md")

    # (fuzzer, host) -> [total_bugs, detected_bugs]
    table = defaultdict(lambda: [0, 0])
    hosts = set()
    fuzzers = set()

    with open(csv_path) as f:
        for row in csv.DictReader(f):
            host = row["host"]
            fuzzer = row["fuzzer"]
            hosts.add(host)
            fuzzers.add(fuzzer)
            table[(fuzzer, host)][0] += 1
            if float(row["detection_rate"]) > 0:
                table[(fuzzer, host)][1] += 1

    hosts = sorted(hosts)
    fuzzers = sorted(fuzzers)

    with open(out_path, 'w') as f:
        header = ["Fuzzer"] + [f"{h} detected / total" for h in hosts] + ["Combined %"]
        f.write("| " + " | ".join(header) + " |\n")
        f.write("|" + "|".join(["---"] * len(header)) + "|\n")
        for fuzzer in fuzzers:
            cells = [fuzzer]
            tot_d, tot_t = 0, 0
            for host in hosts:
                t, d = table[(fuzzer, host)]
                cells.append(f"{d} / {t}")
                tot_t += t
                tot_d += d
            pct = (100.0 * tot_d / tot_t) if tot_t else 0.0
            cells.append(f"{pct:.1f}%")
            f.write("| " + " | ".join(cells) + " |\n")

    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
