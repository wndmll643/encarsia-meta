"""Deterministic subset selector for the bugs-found experiment.

After `encarsia.py -Y` runs Yosys formal verification, surviving bugs have a
`yosys_proof.S` file in their directory. This script lists those survivors
under {host}/{driver,multiplexer}/ and writes a deterministic subset of bug
IDs to selected_driver_bugs.txt and selected_mux_bugs.txt — to be passed to
multi_run_ttb.py via -D / -M so all fuzzers see the same bugs.

Usage:
    python select_bug_subset.py -d out/LargeCorpus -H rocket boom -n 250
"""

import argparse
import os
import random


def list_survivors(corpus_dir, host, category):
    cat_dir = os.path.join(corpus_dir, host, category)
    if not os.path.isdir(cat_dir):
        return []
    survivors = []
    for bug_id in os.listdir(cat_dir):
        bug_path = os.path.join(cat_dir, bug_id)
        if not os.path.isdir(bug_path):
            continue
        if os.path.exists(os.path.join(bug_path, "yosys_proof.S")):
            survivors.append(bug_id)
    return sorted(survivors, key=lambda x: int(x) if x.isdigit() else x)


def pick_subset(survivors, k, seed):
    if len(survivors) <= k:
        return list(survivors)
    return sorted(random.Random(seed).sample(survivors, k),
                  key=lambda x: int(x) if x.isdigit() else x)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", required=True,
                        help="Corpus directory (e.g. out/LargeCorpus)")
    parser.add_argument("-H", "--hosts", nargs='+', required=True,
                        help="Hosts (e.g. rocket boom)")
    parser.add_argument("-n", "--total", type=int, default=250,
                        help="Total bugs to select per host (split 50/50 driver/mux)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for deterministic sampling")
    args = parser.parse_args()

    corpus_dir = os.path.abspath(args.directory)
    half = args.total // 2

    for host in args.hosts:
        drivers = list_survivors(corpus_dir, host, "driver")
        muxes = list_survivors(corpus_dir, host, "multiplexer")

        sel_drv = pick_subset(drivers, half, args.seed)
        sel_mux = pick_subset(muxes, args.total - half, args.seed + 1)

        host_dir = os.path.join(corpus_dir, host)
        with open(os.path.join(host_dir, "selected_driver_bugs.txt"), 'w') as f:
            f.write("\n".join(sel_drv) + "\n")
        with open(os.path.join(host_dir, "selected_mux_bugs.txt"), 'w') as f:
            f.write("\n".join(sel_mux) + "\n")

        print(f"{host}: survivors driver={len(drivers)} mux={len(muxes)} "
              f"-> selected driver={len(sel_drv)} mux={len(sel_mux)}")


if __name__ == "__main__":
    main()
