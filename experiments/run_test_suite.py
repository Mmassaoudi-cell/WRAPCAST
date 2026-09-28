"""Held-out evaluation.  Must only be run after FINAL_MODEL_CONFIG.yaml is frozen.

Groups
  main      TEST main scenarios x TEST seeds, all benchmarks + PROPOSED
  robust    robustness scenarios x ROBUST seeds, key benchmarks + PROPOSED
  scaling   scaling scenarios x ROBUST seeds, key benchmarks + PROPOSED
  ablation  PROPOSED and its ablations on three TEST scenarios x first 5 TEST seeds
Protocols are interleaved in a seeded random order inside every (scenario, seed) cell so that
background machine load affects all methods alike.  Results are appended row by row to
results/test/<group>.csv and the script resumes where it stopped.
"""
import argparse
import os
import random
import sys
import zlib
from dataclasses import replace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pandas as pd

from otasim import scenarios as S
from otasim.experiment import run_cell
from otasim.protocols import BENCHMARKS, ablation_factory, final_config, proposed_factory

OUT = os.path.join(os.path.dirname(__file__), "..", "results", "test")
KEY = ["B01_SOURCE_REPRO", "B06_TLS13_CLASSIC", "B07_TLS13_PQHYBRID", "B09_UPTANE_PQ", "B10_KEMTLS"]
ABLATIONS = ["PROPOSED", "ABL_per_vehicle_content", "ABL_no_batch", "ABL_digest_only", "ABL_pure_mlkem",
             "ABL_online_manifest", "ABL_no_report", "PM_level5", "SENS_director_mldsa44"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("group", choices=["main", "robust", "scaling", "ablation"])
    ap.add_argument("--only", nargs="*", default=None, help="restrict to these scenario ids")
    a = ap.parse_args()
    cfg = final_config()
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, f"{a.group}.csv")
    done = set()
    if os.path.exists(path):
        d = pd.read_csv(path)
        done = set(zip(d.protocol, d.sid, d.seed))
    if a.group == "main":
        scs, seeds, protos = S.test_main(), S.TEST_SEEDS, BENCHMARKS + ["PROPOSED"]
    elif a.group == "robust":
        scs, seeds, protos = S.test_robustness(), S.ROBUST_SEEDS, KEY + ["PROPOSED"]
    elif a.group == "scaling":
        scs, seeds, protos = S.test_scaling(), S.ROBUST_SEEDS, KEY + ["PROPOSED"]
    else:
        keep = {"T2_wifi_N60_16M", "T3_wifiMC_N60_16M", "T4_lte_N200_16M"}
        scs, seeds, protos = [s for s in S.test_main() if s.sid in keep], S.TEST_SEEDS[:5], ABLATIONS
    if a.only:
        scs = [s for s in scs if s.sid in set(a.only)]
    for sc in scs:
        for seed in seeds:
            order = protos[:]
            random.Random(seed * 1009 + zlib.crc32(sc.sid.encode())).shuffle(order)
            for p in order:
                if (p, sc.sid, seed) in done:
                    continue
                scs_ = replace(S.with_seed(sc, seed), mc_rate=cfg["delivery"]["multicast_rate_mbps"],
                               batch_window=cfg["authorization"]["batch_window_s"],
                               batch_max=cfg["authorization"]["batch_max"])
                if p == "PROPOSED":
                    fac = proposed_factory(cfg)
                elif p.startswith(("ABL_", "PM_", "SENS_")):
                    fac = ablation_factory(cfg, p)
                else:
                    fac = None
                row = run_cell(p, scs_, proto_factory=fac)
                row["group"] = a.group
                pd.DataFrame([row]).to_csv(path, mode="a", header=not os.path.exists(path), index=False)
                print(a.group, sc.sid, seed, p, f"makespan={row['makespan']:.3f}", f"srv={row['server_cpu_per_vehicle_ms']:.2f}ms",
                      f"wall={row['wall_s']:.1f}s", flush=True)


if __name__ == "__main__":
    main()
