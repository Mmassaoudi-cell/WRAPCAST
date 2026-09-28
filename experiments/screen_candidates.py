"""Stages 1-2 of candidate screening on DEV scenarios only (never TEST).

Stage 1: seed 0, all candidates, all DEV scenarios (+ security conformance suite).
Stage 2: DEV seeds {0,1,2}.
Output: results/selection/screening.csv, results/selection/candidate_security.csv
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pandas as pd
from otasim import attacks as A
from otasim.experiment import run_cell
from otasim.protocols import CANDIDATES
from otasim.scenarios import DEV_SEEDS, dev_scenarios, with_seed

OUT = os.path.join(os.path.dirname(__file__), "..", "results", "selection")
os.makedirs(OUT, exist_ok=True)
rows = []
for seed in DEV_SEEDS:
    for sc in dev_scenarios():
        for c in CANDIDATES:  # interleaved: every candidate sees the same machine load per scenario/seed
            r = run_cell(c, with_seed(sc, seed))
            r["stage"] = 1 if seed == 0 else 2
            rows.append(r)
            print(seed, sc.sid, c, f"makespan={r['makespan']:.2f} lat={r['lat_mean']:.2f} srv={r['server_cpu_per_vehicle_ms']:.2f}ms", flush=True)
    pd.DataFrame(rows).to_csv(os.path.join(OUT, "screening.csv"), index=False)
sec = [A.run_test(c, t, s) for c in CANDIDATES for t in A.TESTS for s in range(5)]
pd.DataFrame(sec).to_csv(os.path.join(OUT, "candidate_security.csv"), index=False)
print("done")
