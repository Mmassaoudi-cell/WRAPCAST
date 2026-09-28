"""Stage 3 confirmation on DEV seed 2 (not used by the tuner) for the tied top configurations."""
import os, sys
from dataclasses import replace
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pandas as pd
from otasim.experiment import run_cell
from otasim.protocols import WrapOnceOTA
from otasim.scenarios import dev_scenarios, with_seed
CFGS = {
  "C4_t17": dict(chunk=16384, dir_sig="Falcon-512", batch=16, window=0.01),
  "C4_t1": dict(chunk=262144, dir_sig="Falcon-512", batch=64, window=0.01),
  "C3_t13": dict(chunk=262144, dir_sig="Falcon-512", batch=None, window=0.05),
  "C3_t11": dict(chunk=262144, dir_sig="Falcon-512", batch=None, window=0.05),
}
rows = []
for sc in dev_scenarios():
    for name, c in CFGS.items():
        fac = lambda c=c: WrapOnceOTA("X-Wing", c["dir_sig"], "ML-DSA-65", c["chunk"], c["batch"], False, short=name)
        s = replace(with_seed(sc, 2), mc_rate=6.0, batch_window=c["window"], batch_max=c["batch"] or 64)
        r = run_cell(name, s, proto_factory=fac); r["config"] = name; rows.append(r)
        print(sc.sid, name, round(r["makespan"], 3), round(r["server_cpu_per_vehicle_ms"], 3), r["success_rate"], flush=True)
pd.DataFrame(rows).to_csv(os.path.join(os.path.dirname(__file__), "..", "results", "selection", "confirmation_seed2.csv"), index=False)
