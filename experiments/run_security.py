"""Security conformance suite on all benchmarks, the frozen final model and its ablations (20 seeds)."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pandas as pd
from otasim import attacks as A
from otasim.protocols import BENCHMARKS, CANDIDATES, ablation_factory, final_config, proposed_factory

cfg = final_config()
facs = {b: None for b in BENCHMARKS}
facs["PROPOSED"] = proposed_factory(cfg)
for a in ["ABL_per_vehicle_content", "ABL_no_batch", "ABL_digest_only", "ABL_pure_mlkem", "ABL_online_manifest",
          "ABL_no_report", "PM_level5", "SENS_director_mldsa44"]:
    facs[a] = ablation_factory(cfg, a)
rows = []
for name, fac in facs.items():
    for t in A.TESTS:
        for s in range(20):
            r = A.run_test(name, t, 1000 + s, factory=fac)
            rows.append(r)
    print(name, "done", flush=True)
out = os.path.join(os.path.dirname(__file__), "..", "results", "security")
os.makedirs(out, exist_ok=True)
df = pd.DataFrame(rows)
df.to_csv(os.path.join(out, "security_raw.csv"), index=False)
df["bad"] = df.apply(lambda r: bool(r["false_reject"]) if r["test"] == "benign" else bool(r["violation"]), axis=1)
m = df.pivot_table(index="protocol", columns="test", values="bad", aggfunc="mean")[A.TESTS]
m.to_csv(os.path.join(out, "security_matrix.csv"))
print(m.to_string())
