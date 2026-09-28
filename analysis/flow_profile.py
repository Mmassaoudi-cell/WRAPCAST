"""Per-flight message profile of one real session per protocol (16 MB package, 5 repetitions).
Output: results/test/flow_profile.csv (protocol, rep, order, src, label, bytes, cpu_ms, bulk)."""
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pandas as pd

from otasim import prims
from otasim.common import make_package
from otasim.protocols import BENCHMARKS, build, final_config, proposed_factory

prims.pin_measurement_core()
cfg = final_config()
rows = []
for name in BENCHMARKS + ["PROPOSED"]:
    p = proposed_factory(cfg)() if name == "PROPOSED" else build(name)
    p.setup(8)
    pkg = make_package(16 << 20, 2)
    p.release(pkg)
    vids = p.vids()
    for v in vids[:3]:
        p.session(v, pkg, rng=random.Random(0))
    for rep, v in enumerate(vids[3:8]):
        tr = p.session(v, pkg, rng=random.Random(rep))
        assert tr.accepted and tr.installed_ok
        for k, f in enumerate(tr.flights):
            rows.append(dict(protocol=name, short=p.short, rep=rep, order=k, src=f.src, label=f.label, bytes=f.nbytes,
                             cpu_ms=1e3 * f.cpu, bulk=f.bulk, release_cpu_ms=1e3 * p.release_cpu,
                             final_vehicle_cpu_ms=1e3 * tr.final_vehicle_cpu))
    print(name, flush=True)
out = os.path.join(os.path.dirname(__file__), "..", "results", "test")
pd.DataFrame(rows).to_csv(os.path.join(out, "flow_profile.csv"), index=False)
