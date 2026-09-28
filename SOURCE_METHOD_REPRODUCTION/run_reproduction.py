"""Reproduce Kumar et al. (IEEE TII 2026), Figs. 3-8 and Table III.

Setting (Sec. V-A of the source): IEEE 802.11g, 2.4 GHz, 54 Mbps, vehicles moving at 5-10 m/s
(random direction), Tx power 1 dBm, log-distance propagation, TCP; N = 20..100 vehicles;
4096-B AES-GCM chunks.  Package size is not reported; the published decryption times are
only consistent with a few-KB file, so the primary reproduction uses a 4 KB package; a 1 MB
package is reported as a sensitivity case.

Outputs: results/reproduction/per_session.csv, per_run.csv, registration.csv
Usage:   python SOURCE_METHOD_REPRODUCTION/run_reproduction.py [--seeds 10]
"""
from __future__ import annotations

import argparse
import os
import random
import sys

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from otasim import prims  # noqa: E402
from otasim.common import make_package  # noqa: E402
from otasim.netsim import Scenario, simulate  # noqa: E402
from otasim.protocols import build  # noqa: E402

PROTOS = ["B01_SOURCE_REPRO", "B02_SRC_DH2048", "B03_SRC_RSA2048", "B04_SRC_McE_SPHINCS"]
HS_S = ("cookie", "kem_pk_sig", "latest_version")
HS_V = ("update_request", "cookie_echo", "kem_ct")
OUT = os.path.join(os.path.dirname(__file__), "..", "results", "reproduction")


def one_run(proto, n, seed, size, warm=3):
    p = build(proto)
    p.setup(n + warm)
    pkg = make_package(size, 2)
    p.release(pkg)
    rng = random.Random(seed)
    vids = p.vids()
    for v in vids[:warm]:
        p.session(v, pkg, rng=rng)
    traces = [p.session(v, pkg, rng=rng) for v in vids[warm:]]
    assert all(t.accepted and t.installed_ok for t in traces)
    sc = Scenario(sid=f"repro_N{n}", channel="wifi", n_vehicles=n, pkg_size=size, seed=seed, split="reproduction")
    vres, fleet = simulate(sc, traces)
    sess = []
    for i, (t, r) in enumerate(zip(traces, vres)):
        c = {f.label: f.cpu for f in t.flights}
        tm = dict(r.times)
        sess.append(dict(
            protocol=proto, n=n, seed=seed, pkg_size=size, vehicle=i,
            server_handshake_s=sum(c[k] for k in HS_S),
            client_handshake_s=sum(c[k] for k in HS_V),
            handshake_cpu_s=sum(c[k] for k in HS_S + HS_V),
            server_zkp_s=c["zkp_challenge"] + t.notes["zkp_server_cpu"],
            client_zkp_s=c["zkp_response"],
            zkp_latency_s=tm["zkp_response"] - tm["get_latest"],  # challenge -> verified response
            server_encryption_s=t.notes["bulk_server_cpu"],
            client_decryption_s=t.final_vehicle_cpu,
            transfer_s=tm["package"] - tm["zkp_response"],
            handshake_latency_s=tm["latest_version"] - r.t_start,
            total_cpu_s=t.cpu_by("S") + t.cpu_by("V") + t.final_vehicle_cpu,
            e2e_latency_s=r.t_done - r.t_start,
            wire_bytes=sum(f.nbytes for f in t.flights),
        ))
    reg = [dict(protocol=proto, n=n, seed=seed, **x) for x in p.reg_times[warm:]]
    run = dict(protocol=proto, n=n, seed=seed, pkg_size=size, **fleet)
    return sess, run, reg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=10)
    a = ap.parse_args()
    prims.pin_measurement_core()
    os.makedirs(OUT, exist_ok=True)
    S, R, G = [], [], []
    for size in (4096, 1 << 20):
        for proto in PROTOS:
            for n in (20, 40, 60, 80, 100):
                seeds = range(a.seeds) if size == 4096 else range(3)
                for seed in seeds:
                    s, r, g = one_run(proto, n, seed, size)
                    S += s
                    R.append(r)
                    G += g
                print(size, proto, n, "done", flush=True)
    pd.DataFrame(S).to_csv(os.path.join(OUT, "per_session.csv"), index=False)
    pd.DataFrame(R).to_csv(os.path.join(OUT, "per_run.csv"), index=False)
    pd.DataFrame(G).to_csv(os.path.join(OUT, "registration.csv"), index=False)


if __name__ == "__main__":
    main()
