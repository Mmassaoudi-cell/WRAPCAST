"""Run one (protocol, scenario) cell: real protocol execution -> trace-driven network simulation."""
from __future__ import annotations

import random
import statistics
import time

import numpy as np

from . import prims
from .common import make_package
from .netsim import Scenario, simulate
from .protocols import build

WARMUP = 3


def run_cell(proto_name: str, sc: Scenario, k_real: int = 5, multicast_ok: bool | None = None,
             proto_factory=None) -> dict:
    prims.pin_measurement_core()
    t_wall = time.perf_counter()
    p = proto_factory() if proto_factory else build(proto_name)
    t0 = time.perf_counter()
    p.setup(sc.n_vehicles + WARMUP)
    setup_s = time.perf_counter() - t0
    pkg = make_package(sc.pkg_size, version=2)
    p.release(pkg)
    rng = random.Random(sc.seed)
    vids = p.vids()
    for v in vids[:WARMUP]:  # warm caches / allocators; discarded
        p.session(v, pkg, rng=rng)
    traces = []
    for j, v in enumerate(vids[WARMUP:]):
        real = j < k_real or not p.has_bulk_samples(pkg, k_real)
        tr = p.session(v, pkg, rng=rng, bulk_real=real)
        if not (tr.accepted and tr.installed_ok):
            raise RuntimeError(f"{proto_name}: honest session failed: {tr.reason}")
        traces.append(tr)
    if multicast_ok is None:
        multicast_ok = sc.multicast
    bsc = getattr(p, "batch_sign_cpu", None) or None
    vres, fleet = simulate(sc, traces, batch_sign_cpu=bsc, multicast_ok=multicast_ok)

    srv = [t.cpu_by("S") + t.final_server_cpu for t in traces]
    veh = [t.cpu_by("V") + t.final_vehicle_cpu for t in traces]
    hs_srv = [sum(f.cpu for f in t.flights if f.src == "S" and not f.bulk) for t in traces]
    hs_veh = [sum(f.cpu for f in t.flights if f.src == "V" and f.label != "install_report") for t in traces]
    row = dict(
        protocol=proto_name, short=p.short, sid=sc.sid, split=sc.split, seed=sc.seed, channel=sc.channel,
        n_vehicles=sc.n_vehicles, pkg_size=sc.pkg_size, multicast=bool(multicast_ok and sc.channel == "wifi"),
        frame_loss=sc.frame_loss, pkt_loss=sc.pkt_loss, area=sc.area, outage_mean_up=sc.outage_mean_up,
        **fleet,
        server_cpu_per_vehicle_ms=1e3 * fleet["server_cpu_total"] / sc.n_vehicles,
        crypto_server_ms=1e3 * statistics.mean(srv),
        crypto_vehicle_ms=1e3 * statistics.mean(veh),
        handshake_server_ms=1e3 * statistics.mean(hs_srv),
        handshake_vehicle_ms=1e3 * statistics.mean(hs_veh),
        release_cpu_ms=1e3 * p.release_cpu,
        n_flights=len(traces[0].flights),
        wire_hs_bytes=int(np.mean([sum(f.nbytes for f in t.flights if not f.bulk) for t in traces])),
        wire_bulk_bytes=int(np.mean([sum(f.nbytes for f in t.flights if f.bulk) for t in traces])),
        batch_sign_ms=1e3 * statistics.mean(bsc) if bsc else 0.0,
        setup_s=setup_s, wall_s=time.perf_counter() - t_wall,
    )
    return row
