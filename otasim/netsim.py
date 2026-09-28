"""Trace-driven discrete-event network emulator (SimPy).

Replaces Mininet-WiFi (unavailable on the Windows host).  Cryptographic work is *not*
modelled: every CPU interval replayed here was measured while executing the real protocol
(protocols.py).  What is modelled is the network and the server's finite cores:

wifi      IEEE 802.11g infrastructure BSS (the source paper's setting): shared medium,
          DCF airtime model with frame-level fairness (802.11 "performance anomaly",
          Heusse et al. INFOCOM'03), OFDM rate adaptation from RSSI (log-distance path loss,
          802.11g receiver sensitivities), random-direction mobility, MAC retries.
          Optional multicast carousel for content that is identical for every vehicle, with
          per-vehicle unicast repair of lost packets.
cellular  per-vehicle LTE/5G links (lognormal rates, RTT, loss -> Mathis TCP bound, slow start),
          shared server egress with max-min fair sharing, on/off outages.

A connection that makes no progress for `tcp_timeout` seconds breaks; the vehicle then
reconnects and either resumes the download (resumable protocols) or restarts the whole
session (non-resumable protocols).
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

import numpy as np
import simpy

MSS = 1460

# ------------------------------------------------------------------ 802.11g PHY/MAC timing
SLOT, SIFS, DIFS = 9e-6, 10e-6, 28e-6
CWMIN = 15
RATES = [54, 48, 36, 24, 18, 12, 9, 6]  # Mbps
SENS = {54: -65, 48: -66, 36: -70, 24: -74, 18: -77, 12: -79, 9: -81, 6: -82}  # dBm (802.11g typical)


def _ppdu(rate_mbps: float, nbytes: int) -> float:
    """ERP-OFDM PPDU duration: 20 us preamble/header + 4 us symbols + 6 us signal extension."""
    bits = 16 + 6 + 8 * nbytes
    return 20e-6 + 4e-6 * math.ceil(bits / (4 * rate_mbps)) + 6e-6


def frame_exchange(rate: float, payload: int, ack: bool = True) -> float:
    """One DCF data frame (MAC 28 B + LLC 8 B + IP/TCP 40 B + payload) incl. mean backoff and MAC ACK."""
    t = DIFS + CWMIN / 2 * SLOT + _ppdu(rate, 28 + 8 + 40 + payload)
    if ack:
        t += SIFS + _ppdu(min(rate, 24), 14)
    return t


def airtime_per_mss(rate: float, loss: float) -> float:
    """Airtime to move MSS payload bytes incl. one TCP ACK per two segments and MAC retries."""
    return (frame_exchange(rate, MSS) + 0.5 * frame_exchange(rate, 0)) / max(1e-9, 1 - loss)


# ------------------------------------------------------------------ mobility
class RandomDirection:
    """Random-direction mobility in [0,L]^2; new heading at the boundary."""

    def __init__(self, L: float, vmin: float, vmax: float, rng: random.Random):
        self.L, self.vmin, self.vmax, self.rng = L, vmin, vmax, rng
        self.legs = []  # (t0, x0, y0, vx, vy, t1)
        x, y = rng.uniform(0, L), rng.uniform(0, L)
        self._extend(0.0, x, y)

    def _extend(self, t0, x, y):
        v = self.rng.uniform(self.vmin, self.vmax)
        th = self.rng.uniform(0, 2 * math.pi)
        vx, vy = v * math.cos(th), v * math.sin(th)
        ts = []
        for p, vp in ((x, vx), (y, vy)):
            if vp > 1e-12:
                ts.append((self.L - p) / vp)
            elif vp < -1e-12:
                ts.append(-p / vp)
        dt = max(0.5, min(ts) if ts else 1e9)
        self.legs.append((t0, x, y, vx, vy, t0 + dt))

    def pos(self, t: float):
        while self.legs[-1][5] < t:
            t0, x, y, vx, vy, t1 = self.legs[-1]
            d = t1 - t0
            nx = min(max(x + vx * d, 0.0), self.L)
            ny = min(max(y + vy * d, 0.0), self.L)
            self._extend(t1, nx, ny)
        for t0, x, y, vx, vy, t1 in reversed(self.legs):
            if t0 <= t:
                d = t - t0
                return min(max(x + vx * d, 0), self.L), min(max(y + vy * d, 0), self.L)
        return self.legs[0][1], self.legs[0][2]


# ------------------------------------------------------------------ scenario
@dataclass
class Scenario:
    sid: str
    channel: str = "wifi"  # wifi | cellular
    n_vehicles: int = 20
    pkg_size: int = 4096
    seed: int = 0
    split: str = "dev"
    # wifi
    area: float = 80.0
    vmin: float = 5.0
    vmax: float = 10.0
    tx_dbm: float = 1.0
    ant_gain: float = 5.0  # per side (Mininet-WiFi default)
    pl_exp: float = 3.0
    frame_loss: float = 0.02
    multicast: bool = False
    mc_rate: float = 24.0
    # cellular
    dl_median_mbps: float = 20.0
    ul_median_mbps: float = 5.0
    rtt_ms: float = 50.0
    pkt_loss: float = 0.001
    egress_gbps: float = 1.0
    outage_mean_up: float = 0.0  # 0 -> no outages
    outage_mean_down: float = 5.0
    # server / timing
    server_cores: int = 8
    start_jitter: float = 1.0
    tcp_timeout: float = 20.0
    max_restarts: int = 50
    horizon: float = 7 * 86400.0
    vehicle_cpu_scale: float = 1.0
    batch_window: float = 0.05
    batch_max: int = 64
    note: str = ""


# ------------------------------------------------------------------ fluid media
class Flow:
    __slots__ = ("vid", "remaining", "done", "paused_since", "rate", "kind", "meta")

    def __init__(self, vid, nbytes, done, kind="uni", meta=None):
        self.vid, self.remaining, self.done = vid, float(nbytes), done
        self.paused_since = None
        self.rate = 0.0
        self.kind = kind
        self.meta = meta or {}


class Broken(Exception):
    """Connection broke; args[0] = bytes of the interrupted message still missing."""


class Medium:
    TICK = 1.0

    def __init__(self, env: simpy.Environment, sc: Scenario, rng: random.Random, n: int):
        self.env, self.sc, self.rng = env, sc, rng
        self.flows: list[Flow] = []
        self.changed = env.event()
        self.last = 0.0
        self.airbytes = 0.0
        env.process(self._loop())

    # subclasses: _compute_rates(now) sets f.rate for all flows; link_up(vid, now)
    def transfer(self, vid, nbytes, kind="uni", meta=None):
        ev = self.env.event()
        if nbytes <= 0:
            ev.succeed()
            return ev
        self._advance()
        self.flows.append(Flow(vid, nbytes, ev, kind, meta))
        self._poke()
        return ev

    def _poke(self):
        if not self.changed.triggered:
            self.changed.succeed()

    def _advance(self):
        now = self.env.now
        dt = now - self.last
        if dt > 0:
            for f in self.flows:
                if f.rate > 0:
                    moved = min(f.remaining, f.rate * dt)
                    f.remaining -= moved
                    self.airbytes += moved
                    self._on_progress(f, moved, dt)
        self.last = now

    def _on_progress(self, f, moved, dt):
        pass

    def _loop(self):
        env = self.env
        while True:
            self._advance()
            now = env.now
            # complete / break flows
            keep = []
            for f in self.flows:
                if f.remaining <= 1e-6 and f.kind != "carousel":
                    f.done.succeed()
                elif f.paused_since is not None and f.kind == "uni" and now - f.paused_since >= self.sc.tcp_timeout:
                    f.done.fail(Broken(f.remaining))
                else:
                    keep.append(f)
            self.flows = keep
            self._compute_rates(now)
            for f in self.flows:
                if f.rate <= 0 and f.paused_since is None:
                    f.paused_since = now
                elif f.rate > 0:
                    f.paused_since = None
            dts = [f.remaining / f.rate for f in self.flows if f.rate > 0 and f.kind != "carousel"]
            dts += self._extra_deadlines(now)
            if any(f.paused_since is not None for f in self.flows) or self._needs_tick():
                dts.append(self.TICK)
            if not self.flows and not dts:
                self.changed = env.event()
                yield self.changed
                continue
            dt = max(1e-9, min(dts)) if dts else self.TICK
            self.changed = env.event()
            yield env.timeout(dt) | self.changed

    def _extra_deadlines(self, now):
        return []

    def _needs_tick(self):
        return False


class WiFiMedium(Medium):
    def __init__(self, env, sc, rng, n):
        self.mob = [RandomDirection(sc.area, sc.vmin, sc.vmax, random.Random(rng.random())) for _ in range(n)]
        self.carousel = None  # Flow of the multicast carousel
        self.subs = {}  # vid -> dict(received, sent_since_join, size, event)
        super().__init__(env, sc, rng, n)

    def rssi(self, vid, t):
        x, y = self.mob[vid].pos(t)
        c = self.sc.area / 2
        d = max(1.0, math.hypot(x - c, y - c))
        return self.sc.tx_dbm + 2 * self.sc.ant_gain - (40.05 + 10 * self.sc.pl_exp * math.log10(d))

    def phy_rate(self, vid, t):
        r = self.rssi(vid, t)
        for rate in RATES:
            if r >= SENS[rate]:
                return rate
        return 0

    def link_up(self, vid, t):
        return self.phy_rate(vid, t) > 0

    def _compute_rates(self, now):
        costs = {}
        for f in self.flows:
            if f.kind == "carousel":
                costs[id(f)] = frame_exchange(self.sc.mc_rate, MSS, ack=False)
            else:
                r = self.phy_rate(f.vid, now)
                if r > 0:
                    costs[id(f)] = airtime_per_mss(r, self.sc.frame_loss)
        tot = sum(costs.values())
        for f in self.flows:
            f.rate = (MSS / tot) if id(f) in costs else 0.0

    def _needs_tick(self):
        return bool(self.flows)  # rates change with mobility

    # ---------------- multicast carousel with unicast repair
    def subscribe(self, vid, size):
        ev = self.env.event()
        self._advance()
        self.subs[vid] = dict(received=0.0, sent=0.0, size=float(size), event=ev)
        if self.carousel is None:
            self.carousel = Flow(-1, float("inf"), self.env.event(), kind="carousel")
            self.flows.append(self.carousel)
        self._poke()
        return ev

    def _on_progress(self, f, moved, dt):
        if f.kind != "carousel":
            return
        t = self.env.now
        done = []
        for vid, s in self.subs.items():
            s["sent"] += moved
            # multicast frames are sent at mc_rate without MAC ACK/retry: received iff RSSI clears that
            # rate's sensitivity, and then only with probability (1 - frame_loss)
            if self.rssi(vid, t) >= SENS[int(self.sc.mc_rate)]:
                s["received"] += moved * (1 - self.sc.frame_loss)
            if s["sent"] >= s["size"]:
                done.append(vid)
        for vid in done:
            s = self.subs.pop(vid)
            s["event"].succeed(max(0.0, s["size"] - s["received"]))  # bytes still missing -> unicast repair
        if not self.subs and self.carousel is not None:
            self.carousel.remaining = 0.0
            self.flows = [x for x in self.flows if x is not self.carousel]
            self.carousel = None

    def _extra_deadlines(self, now):
        if self.carousel is None or not self.subs:
            return []
        rate = self.carousel.rate
        if rate <= 0:
            return []
        return [max(1e-9, min(s["size"] - s["sent"] for s in self.subs.values()) / rate)]


class CellularMedium(Medium):
    """Per-vehicle access links + shared server egress (max-min fair)."""

    def __init__(self, env, sc, rng, n):
        g = np.random.default_rng(rng.randrange(2**32))
        self.dl = sc.dl_median_mbps * 1e6 / 8 * g.lognormal(0, 0.5, n)
        self.ul = sc.ul_median_mbps * 1e6 / 8 * g.lognormal(0, 0.5, n)
        self.rtt = sc.rtt_ms / 1e3 * g.lognormal(0, 0.2, n)
        mathis = MSS / self.rtt * math.sqrt(1.5 / sc.pkt_loss) if sc.pkt_loss > 0 else np.full(n, np.inf)
        self.dl_eff = np.minimum(self.dl, mathis)
        self.ul_eff = np.minimum(self.ul, mathis)
        self.outages = []
        for i in range(n):
            iv = []
            if sc.outage_mean_up > 0:
                t = g.exponential(sc.outage_mean_up)
                while t < sc.horizon and len(iv) < 20000:
                    d = g.exponential(sc.outage_mean_down)
                    iv.append((t, t + d))
                    t += d + g.exponential(sc.outage_mean_up)
            self.outages.append(iv)
        super().__init__(env, sc, rng, n)

    def link_up(self, vid, t):
        for a, b in self.outages[vid]:
            if a <= t < b:
                return False
            if a > t:
                break
        return True

    def _compute_rates(self, now):
        cap = self.sc.egress_gbps * 1e9 / 8
        down = [f for f in self.flows if f.meta.get("dir") == "down" and self.link_up(f.vid, now)]
        for f in self.flows:
            f.rate = 0.0
            if not self.link_up(f.vid, now):
                continue
            if f.meta.get("dir") == "up":
                f.rate = self.ul_eff[f.vid]
        # water-filling on the egress for downlink flows
        rem, act = cap, sorted(down, key=lambda f: self.dl_eff[f.vid])
        while act:
            share = rem / len(act)
            f = act[0]
            if self.dl_eff[f.vid] <= share:
                f.rate = self.dl_eff[f.vid]
                rem -= f.rate
                act.pop(0)
            else:
                for f in act:
                    f.rate = share
                break

    def _needs_tick(self):
        return self.sc.outage_mean_up > 0 and bool(self.flows)


# ------------------------------------------------------------------ fleet simulation
@dataclass
class VehicleResult:
    vid: int
    t_start: float = 0.0
    t_auth: float = float("nan")
    t_done: float = float("nan")
    restarts: int = 0
    failed: bool = False
    bytes_down: float = 0.0
    bytes_up: float = 0.0
    server_cpu: float = 0.0
    vehicle_cpu: float = 0.0
    times: list = field(default_factory=list)  # (flight label, time the flight was fully received)


def simulate(sc: Scenario, traces: list, batch_sign_cpu: list[float] | None = None, multicast_ok: bool = False):
    """Replay one trace per vehicle.  Returns (list[VehicleResult], dict fleet metrics)."""
    rng = random.Random(sc.seed * 7919 + 17)
    env = simpy.Environment()
    n = len(traces)
    med = WiFiMedium(env, sc, rng, n) if sc.channel == "wifi" else CellularMedium(env, sc, rng, n)
    cpu = simpy.Resource(env, capacity=sc.server_cores)
    res = [VehicleResult(i) for i in range(n)]
    base_lat = 0.0005 if sc.channel == "wifi" else None
    bsc = batch_sign_cpu or [0.0]

    # ------------------------------------------------ batcher for amortised Director signatures
    batch_q: list = []
    batch_state = {"timer": None}

    def run_batch(items):
        with cpu.request() as rq:
            yield rq
            tot = sum(c for c, _, _ in items) + rng.choice(bsc)
            yield env.timeout(tot)
        for c, ev, i in items:
            res[i].server_cpu += c + rng.choice(bsc) / len(items)
            ev.succeed()

    def batch_timer():
        yield env.timeout(sc.batch_window)
        items = batch_q[:]
        batch_q.clear()
        batch_state["timer"] = None
        if items:
            env.process(run_batch(items))

    def batched(i, c):
        ev = env.event()
        batch_q.append((c, ev, i))
        if len(batch_q) >= sc.batch_max:
            items = batch_q[:]
            batch_q.clear()
            env.process(run_batch(items))
        elif batch_state["timer"] is None:
            batch_state["timer"] = env.process(batch_timer())
        return ev

    # ------------------------------------------------ transmission with latency model
    conn = [dict(cwnd=10 * MSS) for _ in range(n)]

    def send(i, src, nbytes):
        direction = "up" if src == "V" else "down"
        if sc.channel == "wifi":
            yield med.transfer(i, nbytes)
            yield env.timeout(base_lat)
        else:
            rtt = med.rtt[i]
            # slow start rounds on this connection until the congestion window covers the message/BDP
            c = conn[i]
            rate = med.dl_eff[i] if direction == "down" else med.ul_eff[i]
            bdp = rate * rtt
            rounds, sent = 0, 0.0
            while sent + c["cwnd"] < nbytes and c["cwnd"] < bdp:
                sent += c["cwnd"]
                c["cwnd"] *= 2
                rounds += 1
            yield env.timeout(rtt / 2 + rounds * rtt)
            # small-message loss -> retransmission timeout
            segs = max(1, math.ceil(nbytes / MSS))
            if nbytes < 64 * MSS and rng.random() < 1 - (1 - sc.pkt_loss) ** segs:
                yield env.timeout(max(0.2, 2 * rtt))
            yield med.transfer(i, nbytes, meta={"dir": direction})
        if direction == "up":
            res[i].bytes_up += nbytes
        else:
            res[i].bytes_down += nbytes

    def tcp_connect(i):
        conn[i]["cwnd"] = 10 * MSS
        yield from send(i, "V", 60)
        yield from send(i, "S", 60)

    def vehicle(i, tr):
        r = res[i]
        yield env.timeout(rng.uniform(0, sc.start_jitter))
        r.t_start = env.now
        restarts = 0
        pos = 0  # index of the next flight to play
        bulk_left = None  # bytes of the bulk flight still missing (multicast repair or resumption)
        cdn = any(f.src == "CDN" for f in tr.flights)
        handshake = [k for k, f in enumerate(tr.flights) if not f.bulk and f.label != "install_report"]
        while True:
            in_bulk = False
            try:
                while not med.link_up(i, env.now):  # wait for coverage before (re)connecting
                    yield env.timeout(1.0)
                yield from tcp_connect(i)
                if restarts and tr.resumable and not cdn and pos > 0:
                    # TLS-style resumption: new handshake, then an HTTP range request
                    for k in handshake:
                        yield from play(i, tr.flights[k])
                while pos < len(tr.flights):
                    f = tr.flights[pos]
                    if f.label == "install_report":
                        yield env.timeout(f.cpu * sc.vehicle_cpu_scale)
                        r.vehicle_cpu += f.cpu
                        r.t_done = env.now
                        yield from send(i, "V", f.nbytes)
                        if tr.final_server_cpu:
                            with cpu.request() as rq:
                                yield rq
                                yield env.timeout(tr.final_server_cpu)
                            r.server_cpu += tr.final_server_cpu
                        pos += 1
                        continue
                    if f.bulk:
                        in_bulk = True
                        if math.isnan(r.t_auth):
                            r.t_auth = env.now
                        if bulk_left is None and f.multicastable and multicast_ok and sc.channel == "wifi":
                            missing = yield med.subscribe(i, f.nbytes)
                            r.bytes_down += f.nbytes - missing
                            bulk_left = missing  # unicast repair of lost packets
                        if bulk_left is not None:
                            yield from play(i, f, nbytes=bulk_left, cpu_done=True)
                        else:
                            yield from play(i, f)
                        bulk_left = None
                        in_bulk = False
                    else:
                        yield from play(i, f)
                    pos += 1
                if math.isnan(r.t_done):
                    yield env.timeout(tr.final_vehicle_cpu * sc.vehicle_cpu_scale)
                    r.vehicle_cpu += tr.final_vehicle_cpu
                    r.t_done = env.now
                return
            except Broken as e:
                restarts += 1
                r.restarts = restarts
                if restarts > sc.max_restarts:
                    r.failed = True
                    return
                if tr.resumable:
                    bulk_left = float(e.args[0]) if in_bulk else None
                else:  # the source protocol destroys its session key: start over
                    pos, bulk_left = 0, None

    def play(i, f, nbytes=None, cpu_done=False):
        r = res[i]
        if not cpu_done:
            if f.src == "S":
                if f.batched:
                    yield batched(i, f.cpu)
                else:
                    with cpu.request() as rq:
                        yield rq
                        yield env.timeout(f.cpu)
                    r.server_cpu += f.cpu
            elif f.src == "V":
                yield env.timeout(f.cpu * sc.vehicle_cpu_scale)
                r.vehicle_cpu += f.cpu
        yield from send(i, f.src, f.nbytes if nbytes is None else nbytes)
        r.times.append((f.label, env.now))

    for i, tr in enumerate(traces):
        env.process(vehicle(i, tr))
    env.run(until=sc.horizon)

    done = np.array([r.t_done for r in res])
    starts = np.array([r.t_start for r in res])
    lat = done - starts
    ok = ~np.isnan(done)
    fleet = dict(
        makespan=float(np.nanmax(done) - np.min(starts)) if ok.any() else float("nan"),
        lat_mean=float(np.nanmean(lat)) if ok.any() else float("nan"),
        lat_p50=float(np.nanmedian(lat)) if ok.any() else float("nan"),
        lat_p95=float(np.nanpercentile(lat, 95)) if ok.any() else float("nan"),
        auth_lat_mean=float(np.nanmean([r.t_auth - r.t_start for r in res])),
        success_rate=float(ok.mean()),
        restarts=float(np.mean([r.restarts for r in res])),
        server_cpu_total=float(sum(r.server_cpu for r in res)),
        vehicle_cpu_mean=float(np.mean([r.vehicle_cpu for r in res])),
        air_bytes=float(med.airbytes),
        bytes_down_mean=float(np.mean([r.bytes_down for r in res])),
        bytes_up_mean=float(np.mean([r.bytes_up for r in res])),
    )
    return res, fleet
