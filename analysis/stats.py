"""Statistical comparison of PROPOSED against every benchmark (paired by seed).

Pre-declared protocol
  * primary metric: fleet makespan (s), lower is better;
    secondary: mean / p95 per-vehicle completion latency, server CPU per vehicle, authorization latency,
    handshake bytes, vehicle crypto CPU.
  * paired Wilcoxon signed-rank (two-sided) and paired t-test over seeds; Holm correction over the
    benchmarks within each (scenario, metric); effect sizes: matched-pairs rank-biserial r and Cohen's d_z.
  * classes:  superior      Holm-p < 0.05, PROPOSED better, |relative difference| >= 1 %
              practical     PROPOSED better by >= 5 % but Holm-p >= 0.05
              tie           otherwise, unless
              inferior      Holm-p < 0.05 and PROPOSED worse (|rel. diff| >= 1 %)
  * W/T/L: win = superior, loss = inferior, tie = practical or tie.
Outputs: results/test/summary_<group>.csv, stats_<group>.csv, BENCHMARK_WTL.csv (main group)
"""
from __future__ import annotations

import argparse
import os

import numpy as np
import pandas as pd
from scipy import stats

ROOT = os.path.join(os.path.dirname(__file__), "..")
METRICS = ["makespan", "lat_mean", "lat_p95", "server_cpu_per_vehicle_ms", "auth_lat_mean", "wire_hs_bytes",
           "crypto_vehicle_ms", "air_bytes"]


def boot_ci(x, n=10000, seed=0):
    x = np.asarray(x, float)
    if len(x) < 2 or np.allclose(x, x[0]):
        return float(x.mean()), float(x.mean())
    rng = np.random.default_rng(seed)
    m = rng.choice(x, (n, len(x))).mean(1)
    return float(np.percentile(m, 2.5)), float(np.percentile(m, 97.5))


def holm(p):
    p = np.asarray(p, float)
    order = np.argsort(p)
    adj = np.empty_like(p)
    run = 0.0
    m = len(p)
    for k, i in enumerate(order):
        run = max(run, min(1.0, (m - k) * p[i]))
        adj[i] = run
    return adj


def paired(a, b):
    """a = PROPOSED, b = benchmark (aligned by seed). Returns p_wilcoxon, p_t, r_rb, d_z."""
    d = np.asarray(a, float) - np.asarray(b, float)
    if np.allclose(d, 0):
        return 1.0, 1.0, 0.0, 0.0
    try:
        pw = stats.wilcoxon(a, b, zero_method="wilcox", alternative="two-sided").pvalue
    except ValueError:
        pw = 1.0
    pt = stats.ttest_rel(a, b).pvalue if np.std(d) > 0 else (0.0 if abs(d.mean()) > 0 else 1.0)
    nz = d[d != 0]
    ranks = stats.rankdata(np.abs(nz))
    r_rb = (ranks[nz > 0].sum() - ranks[nz < 0].sum()) / ranks.sum() if len(nz) else 0.0
    dz = d.mean() / d.std(ddof=1) if d.std(ddof=1) > 0 else np.sign(d.mean()) * np.inf
    return float(pw), float(pt), float(r_rb), float(dz)


def summarise(df):
    rows = []
    for (sid, proto), g in df.groupby(["sid", "protocol"]):
        for m in METRICS:
            if m not in g:
                continue
            x = g[m].to_numpy(float)
            lo, hi = boot_ci(x)
            rows.append(dict(sid=sid, protocol=proto, short=g["short"].iloc[0], metric=m, n=len(x), mean=x.mean(),
                             sd=x.std(ddof=1) if len(x) > 1 else 0.0, median=np.median(x), ci_lo=lo, ci_hi=hi))
    return pd.DataFrame(rows)


def compare(df, ref="PROPOSED"):
    rows = []
    for sid, g in df.groupby("sid"):
        if ref not in set(g.protocol):
            continue
        a_all = g[g.protocol == ref].set_index("seed")
        for m in METRICS:
            block = []
            for b in sorted(set(g.protocol) - {ref}):
                b_all = g[g.protocol == b].set_index("seed")
                seeds = sorted(set(a_all.index) & set(b_all.index))
                if len(seeds) < 3:
                    continue
                a, bb = a_all.loc[seeds, m].to_numpy(float), b_all.loc[seeds, m].to_numpy(float)
                pw, pt, r, dz = paired(a, bb)
                rel = (a.mean() - bb.mean()) / abs(bb.mean()) * 100 if bb.mean() != 0 else 0.0
                block.append(dict(sid=sid, metric=m, benchmark=b, n=len(seeds), mean_proposed=a.mean(),
                                  mean_benchmark=bb.mean(), rel_diff_pct=rel, p_wilcoxon=pw, p_ttest=pt,
                                  rank_biserial=r, cohen_dz=dz))
            if not block:
                continue
            adj = holm([x["p_wilcoxon"] for x in block])
            for x, h in zip(block, adj):
                x["p_holm"] = h
                better = x["rel_diff_pct"] < 0  # all metrics: lower is better
                big = abs(x["rel_diff_pct"]) >= 1.0
                if h < 0.05 and big:
                    x["verdict"] = "superior" if better else "inferior"
                elif better and abs(x["rel_diff_pct"]) >= 5.0:
                    x["verdict"] = "practical"
                else:
                    x["verdict"] = "tie"
                rows.append(x)
    return pd.DataFrame(rows)


def wtl(cmp, metric):
    out = []
    for b, g in cmp[cmp.metric == metric].groupby("benchmark"):
        out.append(dict(benchmark=b, metric=metric, scenarios=len(g), wins=int((g.verdict == "superior").sum()),
                        ties=int(g.verdict.isin(["tie", "practical"]).sum()), losses=int((g.verdict == "inferior").sum()),
                        practical_only=int((g.verdict == "practical").sum()),
                        median_rel_diff_pct=float(g.rel_diff_pct.median()),
                        median_rank_biserial=float(g.rank_biserial.median()), max_p_holm=float(g.p_holm.max())))
    return pd.DataFrame(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("group", default="main", nargs="?")
    a = ap.parse_args()
    d = os.path.join(ROOT, "results", "test")
    df = pd.read_csv(os.path.join(d, f"{a.group}.csv"))
    summarise(df).to_csv(os.path.join(d, f"summary_{a.group}.csv"), index=False)
    cmp = compare(df)
    cmp.to_csv(os.path.join(d, f"stats_{a.group}.csv"), index=False)
    if a.group == "main":
        W = pd.concat([wtl(cmp, m) for m in ["makespan", "lat_mean", "server_cpu_per_vehicle_ms", "auth_lat_mean"]])
        W.to_csv(os.path.join(ROOT, "BENCHMARK_WTL.csv"), index=False)
        t = W[W.metric == "makespan"]
        print(f"Proposed (makespan): {t.wins.sum()} wins / {t.ties.sum()} ties / {t.losses.sum()} losses")
        print(W.to_string(index=False))


if __name__ == "__main__":
    main()
