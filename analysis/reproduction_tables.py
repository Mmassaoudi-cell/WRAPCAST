"""Published vs. reproduced values for Kumar et al. (Figs. 3-8, Table III, RSA text values).

Aggregation assumption (SOURCE_PAPER_AUDIT.md): bars are sums over the N vehicles of the
per-session quantity.  Reproduced = mean over seeds of that sum (+- sd over seeds).
Writes results/reproduction/published_vs_reproduced.csv and REPRODUCTION_TABLES.md.
"""
import os

import numpy as np
import pandas as pd

ROOT = os.path.join(os.path.dirname(__file__), "..")
D = os.path.join(ROOT, "results", "reproduction")
NS = [20, 40, 60, 80, 100]
PUB = {  # (figure, protocol) -> values for N = 20..100 (units as published)
    ("Fig3 handshake (ms)", "B02_SRC_DH2048"): [1.33, 2.82, 4.08, 5.38, 6.86],
    ("Fig3 handshake (ms)", "B04_SRC_McE_SPHINCS"): [7.72, 13.71, 20.97, 27.35, 35.71],
    ("Fig3 handshake (ms)", "B01_SOURCE_REPRO"): [0.85, 1.61, 2.31, 3.14, 4.11],
    ("Fig4 decryption (ms)", "B02_SRC_DH2048"): [0.64, 1.28, 2.05, 2.75, 3.46],
    ("Fig4 decryption (ms)", "B04_SRC_McE_SPHINCS"): [0.98, 1.64, 2.39, 3.25, 4.15],
    ("Fig4 decryption (ms)", "B01_SOURCE_REPRO"): [0.72, 1.32, 2.03, 2.50, 3.18],
    ("Fig5 ZKP computation (s)", "B01_SOURCE_REPRO"): [0.012, 0.026, 0.035, 0.045, 0.058],
    ("Fig5 ZKP latency (s)", "B01_SOURCE_REPRO"): [0.033, 0.087, 0.101, 0.128, 0.159],
    ("Fig6 framework latency (ms)", "B02_SRC_DH2048"): [81.07, 161.92, 240.74, 323.38, 404.91],
    ("Fig6 framework latency (ms)", "B04_SRC_McE_SPHINCS"): [86.68, 177.45, 256.59, 338.91, 425.80],
    ("Fig6 framework latency (ms)", "B01_SOURCE_REPRO"): [79.92, 158.27, 238.92, 314.65, 394.15],
    ("Fig7 encryption (ms)", "B02_SRC_DH2048"): [5.29, 10.38, 15.65, 21.13, 26.30],
    ("Fig7 encryption (ms)", "B04_SRC_McE_SPHINCS"): [3.82, 7.57, 11.00, 14.60, 18.32],
    ("Fig7 encryption (ms)", "B01_SOURCE_REPRO"): [3.49, 7.10, 10.61, 13.81, 17.39],
    ("Text RSA handshake (s)", "B03_SRC_RSA2048"): [37.89, 76.82, 116.84, 153.49, 194.47],
    ("Fig8 vehicle registration CPU (s)", "B01_SOURCE_REPRO"): [0.014, 0.023, 0.037, 0.049, 0.062],
    ("Fig8 TA registration CPU (s)", "B01_SOURCE_REPRO"): [0.0017, 0.0028, 0.0038, 0.0045, 0.0053],
}
SCALE = {"(ms)": 1e3, "(s)": 1.0}
COL = {
    "Fig3 handshake": "handshake_cpu_s", "Fig4 decryption": "client_decryption_s",
    "Fig5 ZKP computation": ("server_zkp_s", "client_zkp_s"), "Fig5 ZKP latency": "zkp_latency_s",
    "Fig6 framework latency": "total_cpu_s", "Fig7 encryption": "server_encryption_s", "Text RSA handshake": "handshake_cpu_s",
}
TABLE3 = [("Server handshake latency", "server_handshake_s", 0.040000), ("Server transfer time", "transfer_s", 0.176051),
          ("Server ZKP time", "server_zkp_s", 0.460671), ("Client handshake latency", "client_handshake_s", 3.173252),
          ("Client decryption time", "client_decryption_s", 0.030840), ("Client transfer time", "transfer_s", 0.237724)]


def main():
    s = pd.read_csv(os.path.join(D, "per_session.csv"))
    g = pd.read_csv(os.path.join(D, "registration.csv"))
    s4 = s[s.pkg_size == 4096]
    rows = []
    for (fig, proto), pub in PUB.items():
        unit = fig[fig.rindex("("):]
        key = fig[: fig.rindex("(")].strip()
        for n, pv in zip(NS, pub):
            if key.startswith("Fig8"):
                col = "vehicle_cpu" if "vehicle" in key else "ta_cpu"
                sums = g[(g.protocol == proto) & (g.n == n)].groupby("seed")[col].sum()
            else:
                c = COL[key]
                sub = s4[(s4.protocol == proto) & (s4.n == n)]
                v = sub[list(c)].sum(axis=1) if isinstance(c, tuple) else sub[c]
                sums = v.groupby(sub.seed).sum()
            rep = sums.mean() * SCALE[unit]
            sd = sums.std(ddof=1) * SCALE[unit]
            rows.append(dict(item=fig, protocol=proto, N=n, published=pv, reproduced=rep, reproduced_sd=sd,
                             difference=rep - pv, ratio=rep / pv if pv else np.nan))
    df = pd.DataFrame(rows)
    df.to_csv(os.path.join(D, "published_vs_reproduced.csv"), index=False)
    t3 = []
    k = s4[s4.protocol == "B01_SOURCE_REPRO"]
    for name, col, pub in TABLE3:
        x = k[col]
        t3.append(dict(metric=name, published_mean_s=pub, reproduced_mean_s=x.mean(), reproduced_var_s2=x.var(),
                       reproduced_lo=x.mean() - x.std(), reproduced_hi=x.mean() + x.std(), ratio=x.mean() / pub))
    t3 = pd.DataFrame(t3)
    t3.to_csv(os.path.join(D, "table3_vs_reproduced.csv"), index=False)
    # per-vehicle summary (4 KB and 1 MB)
    per = s.groupby(["protocol", "pkg_size"])[["handshake_cpu_s", "server_zkp_s", "client_zkp_s", "server_encryption_s",
                                               "client_decryption_s", "total_cpu_s", "e2e_latency_s", "wire_bytes"]].mean()
    per.to_csv(os.path.join(D, "per_vehicle_means.csv"))
    run = pd.read_csv(os.path.join(D, "per_run.csv"))
    mk = run.groupby(["protocol", "pkg_size", "n"])[["makespan", "lat_mean"]].mean().reset_index()
    mk.to_csv(os.path.join(D, "makespan_means.csv"), index=False)
    with open(os.path.join(ROOT, "REPRODUCTION_TABLES.md"), "w", encoding="utf-8") as f:
        f.write("<!-- generated by analysis/reproduction_tables.py; do not edit by hand -->\n\n")
        f.write("## Published vs. reproduced (4 KB package, sum over N vehicles, mean ± sd over 10 seeds)\n\n")
        f.write("| Item | Protocol | N | Published | Reproduced | ± sd | Difference | Ratio |\n|---|---|---:|---:|---:|---:|---:|---:|\n")
        for r in rows:
            f.write(f"| {r['item']} | {r['protocol']} | {r['N']} | {r['published']:.4g} | {r['reproduced']:.4g} | "
                    f"{r['reproduced_sd']:.2g} | {r['difference']:+.4g} | {r['ratio']:.3g} |\n")
        f.write("\n## Table III (per session, Kyber768+Dilithium3, 4 KB)\n\n| Metric | Published mean (s) | Reproduced mean (s) | Reproduced var (s²) | Ratio |\n|---|---:|---:|---:|---:|\n")
        for r in t3.itertuples():
            f.write(f"| {r.metric} | {r.published_mean_s:.6f} | {r.reproduced_mean_s:.6f} | {r.reproduced_var_s2:.3g} | {r.ratio:.3g} |\n")
        f.write("\n## Per-vehicle means (all N and seeds)\n\n")
        f.write(per.reset_index().to_markdown(index=False, floatfmt=".5g"))
        f.write("\n\n## Simulated fleet makespan (s)\n\n")
        f.write(mk.pivot_table(index=["protocol", "pkg_size"], columns="n", values="makespan").reset_index().to_markdown(index=False, floatfmt=".4g"))
        f.write("\n")
    print(df.groupby(["item", "protocol"]).ratio.median().to_string())
    print(t3.to_string(index=False))


if __name__ == "__main__":
    main()
