"""All paper figures, generated only from result CSV files.  Output: paper/figs/*.pdf (+ .png previews)."""
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = os.path.join(os.path.dirname(__file__), "..")
R = os.path.join(ROOT, "results")
OUT = os.path.join(ROOT, "paper", "figs")
os.makedirs(OUT, exist_ok=True)

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "DejaVu Serif"], "font.size": 8,
    "axes.labelsize": 8, "axes.titlesize": 8, "legend.fontsize": 7, "xtick.labelsize": 7, "ytick.labelsize": 7,
    "axes.spines.top": False, "axes.spines.right": False, "axes.linewidth": 0.6, "grid.linewidth": 0.4,
    "grid.color": "#e4e3df", "axes.grid": True, "axes.axisbelow": True, "lines.linewidth": 1.4,
    "pdf.fonttype": 42, "savefig.dpi": 300,
})
# emphasis palette (reference instance): proposed = slot 1, source = slot 2, strongest competitor = slot 3, rest = neutral
C_PROP, C_SRC, C_UPT, C_GRAY, C_INK = "#2a78d6", "#eb6834", "#1baf7a", "#a3a29c", "#52514e"
W1, W2 = 3.5, 7.16

NAMES = {
    "PROPOSED": "WrapCast", "B01_SOURCE_REPRO": "Kumar et al. (B01)", "B02_SRC_DH2048": "B01-DH2048 (B02)",
    "B03_SRC_RSA2048": "B01-RSA2048 (B03)", "B04_SRC_McE_SPHINCS": "B01-McEliece+SPHINCS+ (B04)",
    "B05_SRC_FALCON": "B01-Falcon (B05)", "B06_TLS13_CLASSIC": "TLS 1.3 (B06)", "B07_TLS13_PQHYBRID": "PQ-TLS 1.3 (B07)",
    "B08_UPTANE_CLASSIC": "Uptane (B08)", "B09_UPTANE_PQ": "PQ-Uptane (B09)", "B10_KEMTLS": "KEMTLS (B10)",
}


def style(p):
    if p == "PROPOSED":
        return dict(color=C_PROP, marker="o", lw=2.0, ms=4.5, zorder=5)
    if p == "B01_SOURCE_REPRO":
        return dict(color=C_SRC, marker="s", lw=1.4, ms=3.5, zorder=4)
    if p == "B09_UPTANE_PQ":
        return dict(color=C_UPT, marker="^", lw=1.4, ms=3.5, zorder=4)
    return dict(color=C_GRAY, marker=".", lw=0.8, ms=3, zorder=2, alpha=0.9)


def plain_log(a, axis="y"):
    from matplotlib.ticker import NullFormatter, ScalarFormatter
    ax_ = a.yaxis if axis == "y" else a.xaxis
    f = ScalarFormatter()
    f.set_scientific(False)
    ax_.set_major_formatter(f)
    ax_.set_minor_formatter(NullFormatter())


def save(fig, name):
    fig.savefig(os.path.join(OUT, name + ".pdf"), bbox_inches="tight")
    fig.savefig(os.path.join(OUT, name + ".png"), bbox_inches="tight", dpi=200)
    plt.close(fig)


def ci(x):
    x = np.asarray(x, float)
    if len(x) < 2:
        return 0.0
    rng = np.random.default_rng(0)
    m = rng.choice(x, (4000, len(x))).mean(1)
    return (np.percentile(m, 97.5) - np.percentile(m, 2.5)) / 2


# ------------------------------------------------------------------ Fig. 2: workflow / flow profile
def fig_flow():
    d = pd.read_csv(os.path.join(R, "test", "flow_profile.csv"))
    pre = d[~d.bulk & (d.label != "install_report")]
    g = pre.groupby(["protocol", "rep"]).agg(flights=("order", "count"), bytes=("bytes", "sum")).groupby("protocol").mean()
    main = pd.read_csv(os.path.join(R, "test", "main.csv"))
    cpu = main[main.sid == "T2_wifi_N100_16M"].groupby("protocol").server_cpu_per_vehicle_ms.mean()
    g["cpu"] = cpu
    g["rtt"] = np.ceil(g.flights / 2)
    order = g.sort_values("cpu").index.tolist()
    fig, ax = plt.subplots(1, 3, figsize=(W2, 2.3), sharey=True)
    y = np.arange(len(order))
    for k, (col, lab, log) in enumerate([("rtt", "Round trips before content", False),
                                          ("bytes", "Pre-content bytes per vehicle", True),
                                          ("cpu", "Server CPU per vehicle (ms), 16 MB", True)]):
        a = ax[k]
        for i, p in enumerate(order):
            s = style(p)
            a.hlines(i, 0 if not log else g[col].min() / 3, g.loc[p, col], color=s["color"], lw=1.0 if p != "PROPOSED" else 2.0)
            a.plot(g.loc[p, col], i, marker=s["marker"] if s["marker"] != "." else "o", color=s["color"], ms=4.5, ls="none")
        if log:
            a.set_xscale("log")
        a.set_xlabel(lab)
        a.grid(axis="y", visible=False)
    ax[0].set_yticks(y, [NAMES[p] for p in order])
    for t in ax[0].get_yticklabels():
        if t.get_text() == "WrapCast":
            t.set_fontweight("bold")
    fig.tight_layout(w_pad=0.8)
    save(fig, "fig2_flow")


# ------------------------------------------------------------------ Fig. 3: main benchmark performance
def fig_main():
    d = pd.read_csv(os.path.join(R, "test", "main.csv"))
    fig, ax = plt.subplots(1, 3, figsize=(W2, 2.35))
    for k, (fam, title) in enumerate([("T2_wifi", "(a) Depot Wi-Fi, 16 MB, unicast"),
                                      ("T3_wifiMC", "(b) Depot Wi-Fi, 16 MB, multicast allowed")]):
        a = ax[k]
        sub = d[d.sid.str.startswith(fam + "_N")]
        sub = sub.assign(N=sub.sid.str.extract(r"_N(\d+)_")[0].astype(int))
        for p in sorted(sub.protocol.unique(), key=lambda q: (q == "PROPOSED", q)):
            s = sub[sub.protocol == p].groupby("N").makespan
            m, e = s.mean(), s.apply(ci)
            st = style(p)
            a.errorbar(m.index, m.values, yerr=e.values, capsize=1.5, elinewidth=0.6, **st,
                       label=NAMES[p] if p in ("PROPOSED", "B01_SOURCE_REPRO", "B09_UPTANE_PQ") else None)
        a.set_yscale("log")
        plain_log(a)
        a.set_xlabel("Fleet size $N$")
        a.set_ylabel("Fleet makespan (s)")
        a.set_title(title, loc="left")
        a.set_xticks([20, 60, 100])
    ax[1].legend(frameon=False, loc="center right")
    # (c) cellular: makespan relative to WrapCast
    a = ax[2]
    sids = [("T4_lte_N200_16M", "LTE, N=200, 16 MB"), ("T5_5g_N1000_64M", "5G, N=1000, 64 MB"),
            ("T6_lteOutage_N100_64M", "LTE+outages, N=100, 64 MB")]
    for j, (sid, lab) in enumerate(sids):
        sub = d[d.sid == sid]
        if sub.empty:
            continue
        ref = sub[sub.protocol == "PROPOSED"].set_index("seed").makespan
        for p in sub.protocol.unique():
            r = (sub[sub.protocol == p].set_index("seed").makespan / ref).dropna()
            st = style(p)
            a.plot(r.mean(), j + (0.18 if p == "PROPOSED" else 0), marker=st["marker"] if st["marker"] != "." else "o",
                   color=st["color"], ms=4 if p != "PROPOSED" else 5, ls="none", alpha=0.9)
    a.axvline(1.0, color=C_PROP, lw=0.8, ls="--")
    a.set_yticks(range(len(sids)), [s[1].replace(", ", chr(10), 1) for s in sids])
    a.set_xlabel("Makespan / WrapCast makespan")
    a.set_title("(c) Cellular fleets", loc="left")
    a.grid(axis="y", visible=False)
    fig.tight_layout(w_pad=0.6)
    save(fig, "fig3_main")


# ------------------------------------------------------------------ Fig. 4: depot multicast under loss + fleet scaling
def fig_difficult():
    rb = pd.read_csv(os.path.join(R, "test", "robust.csv"))
    sc_path = os.path.join(R, "test", "scaling.csv")
    fig, ax = plt.subplots(1, 2, figsize=(W2, 2.3))
    a = ax[0]
    for fam, ls, lab in [("R1_wifi_loss", "--", "unicast"), ("R1m_wifiMC_loss", "-", "multicast allowed")]:
        sub = rb[rb.sid.str.startswith(fam)]
        sub = sub.assign(loss=sub.sid.str.replace(fam, "").astype(float))
        for p in ["B01_SOURCE_REPRO", "B09_UPTANE_PQ", "PROPOSED"]:
            s = sub[sub.protocol == p].groupby("loss").makespan.mean()
            st = style(p)
            a.plot(s.index * 100, s.values, ls=ls, color=st["color"], marker=st["marker"], ms=3.5, lw=st["lw"],
                   label=f"{NAMES[p]}, {lab}" if (p == "PROPOSED" or fam.startswith("R1_")) else None)
    a.set_yscale("log")
    plain_log(a)
    a.set_xlabel("802.11 frame loss rate (%)")
    a.set_ylabel("Fleet makespan (s), N=50, 16 MB")
    a.set_title("(a) Depot delivery vs. channel loss", loc="left")
    a.legend(frameon=False, fontsize=6.5)
    a = ax[1]
    if os.path.exists(sc_path):
        sc = pd.read_csv(sc_path)
        sub = sc[sc.sid.str.startswith("S1_5g_N")]
        sub = sub.assign(N=sub.sid.str.extract(r"_N(\d+)_")[0].astype(int))
        for p in sorted(sub.protocol.unique(), key=lambda q: (q == "PROPOSED", q)):
            s = sub[sub.protocol == p].groupby("N").server_cpu_total.mean()
            st = style(p)
            a.plot(s.index, s.values, **st, label=NAMES[p] if p in ("PROPOSED", "B01_SOURCE_REPRO", "B09_UPTANE_PQ") else None)
        a.set_xscale("log")
        a.set_yscale("log")
        a.set_xlabel("Fleet size $N$ (5G, 16 MB)")
        a.set_ylabel("Total server CPU (s)")
        a.set_title("(b) Server work vs. fleet size", loc="left")
        a.legend(frameon=False)
    fig.tight_layout(w_pad=1.0)
    save(fig, "fig4_difficult")


# ------------------------------------------------------------------ Fig. 5: ablation + robustness (coverage gaps)
ABL = [("ABL_per_vehicle_content", "- encrypt-once"), ("ABL_no_batch", "- batching"), ("ABL_digest_only", "- chunk hash list"),
       ("ABL_pure_mlkem", "- hybrid (ML-KEM only)"), ("ABL_online_manifest", "- offline OEM key*"),
       ("ABL_no_report", "- key confirmation"), ("PM_level5", "NIST level-5 params"), ("SENS_director_mldsa44", "Director ML-DSA-44")]


def fig_ablation():
    d = pd.read_csv(os.path.join(R, "test", "ablation.csv"))
    rb = pd.read_csv(os.path.join(R, "test", "robust.csv"))
    fig, ax = plt.subplots(1, 3, figsize=(W2, 2.5), gridspec_kw=dict(width_ratios=[1.15, 1.15, 1]))
    for k, (metric, lab) in enumerate([("makespan", "Makespan change vs. WrapCast (%)"),
                                       ("server_cpu_per_vehicle_ms", "Server CPU change vs. WrapCast (%)")]):
        a = ax[k]
        for j, (sid, mk, col) in enumerate([("T3_wifiMC_N60_16M", "o", C_PROP), ("T4_lte_N200_16M", "s", C_INK)]):
            sub = d[d.sid == sid]
            ref = sub[sub.protocol == "PROPOSED"].set_index("seed")[metric]
            for i, (p, name) in enumerate(ABL):
                r = (sub[sub.protocol == p].set_index("seed")[metric] / ref - 1).dropna() * 100
                a.plot(r.mean(), i + (0.15 if j else -0.15), marker=mk, color=col, ms=3.8, ls="none",
                       label=("Depot multicast N=60" if j == 0 else "LTE N=200") if i == 0 else None)
        a.axvline(0, color=C_INK, lw=0.6)
        a.set_xscale("symlog", linthresh=10)
        a.set_yticks(range(len(ABL)), [n for _, n in ABL] if k == 0 else [])
        a.invert_yaxis()
        a.set_xlabel(lab)
        a.grid(axis="y", visible=False)
    ax[0].legend(frameon=False, loc="lower right", fontsize=6.5)
    ax[0].set_title("(a) Ablation (held-out, 5 seeds)", loc="left")
    a = ax[2]
    sub = rb[rb.sid.str.startswith("R2_wifi_area")]
    sub = sub.assign(area=sub.sid.str.replace("R2_wifi_area", "").astype(int))
    for p in ["B01_SOURCE_REPRO", "B07_TLS13_PQHYBRID", "B09_UPTANE_PQ", "PROPOSED"]:
        s = sub[sub.protocol == p].groupby("area").success_rate.mean() * 100
        st = style(p)
        a.plot(s.index, s.values, **{**st, "lw": st["lw"]}, label=NAMES[p])
    a.set_xlabel("Depot side length (m)")
    a.set_ylabel("Vehicles updated (%)")
    a.set_title("(b) Coverage gaps", loc="left")
    a.set_ylim(0, 105)
    a.legend(frameon=False, fontsize=6.5, loc="lower left")
    fig.tight_layout(w_pad=0.8)
    save(fig, "fig5_ablation_robust")


# ------------------------------------------------------------------ Fig. 6: Pareto
def fig_pareto():
    d = pd.read_csv(os.path.join(R, "test", "main.csv"))
    sec = pd.read_csv(os.path.join(R, "security", "security_matrix.csv")).set_index("protocol")
    viol = (sec.drop(columns=["benign"]) > 0).sum(axis=1)
    fig, ax = plt.subplots(1, 2, figsize=(W2, 2.4))
    for k, (sid, title) in enumerate([("T3_wifiMC_N100_16M", "(a) Depot, N=100, 16 MB"),
                                      ("T4_lte_N200_16M", "(b) LTE, N=200, 16 MB")]):
        a = ax[k]
        sub = d[d.sid == sid].groupby("protocol")[["makespan", "server_cpu_per_vehicle_ms"]].mean()
        pts = []
        for p, r in sub.iterrows():
            st = style(p)
            filled = viol.get(p, 0) == 0
            a.plot(r.server_cpu_per_vehicle_ms, r.makespan, marker=st["marker"] if st["marker"] != "." else "o",
                   ms=6 if p == "PROPOSED" else 4.5, color=st["color"], mfc=st["color"] if filled else "white",
                   ls="none", zorder=st["zorder"])
            pts.append((r.server_cpu_per_vehicle_ms, r.makespan, p))
            off = {"PROPOSED": (5, 4), "B01_SOURCE_REPRO": (-48, 5), "B09_UPTANE_PQ": (7, 3)}
            if p in off:
                a.annotate(NAMES[p].split(" (")[0], (r.server_cpu_per_vehicle_ms, r.makespan), fontsize=6.5,
                           xytext=off[p], textcoords="offset points", color=C_INK, ha="left")
        # Pareto front (minimise both)
        pts.sort()
        front, best = [], np.inf
        for x, y, p in pts:
            if y < best:
                front.append((x, y))
                best = y
        fx, fy = zip(*front)
        a.step(fx, fy, where="post", color=C_PROP, lw=0.8, ls=":")
        a.set_xscale("log")
        if k == 0:
            a.set_yscale("log")
        plain_log(a, "x")
        plain_log(a, "y") if k == 0 else None
        a.set_xlabel("Server CPU per vehicle (ms)")
        a.set_ylabel("Fleet makespan (s)")
        a.set_title(title, loc="left")
    fig.tight_layout(w_pad=1.0)
    save(fig, "fig6_pareto")


if __name__ == "__main__":
    for f in (fig_flow, fig_main, fig_difficult, fig_ablation, fig_pareto):
        try:
            f()
            print("ok", f.__name__)
        except Exception as e:  # partial data while experiments are still running
            print("skip", f.__name__, type(e).__name__, e)
