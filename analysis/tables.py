"""IEEE LaTeX tables generated from result CSVs -> paper/tab_*.tex."""
import os

import numpy as np
import pandas as pd

ROOT = os.path.join(os.path.dirname(__file__), "..")
R = os.path.join(ROOT, "results")
P = os.path.join(ROOT, "paper")

NAMES = {
    "PROPOSED": r"\WC{} (ours)", "B01_SOURCE_REPRO": r"B01 Kumar \emph{et al.}~\cite{kumar2026pqota}",
    "B02_SRC_DH2048": "B02 B01-DH2048", "B03_SRC_RSA2048": "B03 B01-RSA2048", "B04_SRC_McE_SPHINCS": "B04 B01-McE+SPHINCS+",
    "B05_SRC_FALCON": "B05 B01-Falcon", "B06_TLS13_CLASSIC": "B06 TLS 1.3", "B07_TLS13_PQHYBRID": "B07 PQ-TLS 1.3",
    "B08_UPTANE_CLASSIC": "B08 Uptane", "B09_UPTANE_PQ": "B09 PQ-Uptane", "B10_KEMTLS": "B10 KEMTLS",
}
ORDER = ["B01_SOURCE_REPRO", "B02_SRC_DH2048", "B03_SRC_RSA2048", "B04_SRC_McE_SPHINCS", "B05_SRC_FALCON",
         "B06_TLS13_CLASSIC", "B07_TLS13_PQHYBRID", "B08_UPTANE_CLASSIC", "B09_UPTANE_PQ", "B10_KEMTLS", "PROPOSED"]
ATTACKS = ["tamper_chunk", "reorder_chunks", "truncate", "replay_server", "misdelivery", "malicious_server",
           "rollback_server", "stale_metadata", "unregistered"]


def fmt(x, sd=None):
    if pd.isna(x):
        return "--"
    if x >= 100:
        s = f"{x:.0f}"
    elif x >= 10:
        s = f"{x:.1f}"
    elif x >= 1:
        s = f"{x:.2f}"
    else:
        s = f"{x:.3f}"
    return s


def tab_main():
    d = pd.read_csv(os.path.join(R, "test", "main.csv"))
    fp = pd.read_csv(os.path.join(R, "test", "flow_profile.csv"))
    pre = fp[~fp.bulk & (fp.label != "install_report")].groupby(["protocol", "rep"]).bytes.sum().groupby("protocol").mean()
    sec = pd.read_csv(os.path.join(R, "security", "security_matrix.csv")).set_index("protocol")
    cols = [("T1_wifi_N100_4K", "T1"), ("T2_wifi_N100_16M", "T2"), ("T3_wifiMC_N100_16M", "T3"),
            ("T4_lte_N200_16M", "T4"), ("T5_5g_N1000_64M", "T5"), ("T6_lteOutage_N100_64M", "T6")]
    m = d.groupby(["protocol", "sid"]).makespan.agg(["mean", "std"])
    cpu = d[d.sid == "T4_lte_N200_16M"].groupby("protocol").server_cpu_per_vehicle_ms.mean()
    best = {sid: m.xs(sid, level="sid")["mean"].min() for sid, _ in cols if sid in m.index.get_level_values(1)}
    lines = [r"\begin{table*}[t]", r"\centering",
             r"\caption{Held-out results (mean $\pm$ s.d. over 10 seeds). Makespan in seconds for $N=100$ (T1--T3), $N=200$ (T4), $N=1000$ (T5), $N=100$ (T6); server CPU per vehicle in T4; pre-content bytes per vehicle for a 16-MB image; conformance violations out of 9 attack classes. Best mean per column in bold.}",
             r"\label{tab:main}", r"\footnotesize", r"\setlength{\tabcolsep}{3pt}",
             r"\begin{tabular}{@{}l" + "r" * len(cols) + "rrr@{}}", r"\toprule",
             r" & \multicolumn{" + str(len(cols)) + r"}{c}{Fleet makespan (s)} & Server CPU & Pre-content & Viol. \\",
             r"\cmidrule(lr){2-" + str(len(cols) + 1) + "}",
             "Method & " + " & ".join(f"{c}" for _, c in cols) + r" & (ms/veh.) & (KB) & (/9) \\", r"\midrule"]
    for p in ORDER:
        cells = []
        for sid, _ in cols:
            if (p, sid) in m.index:
                mu, sd = m.loc[(p, sid)]
                s = f"{fmt(mu)}$\\pm${fmt(sd if not pd.isna(sd) else 0)}"
                if np.isclose(mu, best[sid]):
                    s = r"\textbf{" + s + "}"
            else:
                s = "--"
            cells.append(s)
        v = int((sec.loc[p, ATTACKS] > 0).sum()) if p in sec.index else "--"
        row = NAMES[p] + " & " + " & ".join(cells) + f" & {fmt(cpu.get(p, np.nan))} & {pre.get(p, np.nan) / 1024:.1f} & {v} \\\\"
        if p == "PROPOSED":
            lines.append(r"\midrule")
        lines.append(row)
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    open(os.path.join(P, "tab_main.tex"), "w", encoding="utf-8").write("\n".join(lines) + "\n")


def tab_wtl():
    w = pd.read_csv(os.path.join(ROOT, "BENCHMARK_WTL.csv"))
    mets = [("makespan", "Makespan"), ("lat_mean", "Latency"), ("server_cpu_per_vehicle_ms", "CPU"),
            ("auth_lat_mean", "Auth.")]
    lines = [r"\begin{table}[t]", r"\centering",
             r"\caption{Wins/ties/losses of \WC{} against each benchmark over the 14 held-out scenarios (Holm-corrected paired Wilcoxon, $\alpha=0.05$, $\geq$1\% difference).}",
             r"\label{tab:wtl}", r"\footnotesize", r"\setlength{\tabcolsep}{3pt}",
             r"\begin{tabular}{@{}l" + "c" * len(mets) + "@{}}", r"\toprule",
             "Benchmark & " + " & ".join(n for _, n in mets) + r" \\", r"\midrule"]
    tot = {k: [0, 0, 0] for k, _ in mets}
    for b in ORDER[:-1]:
        cells = []
        for k, _ in mets:
            r = w[(w.benchmark == b) & (w.metric == k)]
            if r.empty:
                cells.append("--")
                continue
            r = r.iloc[0]
            cells.append(f"{r.wins}/{r.ties}/{r.losses}")
            tot[k] = [tot[k][0] + r.wins, tot[k][1] + r.ties, tot[k][2] + r.losses]
        lines.append(NAMES[b].split("~")[0].replace(r" \emph{et al.}", "") + " & " + " & ".join(cells) + r" \\")
    lines.append(r"\midrule")
    lines.append("Total & " + " & ".join(f"{a}/{b}/{c}" for a, b, c in tot.values()) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    open(os.path.join(P, "tab_wtl.tex"), "w", encoding="utf-8").write("\n".join(lines) + "\n")


def tab_security():
    sec = pd.read_csv(os.path.join(R, "security", "security_matrix.csv")).set_index("protocol")
    hdr = ["Tamper", "Reorder", "Truncate", "Replay", "Misdeliv.", "Mal. server", "Rollback", "Stale", "Unregist.", "FRR"]
    lines = [r"\begin{table}[t]", r"\centering",
             r"\caption{Conformance suite (20 seeds per cell): fraction of trials in which the vehicle accepted a non-genuine or non-latest update (attacks) or rejected an honest one (FRR). ``0'' = never.}",
             r"\label{tab:security}", r"\scriptsize", r"\setlength{\tabcolsep}{1.6pt}",
             r"\begin{tabular}{@{}l" + "c" * len(hdr) + "@{}}", r"\toprule",
             "Method & " + " & ".join(r"\rotatebox{70}{" + h + "}" for h in hdr) + r" \\", r"\midrule"]
    for p in ORDER:
        if p not in sec.index:
            continue
        vals = [sec.loc[p, a] for a in ATTACKS] + [sec.loc[p, "benign"]]
        cells = ["0" if v == 0 else (r"\textbf{1}" if v == 1 else f"{v:.2f}") for v in vals]
        name = NAMES[p].split("~")[0].replace(r" \emph{et al.}", "")
        if p == "PROPOSED":
            lines.append(r"\midrule")
        lines.append(name + " & " + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    open(os.path.join(P, "tab_security.tex"), "w", encoding="utf-8").write("\n".join(lines) + "\n")


ABL = [("PROPOSED", r"\WC{} (full)"), ("ABL_per_vehicle_content", "$-$ encrypt-once"),
       ("ABL_no_batch", "$-$ batching"), ("ABL_digest_only", "$-$ hash list"),
       ("ABL_pure_mlkem", "$-$ hybrid KEM"), ("ABL_online_manifest", "$-$ offline OEM key"),
       ("ABL_no_report", "$-$ key confirm."), ("PM_level5", "NIST level 5"),
       ("SENS_director_mldsa44", "Director ML-DSA-44")]


def tab_ablation():
    d = pd.read_csv(os.path.join(R, "test", "ablation.csv"))
    sec = pd.read_csv(os.path.join(R, "security", "security_matrix.csv")).set_index("protocol")
    g = d.groupby(["protocol", "sid"])[["makespan", "server_cpu_per_vehicle_ms", "auth_lat_mean", "wire_hs_bytes"]].mean()
    lines = [r"\begin{table}[t]", r"\centering",
             r"\caption{Ablation on held-out scenarios (5 seeds): makespan and authorization latency in depot multicast (T3, $N=60$, shared 802.11g medium), server CPU per vehicle and authorization latency in LTE (T4, $N=200$, dedicated per-vehicle link), pre-content bytes (16 MB), and conformance violations.}",
             r"\label{tab:ablation}", r"\scriptsize", r"\setlength{\tabcolsep}{1.5pt}",
             r"\begin{tabular}{@{}p{0.155\columnwidth}rrrrrc@{}}", r"\toprule",
             r"Variant & \shortstack{T3 mk.\\(s)} & \shortstack{T3 auth.\\(ms)} & \shortstack{T4 CPU\\(ms)} & \shortstack{T4 auth.\\(ms)} & KB & V. \\", r"\midrule"]
    for p, name in ABL:
        try:
            mk = g.loc[(p, "T3_wifiMC_N60_16M"), "makespan"]
            au3 = g.loc[(p, "T3_wifiMC_N60_16M"), "auth_lat_mean"] * 1e3
            cpu = g.loc[(p, "T4_lte_N200_16M"), "server_cpu_per_vehicle_ms"]
            au = g.loc[(p, "T4_lte_N200_16M"), "auth_lat_mean"] * 1e3
            by = g.loc[(p, "T4_lte_N200_16M"), "wire_hs_bytes"] / 1024
        except KeyError:
            continue
        v = int((sec.loc[p, ATTACKS] > 0).sum()) if p in sec.index else "--"
        lines.append(f"{name} & {fmt(mk)} & {fmt(au3)} & {fmt(cpu)} & {fmt(au)} & {by:.1f} & {v} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    open(os.path.join(P, "tab_ablation.tex"), "w", encoding="utf-8").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    for f in (tab_main, tab_wtl, tab_security, tab_ablation):
        try:
            f()
            print("ok", f.__name__)
        except Exception as e:
            print("skip", f.__name__, type(e).__name__, e)
