"""Every number quoted in the manuscript text is a macro computed here from result files.
Output: paper/results_macros.tex and results/manuscript_numbers.csv (audit trail)."""
import os

import numpy as np
import pandas as pd

ROOT = os.path.join(os.path.dirname(__file__), "..")
R = os.path.join(ROOT, "results")
BENCH = ["B01_SOURCE_REPRO", "B02_SRC_DH2048", "B03_SRC_RSA2048", "B04_SRC_McE_SPHINCS", "B05_SRC_FALCON",
         "B06_TLS13_CLASSIC", "B07_TLS13_PQHYBRID", "B08_UPTANE_CLASSIC", "B09_UPTANE_PQ", "B10_KEMTLS"]
ATT = ["tamper_chunk", "reorder_chunks", "truncate", "replay_server", "misdelivery", "malicious_server",
       "rollback_server", "stale_metadata", "unregistered"]
M = {}


def put(name, value, fmt="{:.1f}", source=""):
    M[name] = (fmt.format(value) if not isinstance(value, str) else value, source)


def main():
    d = pd.read_csv(os.path.join(R, "test", "main.csv"))
    mk = d.groupby(["sid", "protocol"]).makespan.mean()
    cpu = d.groupby(["sid", "protocol"]).server_cpu_per_vehicle_ms.mean()

    def best_bench(sid, series=mk):
        s = series.loc[sid]
        s = s[s.index.isin(BENCH)]
        return s.idxmin(), s.min()

    # ---- depot multicast
    for n, w in [(20, "twenty"), (60, "sixty"), (100, "hundred")]:
        sid = f"T3_wifiMC_N{n}_16M"
        b, v = best_bench(sid)
        put(f"mcSpeedupN{w}", v / mk.loc[(sid, "PROPOSED")], "{:.1f}", f"main.csv {sid} best={b}")
        put(f"mcPropN{w}", mk.loc[(sid, "PROPOSED")], "{:.1f}", f"main.csv {sid} PROPOSED")
        put(f"mcBestN{w}", v, "{:.0f}", f"main.csv {sid} {b}")
    # ---- unicast depot and cellular: relative makespan vs best benchmark
    for sid, w in [("T1_wifi_N100_4K", "TOne"), ("T2_wifi_N100_16M", "TTwo"), ("T4_lte_N200_16M", "TFour"),
                   ("T5_5g_N1000_64M", "TFive"), ("T6_lteOutage_N100_64M", "TSix")]:
        if sid not in mk.index.get_level_values(0):
            continue
        b, v = best_bench(sid)
        put(f"relMk{w}", (mk.loc[(sid, "PROPOSED")] / v - 1) * 100, "{:+.1f}", f"main.csv {sid} vs {b}")
        put(f"propMk{w}", mk.loc[(sid, "PROPOSED")], "{:.2f}" if mk.loc[(sid, "PROPOSED")] < 10 else "{:.0f}", sid)
        put(f"srcMk{w}", mk.loc[(sid, "B01_SOURCE_REPRO")], "{:.2f}" if mk.loc[(sid, "B01_SOURCE_REPRO")] < 10 else "{:.0f}", sid)
        put(f"propCpu{w}", cpu.loc[(sid, "PROPOSED")], "{:.2f}", sid)
        put(f"srcCpu{w}", cpu.loc[(sid, "B01_SOURCE_REPRO")], "{:.1f}", sid)
        put(f"uptCpu{w}", cpu.loc[(sid, "B09_UPTANE_PQ")], "{:.1f}", sid)
        bc, vc = best_bench(sid, cpu)
        put(f"cpuFactor{w}", vc / cpu.loc[(sid, "PROPOSED")], "{:.0f}", f"{sid} best cpu bench={bc}")
    put("srvReductionTwoSixteen", cpu.loc[("T2_wifi_N100_16M", "B01_SOURCE_REPRO")] / cpu.loc[("T2_wifi_N100_16M", "PROPOSED")],
        "{:.0f}", "main.csv T2 N100 cpu B01/PROPOSED")
    # ---- W/T/L
    w = pd.read_csv(os.path.join(ROOT, "BENCHMARK_WTL.csv"))
    for metric, name in [("makespan", "Mk"), ("lat_mean", "Lat"), ("server_cpu_per_vehicle_ms", "Cpu"), ("auth_lat_mean", "Auth")]:
        t = w[w.metric == metric]
        put(f"wins{name}", int(t.wins.sum()), "{:d}", "BENCHMARK_WTL.csv")
        put(f"ties{name}", int(t.ties.sum()), "{:d}", "BENCHMARK_WTL.csv")
        put(f"losses{name}", int(t.losses.sum()), "{:d}", "BENCHMARK_WTL.csv")
        put(f"cells{name}", int(t.scenarios.sum()), "{:d}", "BENCHMARK_WTL.csv")
    t = w[w.metric == "makespan"]
    put("WTLsummary", f"{int(t.wins.sum())}/{int(t.ties.sum())}/{int(t.losses.sum())}", source="BENCHMARK_WTL.csv makespan")
    # ---- security
    s = pd.read_csv(os.path.join(R, "security", "security_matrix.csv")).set_index("protocol")
    put("srcViolations", int((s.loc["B01_SOURCE_REPRO", ATT] > 0).sum()), "{:d}", "security_matrix.csv")
    put("tlsViolations", int((s.loc["B07_TLS13_PQHYBRID", ATT] > 0).sum()), "{:d}", "security_matrix.csv")
    put("secSeeds", int(pd.read_csv(os.path.join(R, "security", "security_raw.csv")).groupby(["protocol", "test"]).size().min()), "{:d}", "security_raw.csv")
    # ---- ablation
    a = pd.read_csv(os.path.join(R, "test", "ablation.csv"))
    g = a.groupby(["sid", "protocol"])[["makespan", "server_cpu_per_vehicle_ms", "auth_lat_mean", "wire_hs_bytes"]].mean()
    T3, T4 = "T3_wifiMC_N60_16M", "T4_lte_N200_16M"
    put("ablEncOnceCpuFactor", g.loc[(T4, "ABL_per_vehicle_content"), "server_cpu_per_vehicle_ms"] / g.loc[(T4, "PROPOSED"), "server_cpu_per_vehicle_ms"], "{:.0f}", "ablation T4")
    put("ablEncOnceMkFactor", g.loc[(T3, "ABL_per_vehicle_content"), "makespan"] / g.loc[(T3, "PROPOSED"), "makespan"], "{:.1f}", "ablation T3")
    for sid, nm in [(T3, "Three"), (T4, "Four")]:
        put(f"ablBatchCpu{nm}", (1 - g.loc[(sid, "PROPOSED"), "server_cpu_per_vehicle_ms"] / g.loc[(sid, "ABL_no_batch"), "server_cpu_per_vehicle_ms"]) * 100, "{:.0f}", f"ablation {sid}")
    put("ablHybridExtraMs", g.loc[(T4, "PROPOSED"), "server_cpu_per_vehicle_ms"] - g.loc[(T4, "ABL_pure_mlkem"), "server_cpu_per_vehicle_ms"], "{:.2f}", "ablation T4")
    put("ablHashKB", g.loc[(T4, "PROPOSED"), "wire_hs_bytes"] / 1024, "{:.1f}", "ablation T4")
    put("ablDigestKB", g.loc[(T4, "ABL_digest_only"), "wire_hs_bytes"] / 1024, "{:.1f}", "ablation T4")
    put("ablHashMkPct", (g.loc[(T3, "PROPOSED"), "makespan"] / g.loc[(T3, "ABL_digest_only"), "makespan"] - 1) * 100, "{:.1f}", "ablation T3")
    put("ablHashAuthMs", g.loc[(T3, "PROPOSED"), "auth_lat_mean"] * 1e3, "{:.0f}", "ablation T3")
    put("ablDigestAuthMs", g.loc[(T3, "ABL_digest_only"), "auth_lat_mean"] * 1e3, "{:.0f}", "ablation T3")
    put("ablHashAuthMsFour", g.loc[(T4, "PROPOSED"), "auth_lat_mean"] * 1e3, "{:.0f}", "ablation T4")
    put("ablDigestAuthMsFour", g.loc[(T4, "ABL_digest_only"), "auth_lat_mean"] * 1e3, "{:.0f}", "ablation T4")
    put("ablLfiveCpuPct", (g.loc[(T4, "PM_level5"), "server_cpu_per_vehicle_ms"] / g.loc[(T4, "PROPOSED"), "server_cpu_per_vehicle_ms"] - 1) * 100, "{:.0f}", "ablation T4")
    put("ablMldsaCpuPct", (g.loc[(T4, "SENS_director_mldsa44"), "server_cpu_per_vehicle_ms"] / g.loc[(T4, "PROPOSED"), "server_cpu_per_vehicle_ms"] - 1) * 100, "{:+.0f}", "ablation T4")
    # ---- insider mirror
    im = pd.read_csv(os.path.join(R, "test", "insider_mirror.csv"))
    put("insiderRejectPct", im.rejected.mean() * 100, "{:.0f}", "insider_mirror.csv")
    put("insiderPropFrac", im[im.variant == "PROPOSED"].frac_before_reject.mean() * 100, "{:.0f}", "insider_mirror.csv")
    put("insiderDigestFrac", im[im.variant == "ABL_digest_only"].frac_before_reject.mean() * 100, "{:.0f}", "insider_mirror.csv")
    # ---- robustness
    rb = pd.read_csv(os.path.join(R, "test", "robust.csv"))
    rm = rb.groupby(["sid", "protocol"]).makespan.mean()
    rs = rb.groupby(["sid", "protocol"]).success_rate.mean()
    for fl, nm in [("0.0", "Zero"), ("0.2", "Twenty")]:
        uni = rm.loc[f"R1_wifi_loss{fl}"]
        uni = uni[uni.index.isin(BENCH)].min()
        put(f"lossSpeedup{nm}", uni / rm.loc[(f"R1m_wifiMC_loss{fl}", "PROPOSED")], "{:.1f}", "robust.csv R1/R1m")
    put("gapSrcSuccess", rs.loc[("R2_wifi_area140", "B01_SOURCE_REPRO")] * 100, "{:.0f}", "robust.csv R2 area140")
    put("gapPropSuccess", rs.loc[("R2_wifi_area140", "PROPOSED")] * 100, "{:.0f}", "robust.csv R2 area140")
    put("gapSrcMk", rm.loc[("R2_wifi_area140", "B01_SOURCE_REPRO")], "{:.0f}", "robust.csv")
    put("gapPropMk", rm.loc[("R2_wifi_area140", "PROPOSED")], "{:.0f}", "robust.csv")
    put("outSrcMk", rm.loc[("R4_lte_outage_up30", "B01_SOURCE_REPRO")], "{:.0f}", "robust.csv")
    put("outPropMk", rm.loc[("R4_lte_outage_up30", "PROPOSED")], "{:.0f}", "robust.csv")
    # ---- scaling
    sc = pd.read_csv(os.path.join(R, "test", "scaling.csv"))
    sct = sc.groupby(["sid", "protocol"]).server_cpu_total.mean()
    S = "S1_5g_N1000_16M"
    put("scalePropCpuS", sct.loc[(S, "PROPOSED")], "{:.2f}", "scaling.csv")
    put("scaleUptCpuS", sct.loc[(S, "B09_UPTANE_PQ")], "{:.1f}", "scaling.csv")
    put("scaleSrcCpuS", sct.loc[(S, "B01_SOURCE_REPRO")], "{:.1f}", "scaling.csv")
    scm = sc.groupby(["sid", "protocol"]).makespan.mean()
    big = "S2_wifi_N40_262144K"
    bb = scm.loc[big]
    bb = bb[bb.index.isin(BENCH)].min()
    put("bigPkgRelMk", (scm.loc[(big, "PROPOSED")] / bb - 1) * 100, "{:+.2f}", "scaling.csv S2 256MB")
    put("bigPkgPropCpuS", sct.loc[(big, "PROPOSED")], "{:.2f}", "scaling.csv S2 256MB")
    bc = sct.loc[big]
    put("bigPkgBenchCpuMin", bc[bc.index.isin(BENCH)].min(), "{:.0f}", "scaling.csv S2 256MB")
    put("bigPkgBenchCpuMax", bc[bc.index.isin(BENCH)].max(), "{:.0f}", "scaling.csv S2 256MB")
    put("bigPkgHashKB", 256 * 1024 * 1024 / 16384 * 32 / 1024, "{:.0f}", "32 B x (256 MB / 16 KB chunks)")
    thr = 1.0 /(sc[(sc.sid == S) & (sc.protocol == "PROPOSED")].server_cpu_per_vehicle_ms.mean() / 1e3)
    put("propAuthPerCoreSec", thr, "{:,.0f}", "scaling.csv: 1/server CPU per vehicle")
    # ---- flow profile
    fp = pd.read_csv(os.path.join(R, "test", "flow_profile.csv"))
    pre = fp[~fp.bulk & (fp.label != "install_report")].groupby(["protocol", "rep"]).bytes.sum().groupby("protocol").mean()
    put("preKBProp", pre["PROPOSED"] / 1024, "{:.1f}", "flow_profile.csv")
    put("preKBUpt", pre["B09_UPTANE_PQ"] / 1024, "{:.1f}", "flow_profile.csv")
    put("preKBSrc", pre["B01_SOURCE_REPRO"] / 1024, "{:.1f}", "flow_profile.csv")
    put("releaseMs", fp[fp.protocol == "PROPOSED"].release_cpu_ms.iloc[0], "{:.0f}", "flow_profile.csv")
    vb = fp[fp.bulk].groupby("protocol").final_vehicle_cpu_ms.mean()
    # ---- reproduction
    pv = pd.read_csv(os.path.join(R, "reproduction", "published_vs_reproduced.csv"))
    r100 = pv[pv.N == 100].set_index(["item", "protocol"]).ratio
    put("reproHsRatio", r100[("Fig3 handshake (ms)", "B01_SOURCE_REPRO")], "{:.0f}", "published_vs_reproduced.csv")
    put("reproFwRatio", r100[("Fig6 framework latency (ms)", "B01_SOURCE_REPRO")], "{:.2f}", "published_vs_reproduced.csv")
    put("reproDecRatio", r100[("Fig4 decryption (ms)", "B01_SOURCE_REPRO")], "{:.2f}", "published_vs_reproduced.csv")
    put("reproMcERatio", r100[("Fig3 handshake (ms)", "B04_SRC_McE_SPHINCS")], "{:.0f}", "published_vs_reproduced.csv")
    ps = pd.read_csv(os.path.join(R, "reproduction", "per_session.csv"))
    put("reproHsPerVehMs", ps[(ps.protocol == "B01_SOURCE_REPRO") & (ps.pkg_size == 4096)].handshake_cpu_s.mean() * 1e3, "{:.2f}", "per_session.csv")
    rk = pd.read_csv(os.path.join(R, "reproduction", "rsa_keygen_diagnostic.csv")).groupby("impl").seconds.mean()
    put("rsaPyS", rk[[i for i in rk.index if "pure" in i][0]], "{:.2f}", "rsa_keygen_diagnostic.csv")
    put("rsaOsslS", rk[[i for i in rk.index if "OpenSSL" in i][0]], "{:.3f}", "rsa_keygen_diagnostic.csv")

    lines = ["% generated by analysis/make_macros.py from result CSVs -- do not edit by hand"]
    for k, (v, src) in M.items():
        lines.append(f"\\newcommand{{\\{k}}}{{{v}}}% {src}")
    open(os.path.join(ROOT, "paper", "results_macros.tex"), "w", encoding="utf-8").write("\n".join(lines) + "\n")
    pd.DataFrame([dict(macro=k, value=v, source=s) for k, (v, s) in M.items()]).to_csv(
        os.path.join(R, "manuscript_numbers.csv"), index=False)
    print(len(M), "macros")


if __name__ == "__main__":
    main()
