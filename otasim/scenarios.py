"""Pre-registered scenario split.  DEV scenarios/seeds are the only ones used for candidate
screening and tuning; TEST scenarios/seeds are run once, after FINAL_MODEL_CONFIG.yaml is frozen.

DEV and TEST differ in fleet sizes, package sizes, channel parameters and seeds, so that no
TEST scenario is a re-run of a DEV scenario.
"""
from __future__ import annotations

from .netsim import Scenario

MB = 1 << 20
DEV_SEEDS = [0, 1, 2]
TEST_SEEDS = list(range(100, 110))
ROBUST_SEEDS = list(range(200, 205))

LTE = dict(channel="cellular", dl_median_mbps=20.0, ul_median_mbps=5.0, rtt_ms=50.0, pkt_loss=1e-3)
NR5G = dict(channel="cellular", dl_median_mbps=150.0, ul_median_mbps=30.0, rtt_ms=20.0, pkt_loss=1e-4)


def dev_scenarios():
    return [
        Scenario("D1_wifi_N10_256K", n_vehicles=10, pkg_size=256 * 1024, split="dev"),
        Scenario("D2_wifi_N30_4M", n_vehicles=30, pkg_size=4 * MB, split="dev"),
        Scenario("D3_wifiMC_N30_4M", n_vehicles=30, pkg_size=4 * MB, multicast=True, split="dev"),
        Scenario("D4_lte_N50_4M", n_vehicles=50, pkg_size=4 * MB, split="dev", **LTE),
        Scenario("D5_lteOutage_N30_4M", n_vehicles=30, pkg_size=4 * MB, split="dev", outage_mean_up=60.0,
                 outage_mean_down=10.0, **LTE),
    ]


def test_main():
    out = []
    for n in (20, 40, 60, 80, 100):  # the source paper's own setting (4 KB, 802.11g)
        out.append(Scenario(f"T1_wifi_N{n}_4K", n_vehicles=n, pkg_size=4096, split="test"))
    for n in (20, 60, 100):
        out.append(Scenario(f"T2_wifi_N{n}_16M", n_vehicles=n, pkg_size=16 * MB, split="test"))
        out.append(Scenario(f"T3_wifiMC_N{n}_16M", n_vehicles=n, pkg_size=16 * MB, multicast=True, split="test"))
    out.append(Scenario("T4_lte_N200_16M", n_vehicles=200, pkg_size=16 * MB, split="test", **LTE))
    out.append(Scenario("T5_5g_N1000_64M", n_vehicles=1000, pkg_size=64 * MB, split="test", **NR5G))
    out.append(Scenario("T6_lteOutage_N100_64M", n_vehicles=100, pkg_size=64 * MB, split="test",
                        outage_mean_up=120.0, outage_mean_down=15.0, **LTE))
    return out


def test_robustness():
    out = []
    for fl in (0.0, 0.05, 0.1, 0.2):
        out.append(Scenario(f"R1_wifi_loss{fl}", n_vehicles=50, pkg_size=16 * MB, frame_loss=fl, split="robust"))
        out.append(Scenario(f"R1m_wifiMC_loss{fl}", n_vehicles=50, pkg_size=16 * MB, frame_loss=fl, multicast=True,
                            split="robust"))
    for area in (100.0, 120.0, 140.0):  # coverage gaps -> link interruptions
        out.append(Scenario(f"R2_wifi_area{int(area)}", n_vehicles=50, pkg_size=16 * MB, area=area, split="robust"))
    for pl in (1e-4, 1e-2):
        out.append(Scenario(f"R3_lte_loss{pl}", n_vehicles=100, pkg_size=16 * MB, split="robust",
                            **{**LTE, "pkt_loss": pl}))
    for up in (30.0, 60.0):
        out.append(Scenario(f"R4_lte_outage_up{int(up)}", n_vehicles=100, pkg_size=16 * MB, split="robust",
                            outage_mean_up=up, outage_mean_down=15.0, **LTE))
    return out


def test_scaling():
    out = []
    for n in (100, 300, 1000, 3000):
        out.append(Scenario(f"S1_5g_N{n}_16M", n_vehicles=n, pkg_size=16 * MB, split="scaling", **NR5G))
    for sz in (256 * 1024, 1 * MB, 4 * MB, 64 * MB, 256 * MB):
        out.append(Scenario(f"S2_wifi_N40_{sz // 1024}K", n_vehicles=40, pkg_size=sz, split="scaling"))
    return out


def with_seed(sc: Scenario, seed: int) -> Scenario:
    from dataclasses import replace

    return replace(sc, seed=seed)
