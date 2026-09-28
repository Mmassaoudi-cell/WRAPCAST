"""Stage 3: Optuna TPE tuning of the top candidates on DEV scenarios only.

Objective (pre-declared in MODEL_SELECTION_REPORT.md, minimised):
    J = mean_s [ makespan_s / makespan_s(ref) ] + 0.1 * mean_s [ srvcpu_s / srvcpu_s(ref) ]
where s ranges over the DEV scenarios, ref = the untuned default configuration of the same
candidate, both measured with DEV seeds {0, 1}.  Each trial must pass the security suite
(any violation -> J = +inf).
Usage: python experiments/tune_candidates.py C3_WRAPONCE C4_WRAPONCE_BATCH --trials 20
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import numpy as np
import optuna
import pandas as pd

from otasim import attacks as A
from otasim.experiment import run_cell
from otasim.protocols import WrapOnceOTA, build, KEMTLSOTA, TLS13OTA
from otasim.scenarios import dev_scenarios, with_seed

OUT = os.path.join(os.path.dirname(__file__), "..", "results", "selection")
SEEDS = [0, 1]


def factory(cand, params):
    if cand.startswith("C3") or cand.startswith("C4"):
        batch = params.get("batch") if cand.startswith("C4") else None
        return lambda: WrapOnceOTA(params.get("kem", "X-Wing"), params.get("dir_sig", "ML-DSA-65"), "ML-DSA-65",
                                   params.get("chunk", 65536), batch, False, short=cand)
    if cand.startswith("C2"):
        return lambda: KEMTLSOTA(params.get("kem", "X-Wing"), "ML-DSA-65", oem_sig="ML-DSA-65",
                                 record=params.get("chunk", 16384), short=cand)
    if cand.startswith("C1"):
        return lambda: TLS13OTA("X-Wing", "ML-DSA-65", "ML-DSA-44", oem_sig="ML-DSA-65",
                                record=params.get("chunk", 16384), short=cand)
    raise ValueError(cand)


def evaluate(cand, params, window=None, mc_rate=24.0):
    from dataclasses import replace
    rows = []
    for sc in dev_scenarios():
        for s in SEEDS:
            scs = replace(with_seed(sc, s), mc_rate=mc_rate)
            if window is not None:
                scs = replace(scs, batch_window=window, batch_max=params.get("batch", 64))
            rows.append(run_cell(cand, scs, proto_factory=factory(cand, params)))
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cands", nargs="+")
    ap.add_argument("--trials", type=int, default=20)
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    for cand in a.cands:
        ref = evaluate(cand, {}, 0.05 if cand.startswith("C4") else None)
        refm = ref.groupby("sid")[["makespan", "server_cpu_per_vehicle_ms"]].mean()
        log = []

        def objective(trial):
            params = {"chunk": trial.suggest_categorical("chunk", [16384, 65536, 262144])}
            window = None
            mc_rate = 24.0
            if cand.startswith(("C3", "C4")):
                params["dir_sig"] = trial.suggest_categorical("dir_sig", ["ML-DSA-44", "ML-DSA-65", "Falcon-512"])
                mc_rate = trial.suggest_categorical("mc_rate", [6.0, 12.0, 24.0])
            if cand.startswith("C4"):
                params["batch"] = trial.suggest_categorical("batch", [16, 64, 256])
                window = trial.suggest_categorical("window", [0.01, 0.05, 0.2])
            # security gate on a small package
            p = factory(cand, params)
            for t in A.TESTS:
                r = _sec(p, t)
                if r:
                    return float("inf")
            df = evaluate(cand, params, window, mc_rate)
            m = df.groupby("sid")[["makespan", "server_cpu_per_vehicle_ms"]].mean()
            J = float((m["makespan"] / refm["makespan"]).mean() +
                      0.1 * (m["server_cpu_per_vehicle_ms"] / refm["server_cpu_per_vehicle_ms"]).mean())
            log.append(dict(candidate=cand, trial=trial.number, J=J, window=window, mc_rate=mc_rate, **params,
                            **{f"makespan_{k}": v for k, v in m["makespan"].items()},
                            **{f"srvcpu_{k}": v for k, v in m["server_cpu_per_vehicle_ms"].items()}))
            pd.DataFrame(log).to_csv(os.path.join(OUT, f"tuning_{cand}.csv"), index=False)
            print(cand, trial.number, round(J, 4), params, window, flush=True)
            return J

        study = optuna.create_study(direction="minimize", sampler=optuna.samplers.TPESampler(seed=0))
        study.optimize(objective, n_trials=a.trials)
        with open(os.path.join(OUT, f"best_{cand}.json"), "w") as f:
            json.dump(dict(best_params=study.best_params, best_J=study.best_value), f, indent=2)


def _sec(pf, test):
    """Run one conformance test with a custom protocol factory; True = violation."""
    import random
    from otasim.common import make_package
    p = pf()
    p.setup(2)
    pkg = make_package(256 * 1024, 2)
    p.release(pkg)
    import otasim.attacks as AA
    orig = AA.build
    AA.build = lambda name: (lambda q: (q))(pf())
    try:
        r = AA.run_test("custom", test, seed=7)
    finally:
        AA.build = orig
    return bool(r.get("false_reject") if test == "benign" else r["violation"])


if __name__ == "__main__":
    main()
