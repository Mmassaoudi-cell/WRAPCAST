# MODEL (PROTOCOL) SELECTION REPORT

Internal development record, not paper content. Everything below used **DEV scenarios and DEV seeds only** (`otasim/scenarios.py`: D1–D5, seeds 0–2). No TEST scenario or seed was run before `FINAL_MODEL_CONFIG.yaml` was frozen (SHA-256 in `FINAL_MODEL_CONFIG.sha256`).

Raw data: `results/selection/screening.csv`, `candidate_security.csv`, `tuning_C3_WRAPONCE.csv`, `tuning_C4_WRAPONCE_BATCH.csv`, `best_*.json`, `confirmation_seed2.csv`.

## Stage 1 — smoke test (seed 0)

All four candidates (C1 SIGMA-PQ, C2 KEM-AUTH, C3 WRAP-ONCE, C4 WRAP-ONCE-BATCH) completed every DEV scenario with success rate 1.0. None failed to "converge" (all sessions honest-accepted), and none needed unreasonable resources. No candidate was eliminated at this stage.

Security gate (`candidate_security.csv`, 10 tests × 5 seeds per candidate): 0 violations, 0 false rejections for all four.

## Stage 2 — DEV screening, seeds {0,1,2} (means over seeds)

| DEV scenario | Metric | C1 | C2 | C3 | C4 |
|---|---|---:|---:|---:|---:|
| D1 Wi-Fi N=10, 256 KB | makespan (s) | 1.783 | 1.766 | **1.659** | 1.714 |
| | server CPU / vehicle (ms) | 1.35 | 1.06 | **0.77** | 0.81 |
| D2 Wi-Fi N=30, 4 MB | makespan (s) | 90.94 | 90.98 | **90.46** | 90.53 |
| | server CPU / vehicle (ms) | 12.43 | 12.78 | 0.82 | **0.54** |
| D3 Wi-Fi multicast N=30, 4 MB | makespan (s) | 90.95 | 90.98 | 53.72 | **52.94** |
| D4 LTE N=50, 4 MB | makespan (s) | 6.99 | 7.07 | **6.84** | 6.87 |
| | server CPU / vehicle (ms) | 12.62 | 14.00 | 0.76 | **0.43** |
| D5 LTE outages N=30, 4 MB | makespan (s) | 19.23 | 19.18 | **19.10** | 19.20 |
| all | handshake/authorization bytes | 23 722 | 20 159 | 8 366–10 286 | 8 635–10 555 |

Reading:
* On the unicast makespan the four candidates are within about 1–5% of each other. The channel dominates, and per-vehicle transfer volume is identical.
* C1/C2 need about 12–14 ms of server CPU per vehicle for a 4 MB image (per-vehicle encryption), against 0.4–0.8 ms for C3/C4, whose server work does not depend on image size.
* Only C3/C4 can use the depot multicast (D3): −41% makespan even at the untuned 24 Mbps multicast rate.
* C1/C2 send 2–2.8× more handshake bytes (certificate chains).

**Stage-2 decision:** C3 and C4 advance to tuning. C1 is dominated by C3 on every metric. C2 is dominated by C3 on every metric except authorization latency in D1.

## Stage 3 — Optuna TPE tuning (20 trials each, DEV seeds {0,1})

Search space: chunk ∈ {16, 64, 256 KB}; Director signature ∈ {ML-DSA-44, ML-DSA-65, Falcon-512}; multicast PHY rate ∈ {6, 12, 24 Mbps}; C4 additionally batch size B ∈ {16, 64, 256} and window Δ ∈ {10, 50, 200 ms}.
Objective (declared before tuning): J = mean_s(makespan/makespan_ref) + 0.1·mean_s(srvCPU/srvCPU_ref), where ref = the candidate's untuned default. Each trial must also pass the 10-test security gate.

| Candidate | Best trial | J | chunk | Director sig | mc rate | B | Δ |
|---|---|---:|---:|---|---:|---:|---:|
| C3 | 13 | 0.8982 | 256 KB | Falcon-512 | 6 | – | – |
| C4 | 17 | **0.8953** | 16 KB | Falcon-512 | 6 | 16 | 0.01 s |
| C4 | 1 | 0.8967 | 256 KB | Falcon-512 | 6 | 64 | 0.01 s |

Consistent findings: the 6 Mbps multicast basic rate always wins, because its coverage reaches the whole depot area while 24 Mbps reaches only ≈31 m. Falcon-512 always wins among Director signatures (655 B vs 2420/3309 B signatures in every authorization response; vehicles only verify).

## Final selection rule (declared before the confirmation run and before any TEST run)

Configurations within 0.5% of the best J are treated as tied. Among tied configurations, prefer the smaller chunk size (lower vehicle RAM buffer), then the lower server CPU per vehicle.
Tied set: C4-t17 (16 KB), C4-t1 (256 KB), C3-t13 (256 KB), C3-t11 (256 KB) → **C4-t17 selected**.

## Confirmation on DEV seed 2 (unseen by the tuner)

| DEV scenario | C4-t17 | C4-t1 | C3-t13 | C3-t11 |
|---|---:|---:|---:|---:|
| D1 makespan (s) | 1.874 | 1.869 | 1.853 | 1.853 |
| D2 | 91.93 | 91.58 | 91.65 | 91.65 |
| D3 (multicast, 6 Mbps) | 9.12 | 9.04 | 9.03 | 9.03 |
| D4 | 6.477 | 6.461 | 6.451 | 6.451 |
| D5 | 15.45 | 15.43 | 15.41 | 15.41 |
| server CPU / vehicle (ms, mean) | 0.47 | 0.50 | 0.49 | 0.50 |

All within ≈1%. No failure or seed collapse (success 1.0).

**Honest caveat recorded before TEST:** once the Director signs with Falcon-512, batching (C4 vs C3) cuts server CPU only slightly on DEV (≈0.47 vs ≈0.49 ms per vehicle). The TEST ablation (`ABL_no_batch`) will quantify whether batching is a meaningful contribution or only a marginal one. Its role in the paper will be sized to that result.

## Final model

**WrapCast** = C4-t17: X-Wing per-vehicle key wrap · Falcon-512 batched Director authorization (B = 16, Δ = 10 ms) · ML-DSA-65 offline OEM manifest with per-chunk hash list · encrypt-once STREAM AES-256-GCM, 16 KB chunks · key-confirmation install report · multicast-ready (6 Mbps carousel) and resumable delivery. Frozen in `FINAL_MODEL_CONFIG.yaml`.
