# FINAL RESEARCH SUMMARY

All numbers below are copied from `results/manuscript_numbers.csv` (generated from the raw result CSVs by `analysis/make_macros.py`) or from the files cited.

## Source paper
Kumar et al., "A Secure and Post-Quantum-Resilient OTA Software Update Framework for Industrial Autonomous Vehicles," IEEE TII 2026 (DOI 10.1109/TII.2026.3722485). It is a cryptographic-protocol paper (Kyber768 + Dilithium3 + FRI-style vehicle proof + AES-GCM, evaluated in Mininet-WiFi). The ML-oriented master protocol was mapped to protocol engineering: DEV/held-out scenarios instead of train/test; makespan and latency instead of macro-F1; attack acceptance and false rejection instead of FNR/FPR (`SOURCE_PAPER_AUDIT.md` §0).

## Reproduction
* **Functional: successful.** Every honest session installs the genuine image, and wire sizes match the paper.
* **Numerical: not achieved, for documented reasons** (`REPRODUCTION_REPORT.md`):
  * The published numbers are internally inconsistent (Table III vs Fig. 3: ≈1000×).
  * The Kyber+Dilithium handshake reproduces at 0.98 ms per vehicle, 23× the published per-vehicle-sum reading.
  * The McEliece bars are 569× below the cost of a per-session McEliece keygen.
  * The RSA baseline matches pure-Python keygen: 2.07 s per key vs 0.033 s in OpenSSL.
  * The qualitative ordering and the decryption-time order of magnitude (ratio 0.48) are reproduced.
* The authors' code repository is 404.

## Data / simulation framework
No dataset exists in the source. We used real cryptography (liboqs 0.16 with a local AVX2 build, and OpenSSL 3 via pyca/cryptography 50) replayed on a SimPy emulator:
* 802.11g depot matching the source's setting: DCF airtime model, rate adaptation, random-direction mobility, and a multicast carousel with unicast repair;
* LTE and 5G cellular links with the Mathis TCP bound, a shared egress, and outages.

Local IDS datasets were deliberately not used (`DATA_AUDIT.md`). The pre-registered split is in `DATA_SPLIT_MANIFEST.csv`: 5 DEV and 14 held-out TEST scenarios, 15 robustness and 9 scaling scenarios, with disjoint seeds.

## Candidates evaluated (DEV only)
* C1 signed-transcript PQ-TLS + OEM manifest.
* C2 KEMTLS-style implicit authentication + OEM manifest.
* C3 encrypt-once + per-vehicle X-Wing key wrap.
* C4 = C3 + Merkle-batched Director signatures.

C3 and C4 dominated screening, and both were tuned with Optuna TPE (20 trials each). A pre-declared tie rule selected C4-t17 (`MODEL_SELECTION_REPORT.md`).

## Final model — WrapCast (frozen in `FINAL_MODEL_CONFIG.yaml`, SHA-256 c1029692…)
* X-Wing (ML-KEM-768 + X25519) per-vehicle wrapping of a release key.
* Falcon-512 Director signatures, batched (B = 16, δ = 10 ms), bound to a vehicle nonce.
* Offline ML-DSA-65 OEM manifest over a per-chunk SHA-256 hash list.
* Encrypt-once STREAM AES-256-GCM, 16 KB chunks.
* Key-confirmation install report.
* 6 Mb/s depot multicast carousel; resumable delivery.

**Why selected:** best DEV objective within the tie set, smallest chunk size (vehicle RAM), and lowest server CPU. The confirmation seed showed no collapse.

## Headline results (held-out, 10 seeds)
| Item | Result |
|---|---|
| Strongest task-specific benchmark | B09 PQ-Uptane over PQ-TLS (makespan W/T/L vs WrapCast: 8/6/0 in WrapCast's favour) |
| Depot multicast, N=100, 16 MB (T3) | 51.7 s vs 1203 s for the best benchmark (**23.3×**); 7.7× at N=20, 17.6× at N=60 |
| Unicast depot / cellular makespan vs best benchmark | +1.8 % (T1, 4 KB), +0.2 % (T2), +0.5 % (T4), +0.1 % (T5), −0.2 % (T6) |
| Source-paper benchmark (B01) vs WrapCast | T2 makespan 1213 vs 1205 s; T6 (LTE outages) 244 vs 147 s; server CPU (T4) 17.3 vs 0.29 ms per vehicle |
| Server CPU per vehicle (T4, LTE N=200, 16 MB) | 0.29 ms vs 17.3 ms (B01) and 23.3 ms (PQ-Uptane); ≥56× lower than any benchmark |
| Wins/ties/losses (makespan, 140 comparisons) | **67 / 56 / 17**. Every loss is in the 4 KB depot scenarios (T1) |
| W/T/L on server CPU | 140 / 0 / 0 |
| W/T/L on authorization latency | 48 / 11 / **81 (negative result)** |
| Security conformance (9 attack classes × 20 seeds) | WrapCast 0 violations, 0 false rejections. B01–B05 fail 5 classes; plain TLS/KEMTLS fail 3; Uptane 0 |
| Minority-recall / macro-F1 | not applicable (no classification task) |
| Efficiency | 1 authorization RTT (+1 content fetch) vs 4 (+cookie) for B01; one-time release cost 23 ms for 16 MB; ≈7,474 authorizations per core-second |

## Ablation conclusion (5 seeds, held-out)
* **Encrypt-once:** without it, server CPU rises 123× and depot multicast makespan 17.6×. It is the main mechanism.
* **Batching:** −35 % (LTE) / −12 % (depot) server CPU. A secondary optimisation.
* **Hybrid X-Wing:** costs 0.08 ms per vehicle over pure ML-KEM.
* **Chunk hash list (trade-off):** at 16 KB chunks and 16 MB it raises the pre-content message from 5.8 to 37.8 KB, authorization latency from 29 to 772 ms, and multicast makespan by 2.0 %. It buys verify-before-decrypt: a polluted chunk from an insider mirror is rejected after 49 % of the download on average, vs 100 % for digest-only.
* **Offline OEM key:** removing it makes malicious-server and rollback attacks succeed.
* **Level-5 parameters:** +2 % server CPU. The ML-DSA-44 Director (FIPS-final) costs +9 % server CPU with no change in makespan.

## Robustness conclusion (5 seeds)
* **Channel loss:** the multicast advantage shrinks from 22.2× (no loss) to 4.2× (20 % frame loss) because of unicast repair.
* **Coverage gaps:** at the largest depot only 30 % of B01's vehicles finish (restart-from-scratch), vs 100 % for WrapCast and every resumable benchmark.
* **LTE outages (30 s up / 15 s down):** 134 s (B01) vs 100 s (WrapCast).
* **Fleet and package scaling:** makespans are identical across methods, while total server CPU at N=1000 is 0.13 s vs 37.2 s (PQ-Uptane). At 256 MB the 512 KB hash list costs +0.14 % makespan.

## Statistical significance
Paired two-sided Wilcoxon over 10 seeds, Holm across 10 benchmarks, ≥1 % practical threshold, rank-biserial effect sizes (`results/test/stats_main.csv`, `BENCHMARK_WTL.csv`). The 5-seed groups cannot reach Wilcoxon p < 0.05 (minimum 0.0625). For them, paired t-tests and effect sizes are reported and no wins are counted.

## Remaining limitations
* The network is emulated, not a Mininet/hardware testbed, and CPU times come from a desktop CPU on a shared, heavily loaded host (not ECUs).
* Falcon-512 (Director) is still draft FIPS 206.
* The hash list grows with |P|/chunk. The tuning used 4 MB DEV images and so underestimated this cost for 16–256 MB.
* No forward secrecy for K_c in the frozen configuration.
* No mechanized proof (ProVerif/Tamarin); the propositions are proof sketches plus executable conformance tests.
* One emulator bug favouring WrapCast (the content-fetch RTT) was found during TEST, fixed, and all affected runs were repeated (`TEST_PROTOCOL_DEVIATIONS.md`).
* The authorization-latency losses are real.

## Recommended venue
**IEEE Transactions on Vehicular Technology** (fleet OTA, V2X/depot networking, PQ security with system evaluation). Alternatives: IEEE Transactions on Intelligent Transportation Systems; IEEE Transactions on Industrial Informatics (the source's venue — expect reviewers to request the Uptane comparison already included).

## Acceptance gate — status
- [x] Source paper fully audited; [x] reproduced (functionally) with documented differences.
- [x] Data protocol frozen.
- [x] No tuning on held-out scenarios; one documented emulator fix (disclosed).
- [x] 4 candidates; [x] DEV-only screening/tuning; [x] one model; [x] config frozen and hashed before TEST.
- [x] 10 benchmarks incl. the source method, classical TLS, PQ-TLS, KEMTLS, classical and PQ Uptane.
- [x] Multiclass: not applicable (per-attack-class matrix instead).
- [x] Primary metric declared (makespan); [x] 10 seeds headline / 5 seeds secondary; [x] statistical tests.
- [x] Ablation; [x] robustness; [x] efficiency; [x] negative results retained (authorization latency, T1 losses, hash-list cost).
- [x] No "first"/SOTA claims.
- [x] Figures and tables generated from CSVs; [x] every text number is a CSV-derived macro (`analysis/audit_manuscript.py`).
- [x] Citations verified via Crossref/datatracker.
- [x] Manuscript compiles (IEEEtran, 10 pages); [x] README with reproduction commands; [x] requirements.txt.
- [ ] **Author names/affiliations and funding** — placeholder "Anonymous Authors" must be replaced by the user.
- [ ] Not done (future work, stated in the paper): ECU hardware measurements, real-radio testbed, mechanized protocol verification.

**Verdict:** the research artefacts and manuscript are complete and internally consistent. The paper is a strong draft, **not yet submission-ready** until the author block is filled in and the authors review the claims and decide whether ECU measurements or formal verification are needed for their target venue.
