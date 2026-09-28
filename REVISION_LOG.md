# Revision Log — Round 1 (2026-09-28)

Internal record of changes made in response to the five-reviewer panel (`EIC`, `R1` methodology, `R2` domain/crypto, `R3` perspective/deployment, `DA` devil's advocate) that reviewed the manuscript on 2026-09-25. This file is **not part of the submitted paper**; it exists for the authors' own audit trail. Nothing here is referenced from the manuscript text.

## What changed and why (mapped to the Editorial Decision's Revision Roadmap)

| Roadmap item | Manuscript change | Files |
|---|---|---|
| R1 — real author block | `main.tex` author/affiliation/email block replaces the placeholder | `paper/main.tex` |
| R2 — Table I vs. Table VI tension | Added a sentence to §III-F clarifying the round-trip count excludes transport setup and payload-size wall-clock cost, cross-referenced to §V; reframed §V-C's CPU-sweep sentence to name its architectural cause and restated the authorization-latency losses as a direct, quantified consequence of two named design costs rather than an unexplained residual | `paper/sec_method.tex`, `paper/sec_results.tex` |
| R3/DA — T3 authorization-latency number had no table/figure support | Table VII (`tab_ablation.tex`) now reports authorization latency for **both** T3 (depot multicast) and T4 (LTE); §V-E explains the 26.6$\times$ vs. 1.45$\times$ disparity mechanistically (shared-medium airtime contention under the 802.11 DCF model vs. a dedicated cellular link) | `analysis/tables.py`, `analysis/make_macros.py` (new macros `ablHashAuthMsFour`, `ablDigestAuthMsFour`), `paper/sec_results.tex` |
| R1/DA — undisclosed $k_{real}=5$ resampling for $N\geq1000$ | One sentence added to §V-H (Limitations) stating the resampling scheme and its scope; `FINAL_MODEL_CONFIG.yaml`'s `measurement` field expanded to describe it precisely | `paper/sec_results.tex`, `FINAL_MODEL_CONFIG.yaml` |
| R3/DA — VID linkability unacknowledged | One sentence added to §III-A (System and Threat Model) scoping identity confidentiality out of R1–R4 and naming the transport-layer assumption under which it is acceptable, by analogy to TLS client-certificate confidentiality | `paper/sec_method.tex` |
| R2 — missing self-identified PQ-HPKE citation | Cited `draft-ietf-hpke-pq`; added two sentences to §II positioning \WC{}'s wrap construction as HPKE-compatible by construction and naming the three respects in which it differs | `paper/refs.bib`, `paper/sec_related.tex` |
| R2 — Falcon-512 risk disclosure incomplete | §V-H now states the constant-time-Gaussian-sampling implementation consideration alongside the FIPS-206-draft status, and points to Table VII's already-collected ML-DSA-44 sensitivity data as a validated, FIPS-final alternative | `paper/sec_results.tex` |
| R3 — vehicle static-key lifecycle unaddressed | One sentence added to the end of §V-H | `paper/sec_results.tex` |
| EIC — abstract/conclusion length | Abstract rewritten (219 words); conclusion rewritten (221 words) | `paper/sec_abstract.tex`, `paper/sec_conclusion.tex` |

## Explicit decision: no new experiments were run

Every item above is answered from data, code, or documents that already existed before this revision round (raw CSVs under `results/test/`, `otasim/experiment.py`, `SOURCE_WEAKNESS_ANALYSIS.md`). The T3/T4 authorization-latency numbers added to Table VII were spot-verified by hand against `results/test/ablation.csv` (772/29 ms for T3, 278/192 ms for T4, both exact matches to five-seed means) before being written into the table-generation script — no simulation was re-run and the frozen configuration (`FINAL_MODEL_CONFIG.yaml`, crypto section) is unchanged from the version evaluated in the reviewed manuscript.

## `C:\Users\MMASSAOUDI\Desktop\Data` — not used

Re-checked at the start of this revision round (1600+ files enumerated). The folder holds only network-intrusion/traffic-classification datasets (UNSW-NB15, CIC-IDS-2017, CICIoT23, Edge-IIoTset, Bot-IoT/RT-IoT, KDD, TON-IoT, 5GAD, USTC-TFC2016, APA-DDoS, plus unrelated load-forecasting CSVs). None of the five reviewers' concerns concern network-traffic classification; all five concern protocol design, cryptographic scheme choice, or measurement methodology internal to `otasim`. This matches the original `DATA_AUDIT.md` conclusion from the initial research pass and is restated here rather than silently repeated.

## Not changed

- The frozen cryptographic configuration (X-Wing, Falcon-512 Director signature, ML-DSA-65 OEM signature, 16-KB chunks, $B=16$, $\delta=10$ ms, 6 Mb/s multicast) is unchanged. ML-DSA-44 remains a documented, already-evaluated sensitivity variant (Table VII), not the headline configuration; the paper now recommends it explicitly for standards-conservative deployments without requiring a full re-run of the held-out suite.
- All ten benchmark protocols, the security-conformance suite, and the statistical methodology (paired Wilcoxon + Holm, 10 headline seeds / 5 secondary seeds) are unchanged.
- `SOURCE_PAPER_AUDIT.md`, `SOURCE_WEAKNESS_ANALYSIS.md`, `MODEL_SELECTION_REPORT.md`, `TEST_PROTOCOL_DEVIATIONS.md`, `LITERATURE_NOVELTY.md`, `FINAL_RESEARCH_SUMMARY.md`, `BENCHMARK_WTL.csv` are unchanged development-process artifacts; none are cited from the manuscript.
