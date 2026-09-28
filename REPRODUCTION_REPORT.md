# REPRODUCTION REPORT — Kumar et al., IEEE TII 2026

Implementation: `otasim/protocols.py::SourceOTA` + `otasim/fri_zkp.py` (Table II / Sec. IV of the paper, faithfully), run by `SOURCE_METHOD_REPRODUCTION/run_reproduction.py`.
Raw data: `results/reproduction/per_session.csv` (per vehicle), `per_run.csv` (per fleet run), `registration.csv`.
All published-vs-reproduced numbers below are **generated** by `analysis/reproduction_tables.py` into `REPRODUCTION_TABLES.md` and `results/reproduction/published_vs_reproduced.csv`, so nothing is typed by hand. This file quotes selected rows.

**Configurations reproduced:** B01 Kyber768(ML-KEM-768)+Dilithium3(ML-DSA-65)+FRI-ZKP+AES-GCM (the source method); the source's baselines B02 DH-2048(+RSA-PSS), B03 RSA-2048 (ephemeral key per session), B04 McEliece-348864 + SPHINCS+-SHA2-128f; plus B05 Kyber+Falcon-512.
**Setting:** 802.11g, 54 Mbps, 2.4 GHz, 1 dBm, 5–10 m/s random direction, log-distance, TCP; N = 20…100; 4 KB package (primary) and 1 MB (sensitivity); 10 seeds (4 KB) / 3 seeds (1 MB); 3 warm-up sessions discarded per run.
**Environment:** Intel Core Ultra 9 275HX, Windows 11, Python 3.13, liboqs 0.16 (C), OpenSSL 3 via pyca/cryptography 50. One pinned core, high priority. The workstation was shared and fully loaded by unrelated jobs during all runs, so medians are robust but absolute times are somewhat pessimistic.

## 1. Functional reproduction — **successful**

* Registration (Phase I) and Phase II run end to end: 100% of honest sessions are accepted, and the installed image equals the released image (asserted in every run).
* FRI authentication: 200/200 honest proofs accepted and 0/200 modified proofs accepted (`scratch` smoke test, reproducible via `otasim.fri_zkp`).
* Message flow, nonces/cookies/R_auth checks, 4 KB frame format and sizes follow Table II/Prop. 4.
* On-the-wire sizes: Kyber768 pk 1184 B (matches the paper), Dilithium3 signature 3309 B (the paper says ≈2.7 KB, which is the Dilithium2 size), McEliece-348864 pk 261 120 B (the paper says ≈250 KB, consistent).

## 2. Numerical reproduction — **not achieved** (for identifiable reasons)

Aggregation assumption: bars = sum over the N vehicles (values grow linearly with N; see the audit).

| Metric (N = 100 unless stated) | Published | Reproduced (mean over seeds) | Difference | Ratio rep/pub |
|---|---:|---:|---:|---:|
| Fig. 3 handshake, Kyber+Dilithium (ms) | 4.11 | 96.29 | +92.18 | 23.4 |
| Fig. 3 handshake, DH-2048 (ms) | 6.86 | 466.7 | +459.9 | 68 |
| Fig. 3 handshake, McEliece+SPHINCS+ (ms) | 35.71 | 20 310 | +20 270 | 569 |
| Fig. 4 decryption, Kyber+Dilithium (ms) | 3.18 | 1.513 | −1.667 | 0.476 |
| Fig. 5 ZKP computation (s) | 0.058 | 0.009255 | −0.04874 | 0.16 |
| Fig. 6 framework latency, Kyber+Dilithium (ms) | 394.15 | 109.6 | −284.6 | 0.278 |
| Fig. 6 framework latency, DH-2048 (ms) | 404.91 | 482.2 | +77.3 | 1.19 |
| Fig. 6 framework latency, McEliece+SPHINCS+ (ms) | 425.80 | 20 330 | +19 900 | 47.7 |
| Fig. 7 encryption, Kyber+Dilithium (ms) | 17.39 | 1.016 | −16.37 | 0.058 |
| RSA handshake (text) (s) | 194.47 | 11.20 | −183.3 | 0.058 |
| Table III server handshake latency (s, per session) | 0.040000 | 0.000752 | −0.0392 | 0.019 |
| Table III server ZKP time (s, per session) | 0.460671 | 0.000071 | −0.4606 | 0.00015 |
| Table III client handshake latency (s, per session) | 3.173252 | 0.000229 | −3.173 | 0.00007 |
| Table III client decryption time (s, per session) | 0.030840 | 0.000016 | −0.0308 | 0.0005 |

(Exact values for every N are listed in `REPRODUCTION_TABLES.md`.)

### 2.1 Why the numbers cannot agree

1. **The published figures are not mutually consistent.** Table III reports a server handshake of 40 ms *per session*, while Fig. 3 reports 4.11 ms for *100 vehicles*. No single aggregation rule reconciles them. Our per-session measurements fall between the two families.
2. **The published Kyber+Dilithium handshake is physically too small** to be a per-vehicle computation sum: 4.11 ms / 100 = 41 µs per vehicle, whereas an ML-KEM-768 keygen + encaps + decaps + ML-DSA-65 sign + verify costs about 0.8–1.0 ms even in optimized C (measured median 0.98 ms here). The bars must measure something narrower, or be averaged differently, and the paper does not say which.
3. **The McEliece+SPHINCS+ bars are inconsistent with per-session McEliece keys.** The paper generates the server KEM key pair per session (Table II, step 1); McEliece-348864 keygen alone costs ≈50–65 ms in C, while the published bar implies ≈0.36 ms per vehicle. The authors most likely reused a pre-generated McEliece key, which would also void the forward-secrecy claim for that baseline.
4. **The RSA baseline is implementation-bound.** The reported 1.9 s per vehicle handshake is incompatible with C RSA-2048 (≈0.12 s per session here, including per-session keygen) and compatible with pure-Python key generation: pure-Python `rsa.newkeys(2048)` takes a mean of 2.07 s per key (range 0.07–2.70 s over 5 keys; `results/reproduction/rsa_keygen_diagnostic.csv`) versus 0.033 s in OpenSSL, i.e. the same order as the published 1.9 s per vehicle (an earlier ad-hoc run under heavier machine load gave 3.3–11.6 s). The "RSA is 44 000× slower" message therefore reflects a Python library choice, not the algorithm.
5. **Unreported parameters:** package size, repetitions, FRI field/domain, hash, and serialization. The 4 KB assumption is supported by Fig. 4: our 4 KB decryption sum is within 2× of the published one (ratio ≈0.48), whereas any MB-scale package would be orders of magnitude larger.
6. **Simulator:** Mininet-WiFi (Linux kernel, mac80211_hwsim) replaced by a trace-driven 802.11g emulator. This affects the latency bars (Fig. 5 latency, Fig. 6 if it included network time) but not the CPU bars.
7. **Software/hardware:** C implementations (liboqs/OpenSSL) instead of unknown Python libraries; a different CPU; a loaded shared workstation.

### 2.2 What is reproduced qualitatively

* Ordering of handshake cost: Kyber+Dilithium < DH-2048 < McEliece+SPHINCS+ (Fig. 3 ordering) — **reproduced**, with much larger gaps.
* File decryption is small and grows linearly with N (Fig. 4) — **reproduced** (same order of magnitude, ratio ≈0.4–0.5).
* Linear growth of every cumulative metric with N (Figs. 3–8) — **reproduced** (trivially, by construction).
* "Sub-400 ms for 100 vehicles" (Fig. 6) for Kyber+Dilithium — **reproduced as an upper bound** (109.6 ms cumulative CPU).
* Registration storage (vehicle 284 B / TA 338 B with Python `sys.getsizeof`) — not re-measured (it is an artefact of Python object overheads). Wire sizes of our registration messages: 112 B vehicle→TA and 24 B TA→vehicle.

### 2.3 Simulated fleet behaviour (new; not in the source)

Fleet makespan in the paper's 802.11g setting (`results/reproduction/makespan_means.csv`):

* 4 KB package: ≈1.0 s for N = 100 (Kyber+Dilithium, DH), 1.6 s (RSA), 20.2 s (McEliece+SPHINCS+, dominated by N×261 KB public-key transfers over the shared medium).
* 1 MB package: 76.5 s (Kyber+Dilithium) vs 96.5 s (McEliece+SPHINCS+) for N = 100. The shared medium carries N copies of the per-vehicle ciphertext, which is weakness W-E1.

## 3. Decision

The source **method** is reproduced functionally and serves as benchmark B01 (and B02–B05 for its ciphersuite variants). The source's **absolute performance numbers** are not reproducible, because they are internally inconsistent and depend on unreported implementation choices. They are **not** used as benchmark numbers anywhere in the new study: every comparison uses our own measurements of B01–B05 on the same emulator as all other methods. The source method was not modified to force agreement.
