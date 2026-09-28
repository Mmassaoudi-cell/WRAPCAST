# SOURCE PAPER AUDIT

**Paper:** U. Kumar, I. M. Varma, A. K. Sahoo, A. Palkar, A. Azeem, N. Prajapati, N. Kumar,
"A Secure and Post-Quantum-Resilient OTA Software Update Framework for Industrial Autonomous Vehicles,"
*IEEE Transactions on Industrial Informatics*, accepted 6 Aug 2026 (early access), DOI 10.1109/TII.2026.3722485, paper no. TII-26-4511.

Audit performed on the 11-page accepted version (text extracted to `source_extract/fulltext.txt`; figures re-rendered at 300 dpi in `source_extract/`).

---

## 0. Nature of the paper and how the master protocol is adapted

The source paper is a **cryptographic-protocol and systems paper**, not a machine-learning paper. It contains:

* no dataset, no classifier, no train/validation/test split, no accuracy/F1 metrics;
* a protocol (registration + handshake + ZKP-style authentication + encrypted transfer);
* a *performance* evaluation (latency, computation time, storage, communication) in a network simulator;
* an informal/semi-formal security analysis (six propositions).

The master research protocol is therefore mapped as follows (every mapping is used consistently in all later artifacts):

| Master-protocol concept | Instantiation in this study |
|---|---|
| "Model" | An OTA security protocol (key establishment + authentication + package protection + delivery mode) |
| "Hybrid model" | A protocol that combines 2–4 complementary mechanisms (e.g., hybrid classical/PQ KEM, encrypt-once content protection, batch authorization, chunk-level authenticated streaming) |
| Dataset | Simulation scenario = (fleet size, package size, channel model, loss/mobility profile, CPU class) |
| TRAIN/VALIDATION | *Development scenarios* + development seeds, used only for design screening and hyper-parameter tuning (chunk size, batch window, parameter sets) |
| TEST | *Held-out scenarios* (different fleet sizes, package sizes, channels, loss levels) + held-out seeds, run once after the configuration is frozen |
| Primary metric (macro-F1 in ML) | Not applicable. Primary performance metric = **fleet update makespan** and **per-vehicle end-to-end update latency**; primary security gate = **attack acceptance rate = 0** on the executable attack suite and **benign false-rejection rate = 0** |
| FPR / FNR | FPR ↔ benign update wrongly rejected; FNR ↔ malicious/modified update or impersonation accepted |
| Benchmarks | ≥10 protocol configurations (source reproduction, the source's own baselines, TLS 1.3 classical/hybrid-PQ, KEMTLS, Uptane classical/PQ, alternative PQ primitives) |
| Seeds | Independent simulation seeds (mobility, channel, loss, arrival process, cryptographic randomness, timing jitter) |
| Ablation | Remove each protocol mechanism in turn |
| Robustness | Packet loss, link interruptions/mobility, bandwidth heterogeneity, server compromise, adversarial chunk injection, fleet/package scaling |
| Multiclass evaluation | Not applicable (no labels). Replaced by per-attack-class outcome matrix |
| Low-data analysis | Not applicable (no learning). Replaced by package-size / fleet-size scaling |

The local data folder (`C:\Users\MMASSAOUDI\Desktop\Data`) holds network-intrusion datasets; they are not relevant to a protocol-performance study (see `DATA_AUDIT.md`).

---

## 1. Target problem

Secure over-the-air (OTA) software updates for (industrial) autonomous vehicles over open channels, resilient to quantum adversaries (Shor-type attacks on RSA/DH/ECC).

## 2. Claimed novelty (as stated)

* **RC1** "comprehensive end-to-end post-quantum secure framework" for automotive OTA; novelty is the *integration* of Kyber, Dilithium, AES-GCM and ZKP into one architecture.
* **RC2** secure key exchange using Kyber (KEM) and Dilithium (signature); authentication protocol for AVs.
* **RC3** AES-GCM for the OTA package.
* Claimed to be the first integrated PQ-secure OTA framework for AVs over public networks.

## 3. Entities / network model

* **Trusted Authority (TA)**: registers vehicles; persistent DB of registration records; trusted.
* **Server (verifier)**: delivers updates after ZKP authentication; assumed honest ("do not cheat the entire system").
* **Autonomous Vehicle (prover)**: OBU; establishes channel, proves identity, receives updates.
* Registration channel TA↔AV assumed secure (may be offline). AV↔Server channel open and insecure.

## 4. Threat model (as stated)

Adversary can intercept, replay and synthesize messages on the AV–server channel; quantum-capable. Claimed properties: certificate unforgeability, forward secrecy and key-lifecycle security, integrity/tamper resistance, ZKP soundness, ZKP bounded-leakage privacy, proof-based verifiability, replay resistance, impersonation resistance.
**Not in scope (by assumption):** compromised/malicious server, compromised TA, insider at the distribution side, side channels.

## 5. Cryptographic primitives

| Primitive | Parameters given | Notes |
|---|---|---|
| CRYSTALS-Kyber KEM | n = 256, k ∈ {2,3,4}; **Kyber768** used (q = 2^12 per Prop. 1 — *note*: round-3/FIPS 203 q is 3329; "2^12" is an error in the paper) | pk ≈ 1184 B |
| CRYSTALS-Dilithium | n = 256, q = 8380417; **Dilithium3** | sig ≈ 2.7 KB (Dilithium3 = 3293 B; "2.7 KB" close to Dilithium2 = 2420 B) |
| AES-256-GCM | 12-B IV, 16-B tag, 4096-B chunks, framing 4+12+4+ct+4+16 B | per-chunk independent AEAD |
| HKDF-SHA256 | K_AES = HKDF-SHA256(ss) | salt/info "shown in the code" (code unavailable) |
| Hash h(·) | "collision-resistant hash" (SHA3-256 or SHA256 mentioned for Kyber) | used for VPR and Merkle trees |
| FRI polynomial commitment | degree d ∈ [6,12]; coefficients uniform in [−100,100]; prime field F_p; multiplicative subgroup D = ⟨ω⟩ of size N; one folding step | **p, N, hash, leaf encoding not given** |

## 6. Mathematical formulation (equations in paper)

* Eq. (1) f(x) = f_e(x²) + x f_o(x²); Eq. (2) f_e(x²) = (f(x)+f(−x))/2; Eq. (3) f_o(x²) = (f(x)−f(−x))/(2x).
* Folded polynomial f*(x) = f_e(x) + α f_o(x) with TA challenge α.
* Eq. (4) collinearity: y = ½[(1 + α ω^{−i}) f(ω^i) + (1 − α ω^{−i}) f(ω^{N/2+i})] must equal f*(ω^{2i}).
* Channel security composition: Adv^chan ≤ Adv^KEM_Kyber + Adv^SIG_Dilithium + Adv^AEAD_GCM + negl(λ).
* ZKP soundness claim: per-round ε = max(2d/N, 1/q), overall ε^k over k sessions (see weakness analysis — this composition is not valid for impersonation).

## 7. Protocol (Phase I: registration; Phase II: handshake/auth/update) — Table II of the paper

**Phase I (AV ↔ TA, secure channel)**
1. AV: picks VID, PIN, r; VPR = h(VID‖PIN‖r); random degree-d f(x) over F_p; evaluates f on D = ⟨ω⟩ (size N); Merkle tree over {f(ω^i)}; root MR_f.
2. AV → TA: VID, VPR, MR_f.
3. TA → AV: α ∈ {0,…,N−1}, session token R_reg.
4. AV: computes f* on D* = ⟨ω²⟩ (size N/2); Merkle root MR_f*; sends MR_f* to TA.
5. TA stores (VID, VPR, α, R_reg, MR_f, MR_f*).

**Phase II sub-phase I (handshake)**
1. V → S: ⟨VID, Update_Request⟩.
2. S: ephemeral Kyber768 (pk_K, sk_K); σ = Sign_{sk_D}(h(pk_K)) with long-term Dilithium3 key; nonce N_s; cookie C_s. S → V: (pk_K, σ, C_s, N_s).
   *(Text also describes a separate stateless-cookie round trip before key generation; Table II folds it into this message — ambiguity.)*
3. V: verifies σ with pk_D (from TA); (ct, ss) = Encaps(pk_K); K_AES = HKDF-SHA256(ss). V → S: ⟨ct, C_s*, N_s*, "check for latest version"⟩.
4. S: checks C_s*, N_s*; ss = Decaps(sk_K, ct); K_AES.

**Phase II sub-phase II (vehicle authentication + package)**
5. S → V: Enc_K(latest version, N_s).
6. V: if current < latest: V → S: Enc_K(Get latest, N_s*).
7. S: fetch (VPR, α, MR_f, MR_f*) from TA DB by VID; random R_auth, i_val ∈ {0,…,N/2−1}, t ∈ {0,1}. S → V: Enc_K(VPR, t, i_val, R_auth, N_s).
8. V: auth path P_t (t=0: tree of f at i_val; t=1: tree of f* at i_val); A_y = f(ω^i), B_y = f(ω^{N/2+i}), C_y = f*(ω^{2i}). V → S: Enc_K(P_t, A_y, B_y, C_y, R_auth*, N_s*).
9. S: check R_auth; verify P_t against stored root; A_x = ω^i, B_x = ω^{N/2+i}, C_x = α; L(α) per Eq. (4); accept iff C_y = L(α). S → V: Enc_K(Package, N_s, R_auth) (4 KB AES-GCM frames).
10. V: checks R_auth, decrypts, installs. Kyber key pair destroyed at session end.

Round trips before first package byte: cookie exchange (per text) + 1 (KEM) + 1 (version) + 1 (challenge/response) → **3–4 RTT**, plus TCP handshake.

## 8. Experimental setup

* Simulator: **Mininet-WiFi** on Ubuntu 22.04, 16 GB RAM, 8 CPU cores; Python 3; TCP/IP (no IEEE 1609.2/WAVE).
* Radio: IEEE 802.11g, 54 Mbps channel bandwidth, 2.4 GHz; vehicle speed 5–10 m/s; "transmission rate" 1 Mbps; Tx power 1 dBm; random-direction mobility; log-distance propagation.
* Fleet sizes: 20, 40, 60, 80, 100 vehicles ("concurrent").
* Baselines: McEliece + SPHINCS+ ("classical PQ baseline"), RSA-2048, Diffie–Hellman DH-2048 (with the same ZKP).
* ZKP excluded from inter-protocol comparison ("identical in all configurations").
* Chunk size 4096 B.
* Code: "open source at [33]" = github.com/utkarsh-iitr/Over-The-Air — **HTTP 404 on 2026-09-24 (repository and user not found)**.

## 9. Reported results (published values; transcribed from 300-dpi renders)

**Fig. 3 – Initial handshake latency (ms), N = 20/40/60/80/100**
DH: 1.33, 2.82, 4.08, 5.38, 6.86 · McEliece+SPHINCS: 7.72, 13.71, 20.97, 27.35, 35.71 · Kyber+Dilithium: 0.85, 1.61, 2.31, 3.14, 4.11

**Fig. 4 – File decryption time and transfer delay (ms)**
DH: 0.64, 1.28, 2.05, 2.75, 3.46 · McE+SPH: 0.98, 1.64, 2.39, 3.25, 4.15 · K+D: 0.72, 1.32, 2.03, 2.50, 3.18

**Fig. 5 – ZKP authentication (s)** computation ≈ 0.012, 0.026, 0.035, 0.045, 0.058; latency ≈ 0.033, 0.087, 0.101, 0.128, 0.159 (read from bar heights; no labels)

**Fig. 6 – Framework latency (ms)**
DH: 81.07, 161.92, 240.74, 323.38, 404.91 · McE+SPH: 86.68, 177.45, 256.59, 338.91, 425.80 · K+D: 79.92, 158.27, 238.92, 314.65, 394.15

**Fig. 7 – File encryption time and transfer delay (ms)**
DH: 5.29, 10.38, 15.65, 21.13, 26.30 · McE+SPH: 3.82, 7.57, 11.00, 14.60, 18.32 · K+D: 3.49, 7.10, 10.61, 13.81, 17.39

**Fig. 8 – Registration** TA computation ≈ 0.0017–0.0053 s; manufacturer computation ≈ 0.014, 0.023, 0.037, 0.049, 0.062 s; latency ≈ 1.5, 2.5, 4.3, 6.6, 9.3 s (N registrations 20–100)

**RSA (text only):** handshake 37.89, 76.82, 116.84, 153.49, 194.47 s; authentication 837.59, 1676.061, 2515.62, 3355.27, 4188.60 s (N = 20…100).

**Table III (per-session, Kyber+Dilithium; mean, variance, mean±σ):**
Server handshake 0.040000 s (var 0.000204); server transfer 0.176051 s (0.000191); server ZKP 0.460671 s (0.000817); client handshake 3.173252 s (0.000346); client decryption 0.030840 s (0.000016); client transfer 0.237724 s (0.0000884).

**Storage:** vehicle 284 B (f with degree 12: 144 B; VID, PIN, r: 56+56+28 B); TA 338 B; total 622 B.
**Communication:** Kyber768 pk 1184 B; Dilithium3 sig ≈ 2.7 KB; McEliece pk ≈ 250 KB; RSA-2048 ≈ 256 B.

**Textual claims:** "up to 42× faster transfer time than RSA", "reduces handshake computation approximately fourfold compared to RSA", "roughly 44% improvement over McEliece-SPHINCS+", "sub-400 ms latencies for 0–100 vehicles", "Kyber–Dilithium remains under 18 ms even with 100 concurrent vehicles".

## 10. Statistics, ablations, robustness

* Statistics: only Table III (mean, variance, mean±σ; number of runs not stated). No confidence intervals, no significance tests, no seed control.
* Ablation: none.
* Robustness: none (no packet loss, no link interruption, no attack-execution experiments).
* Runtime: yes (Figs. 3–8), but units/aggregation not defined (cumulative vs. per-vehicle unclear; see §12).
* Security: six propositions (informal reductions), plus informal analysis. No formal verification (ProVerif/Tamarin), no executable attack tests.

## 11. Limitations stated by the authors

Only future work: "realistic, small-scale hardware testbed".

---

## 12. Reproducibility classification

### Fully specified (reproducible directly)
* Primitive choices and security levels: Kyber768, Dilithium3, AES-256-GCM, HKDF-SHA256.
* Message flow of Phase I and Phase II (Table II), including the challenge values (t, i_val), the collinearity check (Eq. 4), nonces/cookie/R_auth checks.
* AES-GCM frame format (4 B IV-len, 12 B IV, 4 B ct-len, ct, 4 B tag-len, 16 B tag) and 4096-B chunk size.
* Polynomial degree range d ∈ [6,12], coefficient range [−100,100].
* Fleet sizes (20–100), 802.11g/2.4 GHz/54 Mbps, speeds 5–10 m/s, Tx power 1 dBm, random-direction mobility, log-distance propagation, TCP.
* Baseline families: DH-2048, RSA-2048, McEliece + SPHINCS+.

### Partially specified (reasonable implementation assumptions required — each documented)
| Item | Assumption adopted | Rationale |
|---|---|---|
| Kyber/Dilithium implementation | FIPS 203 ML-KEM-768 and FIPS 204 ML-DSA-65 (liboqs / PQClean C via Python bindings) | Paper calls them Kyber768/Dilithium3 (round-3 names); FIPS versions are the standardized successors with identical sizes/costs |
| McEliece parameter set | Classic McEliece 348864 (pk 261 120 B) | Paper says pk ≈ 250 KB |
| SPHINCS+ parameter set | SLH-DSA-SHA2-128f (sig 17 088 B) | "very large signatures", fast signing needed for per-session use; L1 matches McEliece-348864 (L1) |
| DH baseline | Finite-field DH over RFC 3526 2048-bit MODP group, server authenticated by RSA-2048-PSS signature | Paper: "Diffie–Hellman (DH-2048)"; the server-authentication primitive for DH is unspecified |
| RSA baseline | RSA-2048 OAEP key transport + RSA-2048-PSS server signature; ephemeral RSA key per session (to mirror the ephemeral Kyber key) | Paper: "RSA (2048-bit)"; per-session RSA keygen is the only design that can explain second-scale reported costs (tested explicitly) |
| Cookie round trip | Implemented as in the text (stateless HMAC cookie round trip before key generation) | Text is more detailed than Table II |
| FRI field / domain | BabyBear prime p = 15·2^27 + 1 = 2013265921 (standard FRI field), N = 64 (domain size), SHA-256 Merkle leaves over 8-byte big-endian field elements | Not given; values chosen so that N/2 ≥ d+1 and the domain admits a 2-adic subgroup; sensitivity analysis over N ∈ {16, 64, 256, 1024} |
| Package size | 4 KB (single chunk) for reproducing Figs. 3–7; 1 MB additionally | Fig. 4 decryption time (≈32 µs/vehicle) is only consistent with a few-KB file |
| Aggregation of Figs. 3–7 | Bars interpreted as the **sum over N vehicles** of the per-session quantity | Values scale linearly with N; per-vehicle averages would not grow with N |
| Mininet-WiFi | Replaced by a trace-driven discrete-event emulator (real cryptographic execution + 802.11g DCF airtime model with performance-anomaly sharing, log-distance path loss, random-direction mobility, rate adaptation) | Mininet-WiFi requires a Linux kernel with mac80211_hwsim; the host is Windows without WSL |
| Hardware | Intel Core Ultra 9 275HX, 64 GB RAM, Windows 11, Python 3.13, single-thread crypto | Paper: 8-core/16 GB Ubuntu VM |

### Missing (cannot be inferred reliably — not invented; reported as unknown)
* Source code (repository 404).
* Package/firmware size(s) used in Figs. 3–7 and Table III.
* Number of repetitions / seeds behind Table III and the figures.
* Whether Figs. 3–7 are cumulative sums, means, or makespans (inferred, not stated).
* Prime p, domain size N, hash function and leaf encoding of the FRI commitment.
* Exact mobility area, AP placement, log-distance exponent, MAC settings.
* HKDF salt/info, nonce lengths, cookie construction, serialization format.
* Which RSA/DH implementation (library) was used; server-authentication primitive of the DH baseline.
* Reason for the 1000× discrepancy between Table III (seconds) and Figs. 3/4 (milliseconds).

## 13. Internal inconsistencies found during the audit (to be reported, not "fixed")

1. Table III server handshake = 0.040 s per session vs. Fig. 3 = 4.11 ms for 100 vehicles (≈0.04 ms per vehicle): factor ≈ 1000.
2. Table III client decryption = 30.8 ms vs. Fig. 4 = 3.18 ms for 100 vehicles.
3. "Kyber–Dilithium reduces handshake computation by approximately fourfold compared to RSA" vs. reported RSA handshake 37.89 s (N=20) vs. 0.85 ms → ratio ≈ 44 000, not 4.
4. "44% improvement over McEliece-SPHINCS+" vs. Fig. 3 (4.11 vs. 35.71 ms → 88% reduction) and Fig. 6 (394.15 vs. 425.80 → 7.4%).
5. "Dilithium3 signature ≈ 2.7 KB": Dilithium3 signature is 3293 B (2420 B is Dilithium2).
6. Prop. 1 states Kyber modulus q = 2^12; Kyber uses q = 3329.
7. "SUF-CMA" is claimed for Dilithium; FIPS 204 ML-DSA is proven EUF-CMA (SUF-CMA holds under additional assumptions) — minor.
8. Soundness composition ε^k "over k sessions" (Prop. 5) does not bound single-session impersonation.
