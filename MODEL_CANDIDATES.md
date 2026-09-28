# MODEL (PROTOCOL) CANDIDATES

Written after the source audit, the reproduction and the weakness analysis (`SOURCE_WEAKNESS_ANALYSIS.md`), **before** any candidate was run. Weakness IDs (W-S*, W-E*) refer to that file.

All candidates share three fixes that the conformance suite showed are needed:
(i) an **offline OEM release signature** over version, expiry, hardware ID and content digest (fixes W-S1 compromised server, W-S4 rollback, W-S5 freeze);
(ii) **sequence-bound chunk protection** (STREAM / TLS record sequence numbers) (fixes W-S3 reorder/truncation);
(iii) **transcript- or nonce-bound server authentication** (fixes W-S2).
They differ in how the channel is keyed, how the vehicle is authenticated, and how content is delivered. Those choices drive the efficiency weaknesses (W-E1…W-E4), which is where the candidates actually compete.

Notation: X-Wing = ML-KEM-768 + X25519 hybrid KEM (draft-connolly-cfrg-xwing-kem); ML-DSA = FIPS 204; STREAM = nonce-based online AE (Hoang–Reyhanitabar–Rogaway–Vizár, CRYPTO 2015).

---

## C1 — SIGMA-PQ: signed-transcript hybrid handshake + OEM manifest (per-vehicle channel)

* **Fixes:** W-S1…W-S5, W-S6 (credential leakage: vehicle authenticates with an ML-DSA-44 certificate instead of revealing polynomial evaluations), W-E3 (3–4 RTT → 1 RTT handshake).
* **Architecture:** TLS 1.3-shaped 1-RTT mutual authentication: ClientHello(X-Wing ephemeral pk) → ServerHello(ct) ‖ Cert ‖ CertVerify(ML-DSA-65 over transcript) ‖ Finished → client Cert ‖ CertVerify(ML-DSA-44) ‖ Finished ‖ GET → [OEM manifest ‖ image] in AES-256-GCM records.
* **Core formulation:** k = HKDF(ss_XWing, H(transcript)); σ_S = Sign_{sk_S}(H(CH‖SH‖Cert)); vehicle accepts iff Verify(σ_S) ∧ Verify_OEM(M) ∧ H(image) = M.digest ∧ M.version > v_cur ∧ M.expiry > clock.
* **Why better than source:** fewer RTTs, forward-secure hybrid key, no secret leakage, end-to-end authenticity.
* **Expected efficiency:** handshake bytes grow (two ML-DSA certificate chains ≈ 20 KB) but RTTs drop; server still encrypts per vehicle, so server CPU is O(N·|P|).
* **Expected weakness:** close to PQ-TLS + signed manifest, so little novelty; bulk cost unchanged.
* **Ablation needed:** remove OEM manifest; replace X-Wing by ML-KEM-768.
* **Cost:** vehicle 1 X-Wing keygen + decaps, 3 ML-DSA verifies, 1 ML-DSA-44 sign; server 1 encaps, 1 ML-DSA-65 sign, 2 verifies, per-vehicle AES-GCM of |P|.

## C2 — KEM-AUTH: KEMTLS-style implicit authentication + OEM manifest (per-vehicle channel)

* **Fixes:** as C1, and removes online signing (W-E1: server signing per session).
* **Architecture:** ClientHello(ephemeral X-Wing pk) → ServerHello(ct_e) ‖ server cert(static X-Wing pk, CA ML-DSA-65) → ct_S (to server static) ‖ client cert(static KEM pk) → ct_C (to vehicle static) ‖ Finished → Finished ‖ GET → records.
* **Core formulation:** k = HKDF(ss_e ‖ ss_S ‖ ss_C, H(transcript)); authentication is implicit: only the holders of sk_S / sk_V can derive k.
* **Why better:** KEM operations are about 10× cheaper than ML-DSA signing; certificate chains are smaller than signature-based ones.
* **Expected weakness:** 2 RTT before application data; per-vehicle bulk encryption remains.
* **Ablation needed:** remove client static KEM (server-only auth); hybrid vs. pure ML-KEM.
* **Cost:** vehicle 1 keygen, 2 decaps, 1 encaps, 2 verifies; server 1 decaps, 2 encaps, 1 verify, per-vehicle AES-GCM of |P|.

## C3 — WRAP-ONCE: encrypt-once content + per-vehicle hybrid KEM key wrap (store-and-forward)

* **Fixes:** W-S1…W-S6 and the efficiency root cause W-E2 (per-vehicle re-encryption, which forbids CDN caching and multicast), plus W-E3 (RTTs) and W-E1 (per-session ephemeral keygen).
* **Architecture:**
  1. *Release (once):* K_c ←$; C = STREAM-AES-256-GCM_{K_c}(image) in chunks of size s; h_i = SHA-256(C_i); M = (release, hw, version, expiry, |P|, s, #chunks, prefix, SHA-256(h_1‖…‖h_n)); σ_OEM = ML-DSA-65.Sign(M) (offline key).
  2. *Authorization (1 RTT):* V → S: (VID, n_V, v_cur). S: (ct_V, ss_V) = X-Wing.Encaps(pk_V); (k_wrap‖k_conf) = HKDF(ss_V, VID‖release‖n_V); w = AEAD_{k_wrap}(K_c; AD = VID‖release); T = (VID, release, n_V, t, exp, ct_V, w); σ_D = ML-DSA-65.Sign_{sk_D}(T). S → V: (T, σ_D, M, σ_OEM, h_1…h_n).
  3. *Content:* the same C from any mirror (server, CDN, depot multicast, peer). Each chunk is checked against h_i **before** decryption; STREAM binds order and end-of-stream.
  4. *Key confirmation:* V → S: MAC_{k_conf}(VID‖release‖n_V‖"INSTALLED"). This is implicit vehicle authentication without revealing any long-term secret.
* **Why better:** server per-vehicle work drops to 1 encapsulation + 1 signature, independent of |P|; content becomes cacheable and multicastable while staying confidential against outsiders; downloads resume across disconnections with no new handshake.
* **Expected weakness:** one ML-DSA signature per vehicle dominates server CPU; K_c is shared by the release (any authorised vehicle can read that release: the same as the source, where every vehicle receives the plaintext).
* **Ablation needed:** per-vehicle encryption instead of encrypt-once; remove the chunk-hash list (store-then-verify); pure ML-KEM instead of X-Wing; no OEM signature.
* **Cost:** server 1 X-Wing encaps, 1 HKDF, 1 AEAD(32 B), 1 ML-DSA-65 sign; vehicle 2 ML-DSA verifies, 1 X-Wing decaps, #chunks SHA-256 + STREAM decryption.

## C4 — WRAP-ONCE-BATCH: C3 + Merkle-batched Director authorization

* **Fixes:** additionally the residual W-E1 of C3 (one online signature per vehicle) under fleet-scale concurrency.
* **Architecture:** as C3, but tokens issued within a window Δ (or up to B tokens) form the leaves of a Merkle tree; the Director signs only the root: σ_D = Sign(root ‖ t ‖ exp). Each vehicle receives (T, idx, path, root-body, σ_D) and verifies path + signature. Freshness still comes from n_V inside T.
* **Core formulation:** leaf_j = H(0x00‖T_j); node = H(0x01‖L‖R); per-vehicle signing cost = c_sign / |batch| + (log2|batch|) hashes; extra bytes 32·⌈log2 B⌉.
* **Why better:** server CPU per vehicle is dominated by the ~0.1 ms X-Wing encapsulation instead of the ~0.4 ms ML-DSA signature, which raises authorization throughput per core by several times.
* **Expected weakness:** adds up to Δ of queueing latency per request; gains appear only under concurrency.
* **Ablation needed:** B = 1 (equivalent to C3); Δ sweep.
* **Tunable hyper-parameters (DEV only):** chunk size s ∈ {16, 64, 256 KB}, Δ ∈ {10, 50, 200 ms}, B ∈ {16, 64, 256}, Director signature ∈ {ML-DSA-44, ML-DSA-65, Falcon-512}.

---

## Rejected without implementation (and why)

* **Fountain-coded multicast with homomorphic packet signatures:** needs RaptorQ/network-coding implementations whose CPU cost cannot be measured with the available libraries. Plain multicast with unicast repair captures the fleet-bandwidth effect without unmeasured components.
* **Replacing the FRI step with a genuine zk-STARK proof of polynomial knowledge:** keeps the source architecture and its per-vehicle bulk cost while making authentication orders of magnitude more expensive. It fixes nothing that a KEM- or signature-based credential does not already fix.
* **Blockchain-anchored release log:** adds consensus latency; the transparency property can be obtained with a signed append-only log if needed (future work).

## Pre-screening ranking (expected, before any run)

| Rank | Candidate | Pred. performance | Novelty | Efficiency | Data fit | Feasibility | Transactions-level |
|---|---|---|---|---|---|---|---|
| 1 | C4 | high (multicast/CDN, low server CPU) | medium-high | high | high | high | high |
| 2 | C3 | high | medium | high | high | high | medium-high |
| 3 | C2 | medium | medium | medium | high | high | medium |
| 4 | C1 | medium | low | medium | high | high | low |
