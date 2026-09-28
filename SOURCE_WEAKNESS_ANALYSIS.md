# SOURCE WEAKNESS ANALYSIS

Source: Kumar et al., IEEE TII 2026 (see `SOURCE_PAPER_AUDIT.md`).
Evidence types: **[C]** executable conformance test (`otasim/attacks.py`, results in `results/security/`), **[M]** measurement from the reproduction (`results/reproduction/`), **[A]** analytical argument from the paper's own specification.
The ML-oriented categories of the master protocol (predictive/architectural/computational/scientific) map here to security-design, efficiency and evaluation weaknesses. Items are ranked by expected impact on a deployed OTA system.

> Scope note. The ZKP-related items below are argued from the paper's equations and parameters. No exploit tooling was built; the executable tests only check whether a receiving party accepts or rejects deviating inputs.

---

## A. Security-design weaknesses (ranked)

### W-S1 (critical) — No end-to-end authenticity of the software image [C]
The package is protected only by the per-session AES-GCM key shared with the distribution server (Table II, step 6). Nothing authenticates the image to the **OEM**: no release signature, digest or metadata. A compromised or insider-controlled distribution server, which holds every key the protocol uses online, can deliver an arbitrary image, and the vehicle installs it. The threat model assumes the server "does not cheat", but repository compromise is the main attack class that automotive OTA standards (Uptane, IEEE-ISTO 6100) are built to survive.
*Conformance result:* `malicious_server` → violation for all five source-family configurations (B01–B05); rejected by Uptane (B08/B09) and by every candidate.

### W-S2 (high) — Server authentication is not bound to the session [A]
σ = Sign_{sk_D}(h(pk_K)) covers only the ephemeral KEM key: no vehicle nonce, VID, version or transcript. Any (pk_K, σ) pair ever produced stays a valid "server hello" forever, so the protocol relies entirely on no ephemeral secret key ever leaking (memory disclosure, core dump, logging). TLS 1.3 and SIGMA-style designs sign the transcript, including a fresh client value, for exactly this reason. For a pure network attacker without such a leak, replay fails (conformance test `replay_server` → rejected for all protocols).

### W-S3 (high) — Chunk framing without sequence binding [C, conditional on the paper's description]
Prop. 4 describes each 4 KB chunk as an independent AES-GCM frame (IV, ciphertext, tag), with no chunk index, total length or end-of-stream marker in the associated data. Under this framing, reordering and dropping trailing chunks are not detected; only modifying a chunk is.
*Conformance result:* `reorder_chunks` and `truncate` → violation for B01–B05 in our implementation of the described framing. (The authors' code is unavailable, so an implementation that adds sequence numbers would not have this issue. We report it as a specification gap.)

### W-S4 (high) — Rollback is decided by the server [C]
The "latest version" is an unauthenticated server statement (Table II, sub-phase II, step 3). A compromised server can re-serve an old image while labelling it as newer.
*Conformance result:* `rollback_server` → violation for B01–B05 and for plain TLS/KEMTLS (B06, B07, B10); rejected by Uptane and all candidates.

### W-S5 (medium) — No freshness bound on release information [C]
There is no expiry or timestamp on what the vehicle is told, so stale or frozen update information cannot be detected (`stale_metadata` → accepted by B01–B07, B10).

### W-S6 (high) — The vehicle credential leaks through the authentication responses [A]
Each session reveals A_y = f(ω^i) and B_y = f(ω^{N/2+i}) to the server in the clear (inside the channel). Prop. 6 bounds privacy only while the verifier has seen fewer than d+1 points, and it adds the "deployment assumption" that no verifier accumulates more. The protocol, however, has a single long-lived verifier and no re-registration mechanism. Moreover, the coefficients are drawn from [−100, 100], so f has at most (d+1)·log2(201) ≈ 7.65(d+1) bits of entropy: about 53 bits for d = 6 and 99 bits for d = 12. Each revealed evaluation in F_p (p ≈ 2^31) constrains about 31 bits. Information-theoretically, f is therefore determined by far fewer than d+1 evaluations (about 2 for d = 6 and 4 for d = 12, i.e. one or two sessions), so the leakage bound of Prop. 6 is not a meaningful privacy guarantee for the stated parameters. Whoever learns f can recompute both Merkle trees and answer any future challenge. In a deployment where several servers or mirrors share the TA database, one curious server can then impersonate the vehicle to the others.

### W-S7 (medium) — The FRI consistency check adds no soundness beyond the Merkle opening [A]
Only one Merkle path is opened per session (for A_y if t = 0, or for C_y if t = 1). The value that is not authenticated (B_y, and C_y or A_y) is constrained only by the linear relation of Eq. (4), and the prover can always satisfy that relation by choosing it after the fact. The authentication therefore reduces to "possess one committed leaf value at the challenged position", and the per-session soundness argument of Prop. 5 (the ε^k composition across sessions, and the 2d/N term) does not describe what is actually checked. It is also not zero-knowledge: evaluations of the witness are disclosed (W-S6).

### W-S8 (medium) — VID sent in clear; parameter errors [A]
The first message carries the VID in the clear (linkability of vehicles across updates). The paper states Kyber q = 2^12 (it is 3329) and "Dilithium3 ≈ 2.7 KB" (3293 B).

---

## B. Efficiency / architectural weaknesses (ranked) — numbers from `REPRODUCTION_REPORT.md`

### W-E1 (critical at fleet scale) — Per-vehicle re-encryption of the whole package
The package is encrypted separately for every vehicle under its session key, so server work and egress are O(N·|P|). The content can be served neither from a CDN/cache nor over depot multicast, because every vehicle's ciphertext differs. This is the dominant cost for any realistic image size, and it is the main target of the new design.

### W-E2 (high) — Round trips before the first package byte
Cookie exchange, KEM, version query and challenge-response give 4 application RTTs (plus TCP), against 1 for TLS 1.3. This matters on cellular links (RTT 20–100 ms).

### W-E3 (medium) — No resumption
The session key is destroyed at the end of a session, and a broken connection restarts the whole protocol, including the full package transfer. Moving vehicles lose coverage routinely.

### W-E4 (medium) — Per-session ephemeral server key generation and signing
Every session costs a KEM keygen plus a signature on the server. For the source's McEliece baseline this means a 261 KB public key and a ≈50–65 ms keygen per session.

### W-E5 (low) — 4 KB chunks
The 40 B framing per 4 KB chunk (≈1%) and per-chunk call overhead are small but avoidable.

---

## C. Scientific / evaluation weaknesses

1. **Internally inconsistent results:** Table III (seconds) vs. Figs. 3/4 (milliseconds) differ by ≈1000×; "fourfold vs RSA" vs. 37.89 s vs 0.85 ms; "44% vs McEliece" vs. 88% (Fig. 3) / 7.4% (Fig. 6). See the audit, §13.
2. **Implementation-dominated baselines:** the RSA baseline's second-scale costs match pure-Python RSA key generation (mean 2.07 s per 2048-bit key with the pure-Python `rsa` package vs 0.033 s in OpenSSL; `results/reproduction/rsa_keygen_diagnostic.csv`). They are not a property of RSA.
3. **Unreported package size and repetition count;** figures lack units of aggregation (cumulative vs. mean).
4. **Weak baselines:** no TLS 1.3, no hybrid PQ-TLS (the deployed standard X25519MLKEM768), no KEMTLS, no Uptane, the automotive OTA standard. The comparison is among ciphersuites inside the authors' own architecture only.
5. **No statistics** beyond mean/variance; no confidence intervals or significance tests.
6. **No ablation, no robustness** (loss, interruptions, compromised server) and no executable security evaluation; the security analysis is informal and, for Props. 5–6, does not match the construction (W-S6, W-S7).
7. **Novelty overstated:** Uptane-style designs with PQ signatures and PQ-TLS transports already provide integrated authentication, key exchange and confidentiality; the paper does not compare against them.

## D. Ranking by expected impact (drives candidate design)

| Rank | ID | Type | Impact | Addressed by |
|---|---|---|---|---|
| 1 | W-S1 | security | installs attacker firmware if the server is compromised | OEM release signature (all candidates) |
| 2 | W-E1 | efficiency | O(N·\|P\|) server/egress; no CDN or multicast | encrypt-once + per-vehicle key wrap (C3, C4) |
| 3 | W-S6/W-S7 | security | credential leakage; authentication strength misstated | KEM/signature credentials (C1–C4) |
| 4 | W-S4/W-S5 | security | rollback / freeze | signed version + expiry (all candidates) |
| 5 | W-S2 | security | unbound server authentication | transcript/nonce-bound signatures (C1, C3, C4) or KEM auth (C2) |
| 6 | W-S3 | security | reorder/truncation | STREAM / TLS records |
| 7 | W-E2/W-E3 | efficiency | RTTs, no resumption | 1-RTT authorization, resumable content |
| 8 | W-E4 | efficiency | per-session signing | batched Director signatures (C4) |
