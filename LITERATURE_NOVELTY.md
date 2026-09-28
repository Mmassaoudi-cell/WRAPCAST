# LITERATURE AND NOVELTY VERIFICATION (performed 2026-09-25)

Searches: web search (IEEE Xplore/ACM/Springer/IACR ePrint/arXiv/IETF datatracker results), Crossref metadata verification for every DOI cited in the manuscript (`scratch/crossref.py` output reproduced in the bibliography check).

## What already exists (and is therefore NOT claimed as new)

| Mechanism | Prior art | Consequence for our claims |
|---|---|---|
| Encrypt-once firmware with per-device key wrapping (one CEK, many wrapped keys) | IETF SUIT "Encrypted Payloads in SUIT Manifests" (draft-ietf-suit-firmware-encryption-26, Dec 2025; ES-DH/HPKE + AES-KW); several OEM patents (version key wrapped per vehicle) | We do not claim encrypt-once or key wrapping per se. SUIT uses classical ES-DH; PQ HPKE is a separate draft (draft-ietf-hpke-pq) |
| Hybrid PQ/T KEM | X-Wing (Barbosa et al., IACR CiC 2024; draft-connolly-cfrg-xwing-kem) | used as a building block |
| Merkle batch signatures to amortize PQ signing | Aguilar-Melchor et al., "Batch Signatures, Revisited", CT-RSA 2024 (LNCS, pp. 163–186); draft-joseph-tls-batch-signatures | used as a building block; our contribution is applying it to per-vehicle OTA authorization tokens and measuring it (its effect turned out small, see ablation) |
| Uptane (Director + Image repository, offline/online roles) | Kuppusamy et al., IEEE VT Mag. 2018; IEEE-ISTO 6100; automated analysis by Lorch et al., RAID 2024 | PQ-Uptane is a benchmark (B09), not a contribution |
| PQ signatures for automotive OTA | Bos et al. (ePrint 2023/965, AUTOSAR Adaptive, S32G); La Manna et al., ISCC 2021 | cited; they address signature cost, not fleet delivery or confidentiality |
| PQ-TLS / KEMTLS | Sikeridis et al., NDSS 2020; Schwabe–Stebila–Wiggers, CCS 2020 / ESORICS 2021; Paul et al., AsiaCCS 2022 | benchmarks B07, B10 |
| Online AE / STREAM | Hoang et al., CRYPTO 2015 | building block |
| ZKP/PUF OTA authentication for SDVs | Tangade et al., zk-ScalHard (arXiv 2607.07371, Jul 2026; not PQ, compares with Uptane) | related work |
| PQC algorithm guidance for automotive (secure boot, OTA, V2X) | Kushwaha & Kaur, ePrint 2026/2149 (Sep 2026; RPi 4B / x86, TLS configurations) | related work |
| Source paper | Kumar et al., IEEE TII 2026 (per-vehicle Kyber/Dilithium/AES-GCM + FRI "ZKP") | benchmark B01 |

## What we did not find (claim scope)

No study found (2024–2026) that jointly:
1. keeps OTA content **confidential against quantum-capable outsiders** (hybrid X-Wing wrapping of a release key) while the ciphertext is **identical for the whole fleet**, so it can be cached, multicast and resumed;
2. makes that content **verifiable chunk by chunk from untrusted mirrors or multicast** through an offline-OEM-signed hash list, with STREAM order/truncation binding;
3. obtains **implicit PQ vehicle authentication** via key confirmation instead of online vehicle signatures or ZKPs;
4. evaluates such a design against PQ-TLS, KEMTLS, PQ-Uptane and a ZKP-based PQ OTA framework on a **common emulator with executable conformance tests**, repeated-seed statistics and ablations.

Wording to use: *"To our knowledge, existing post-quantum OTA studies have not jointly addressed fleet-level delivery cost, confidentiality of cacheable/multicast content, and end-to-end release authenticity."* Do **not** write "first".

## Deployment caveat found during verification

FN-DSA (Falcon, FIPS 206) was still a **draft** as of mid-2026 (NIST submitted it for approval in Aug 2025; final expected late 2026/early 2027). Falcon signing needs careful constant-time floating-point implementation. The frozen configuration uses Falcon-512 for the online Director signature (vehicles only verify). The manuscript must state this and report the ML-DSA-44 Director variant (sensitivity run `SENS_director_mldsa44`) as the FIPS-final alternative.
