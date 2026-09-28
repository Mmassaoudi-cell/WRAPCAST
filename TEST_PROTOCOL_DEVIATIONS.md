# Deviations from the pre-registered TEST protocol

## D1 — Content-fetch round trip missing for encrypt-once delivery (fixed during TEST, 2026-09-25)

**What:** In the first TEST runs, WrapCast's content transfer from a content source (CDN/mirror/depot AP) started immediately after the authorization response. The TCP connection setup to the content source and the HTTP GET were not modelled. The TLS/Uptane/KEMTLS benchmarks do pay for their GET (it is piggybacked on the client's handshake flight or sent as a separate flight on the same connection). This was an emulator-fidelity bug that **favoured the proposed method** by 1–2 RTTs of authorization latency.

**Found by:** inspection of the flow-profile figure (round trips before content), before any statistics or manuscript numbers were produced from TEST data.

**Fix:** `WrapOnceOTA.session` now emits `cdn_syn` / `cdn_synack` (60 B each) and `content_get` flights before the content (only `content_get` on the existing connection for the per-vehicle-content ablation). No protocol parameter, frozen configuration value, scenario or seed was changed. `FINAL_MODEL_CONFIG.yaml` is unchanged (hash still matches `FINAL_MODEL_CONFIG.sha256`).

**Data handling:** all rows of WrapCast and its ablation/sensitivity variants (PROPOSED, ABL_*, PM_*, SENS_*) were removed from `results/test/{main,robust,scaling,ablation}.csv` and re-run with the corrected emulator. Benchmark rows are unaffected by the change and were kept. The pre-fix files are preserved in `results/test/_superseded/` for audit. The flow profile and the security suite were re-run in full.

**Direction of effect:** the correction can only make WrapCast slower. The DEV-stage selection (which also lacked this RTT, for all encrypt-once candidates alike) is not repeated. The missing RTT affected C3 and C4 identically, so it cannot have changed the choice between them.
