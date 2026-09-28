# DATA AUDIT

## 1. Data used by the source paper

The source paper (Kumar et al., IEEE TII 2026) uses **no dataset**. Its evaluation is a protocol simulation in Mininet-WiFi (802.11g, 20–100 vehicles), with timing measured on the authors' Python implementation. The "data" of this study are therefore **simulation scenarios** plus **measured cryptographic execution traces**:

| Item | Source paper | This study |
|---|---|---|
| Network | Mininet-WiFi 802.11g, 54 Mbps, 2.4 GHz, 1 dBm, 5–10 m/s, random direction, log-distance | Trace-driven SimPy emulator of the same setting (`otasim/netsim.py`): 802.11g DCF airtime model, rate adaptation from RSSI, random-direction mobility, log-distance loss (exp. 3), MAC retries; plus LTE/5G cellular models |
| Firmware/package | not reported | synthetic random images (encryption cost is content-independent): 4 KB (source regime), 256 KB–256 MB |
| Crypto timing | Python 3, library unknown | real execution: liboqs 0.16 (C, AVX2 where enabled) + OpenSSL 3 via pyca/cryptography 50; single pinned performance core, high priority, 3 warm-up sessions discarded |
| Vehicles | 20–100 | 10–3000 |

Because no pre-existing data are involved, **exact-duplicate and near-duplicate leakage across splits cannot occur**. The analogue of leakage here is *tuning on the evaluation scenarios*. It is prevented by the pre-registered scenario split in `otasim/scenarios.py` / `DATA_SPLIT_MANIFEST.csv`:

* **DEV** (5 scenarios × seeds {0,1,2}): the only scenarios used for candidate screening and hyper-parameter tuning.
* **TEST main** (14 scenarios × seeds 100–109), **TEST robustness** (15 × seeds 200–204), **TEST scaling** (9 × seeds 200–204): run once after `FINAL_MODEL_CONFIG.yaml` is frozen.
* DEV and TEST use disjoint seeds and different (fleet size, package size, channel) combinations. No TEST scenario is a re-parameterisation chosen after inspecting TEST results.

## 2. Local data folder `C:\Users\MMASSAOUDI\Desktop\Data`

Contents (top level): 5GAD-2022, APA-DDoS-Dataset, Bot_IoT, CIC-IDS-2017, CICIOT23, CIC_VPN2016, CS240_ISCXVPN2016, Edge-IIoTset, IDS_ISCX_2012_dataset, KDD, Load Data, RT_IOT / RT_IOT2022, TONIoT Network Dataset, UNSW_NB15, USTC-TFC2016, dataset (UNSW-NB15 train/test CSVs).

**Decision: not used.** These are network-intrusion / traffic-classification and load datasets. The source and the proposed work are cryptographic OTA *protocols*: their correctness is checked by executing them, and their cost depends on primitives, message sizes, channel and fleet parameters, not on labelled traffic. Adding an IDS dataset would mean inventing a learning task the source paper does not study, which the master protocol forbids ("do not use a mechanism simply because it is available"). The decision was made before any experiment was run.

## 3. Randomness sources per seed

Seed-controlled: vehicle start jitter, mobility trajectories, cellular link rates/RTTs, outage processes, ZKP challenges/batch positions, small-message loss. Not seed-controlled (by design, cryptographically secure): key material and nonces. Measured CPU times vary run to run; that variability is part of the reported seed-level spread.
