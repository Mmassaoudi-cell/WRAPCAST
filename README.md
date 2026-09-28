# WrapCast — reproduction of Kumar et al. (IEEE TII 2026) and an encrypt-once post-quantum OTA design

This repository contains **WrapCast**, an independently designed post-quantum OTA protocol (encrypt-once content, per-vehicle X-Wing key wrapping, batched Director authorization, OEM-signed chunk hash list, key-confirmation reports)

## Environment

* Windows 11 (tested), Python 3.13.9; `pip install -r requirements.txt` into `.venv`.
* liboqs 0.16.0 built locally (AVX2 where enabled):
  ```bash
  git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git
  cmake -G "MinGW Makefiles" -DBUILD_SHARED_LIBS=ON -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=auto \
        -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$HOME/_oqs_avx2 -S liboqs -B build
  cmake --build build -j && cmake --install build
  ```
  `otasim/prims.py` sets `OQS_INSTALL_PATH=~/_oqs_avx2` and routes liboqs randomness to the OS CSPRNG (the default Windows path costs ≈0.3 ms per call).
* Optional env var `OTA_CORE` = CPU core to pin measurements to (default 2).
* LaTeX (MiKTeX/TeX Live) with IEEEtran for the manuscript.

## Layout

| Path | Content |
|---|---|
| `otasim/prims.py` | KEM/signature/AEAD wrappers (liboqs + OpenSSL), X-Wing |
| `otasim/fri_zkp.py` | source paper's FRI/Merkle vehicle authentication |
| `otasim/protocols.py` | all protocols: `SourceOTA` (B01–B05), `TLS13OTA` (B06–B09, C1), `KEMTLSOTA` (B10, C2), `WrapOnceOTA` (C3, C4, WrapCast + ablations) |
| `otasim/attacks.py` | security conformance suite (9 attack classes + honest-update check) |
| `otasim/netsim.py` | SimPy emulator: 802.11g depot (DCF airtime, rate adaptation, mobility, multicast) and LTE/5G |
| `otasim/scenarios.py` | pre-registered DEV / TEST / robustness / scaling scenarios |
| `SOURCE_METHOD_REPRODUCTION/` | reproduction script for the source paper |
| `experiments/` | screening, tuning, confirmation, TEST suite, security, polluted-mirror experiment |
| `analysis/` | reproduction tables, statistics, figures, LaTeX tables, manuscript macros |
| `results/` | all raw per-run CSVs (`reproduction/`, `selection/`, `test/`, `security/`) |
| `paper/` | manuscript sources and compiled PDF |

## Exact reproduction commands (in order)

```bash
# 0. environment
python -m venv .venv && .venv/Scripts/python -m pip install -r requirements.txt
# 1. source reproduction (≈1 h)
.venv/Scripts/python SOURCE_METHOD_REPRODUCTION/run_reproduction.py --seeds 10
.venv/Scripts/python analysis/reproduction_tables.py
# 2. candidate screening and tuning (DEV only)
.venv/Scripts/python experiments/screen_candidates.py
.venv/Scripts/python experiments/tune_candidates.py C3_WRAPONCE C4_WRAPONCE_BATCH --trials 20
.venv/Scripts/python experiments/confirm_selection.py
# 3. (FINAL_MODEL_CONFIG.yaml is frozen; verify its hash against FINAL_MODEL_CONFIG.sha256)
# 4. held-out evaluation
.venv/Scripts/python experiments/run_test_suite.py main
.venv/Scripts/python experiments/run_test_suite.py ablation
.venv/Scripts/python experiments/run_test_suite.py robust
.venv/Scripts/python experiments/run_test_suite.py scaling
.venv/Scripts/python experiments/run_security.py
.venv/Scripts/python experiments/insider_mirror.py
.venv/Scripts/python analysis/flow_profile.py
# 5. statistics, tables, figures, macros, manuscript
.venv/Scripts/python analysis/stats.py main
.venv/Scripts/python analysis/stats.py robust
.venv/Scripts/python analysis/tables.py
.venv/Scripts/python analysis/figures.py
.venv/Scripts/python analysis/make_macros.py
cd paper && latexmk -pdf main.tex
```

Absolute CPU times depend on the host and its load; the ordering of methods and the structural effects (O(N·|P|) vs O(|P|) delivery, round trips, bytes) do not.

## Documents

`SOURCE_PAPER_AUDIT.md`, `REPRODUCTION_REPORT.md` (+ generated `REPRODUCTION_TABLES.md`), `SOURCE_WEAKNESS_ANALYSIS.md`, `DATA_AUDIT.md`, `DATA_SPLIT_MANIFEST.csv`, `MODEL_CANDIDATES.md`, `MODEL_SELECTION_REPORT.md`, `FINAL_MODEL_CONFIG.yaml`, `TEST_PROTOCOL_DEVIATIONS.md`, `LITERATURE_NOVELTY.md`, `BENCHMARK_WTL.csv`, `FINAL_RESEARCH_SUMMARY.md`.
