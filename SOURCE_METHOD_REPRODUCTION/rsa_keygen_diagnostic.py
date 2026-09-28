"""Diagnostic: per-key cost of RSA-2048 key generation, pure Python (`rsa`) vs OpenSSL (pyca). 5 keys each."""
import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pandas as pd, rsa
from cryptography.hazmat.primitives.asymmetric import rsa as crsa
from otasim import prims
prims.pin_measurement_core()
rows = []
for i in range(5):
    t = time.perf_counter(); rsa.newkeys(2048); rows.append(dict(impl="pure-python rsa 4.9.1", run=i, seconds=time.perf_counter() - t))
    t = time.perf_counter(); crsa.generate_private_key(65537, 2048); rows.append(dict(impl="OpenSSL (pyca/cryptography)", run=i, seconds=time.perf_counter() - t))
d = pd.DataFrame(rows); d.to_csv(os.path.join(os.path.dirname(__file__), "..", "results", "reproduction", "rsa_keygen_diagnostic.csv"), index=False)
print(d.groupby("impl").seconds.describe())
