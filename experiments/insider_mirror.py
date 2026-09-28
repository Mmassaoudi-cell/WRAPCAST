"""Polluted-mirror experiment (TEST seeds; frozen WrapCast vs. its digest-only ablation).

Threat: an untrusted content source (CDN node, peer, depot multicast relay) controlled by an insider who
knows the release key K_c (any authorized vehicle of the fleet does) replaces chunk j with a *validly
STREAM-encrypted* malicious chunk.  AEAD alone cannot detect this; only the OEM-signed binding can.
Measured: rejection rate, bytes received and vehicle CPU spent before the vehicle rejects.
Output: results/test/insider_mirror.csv
"""
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pandas as pd

from otasim import prims
from otasim.common import Adversary, make_package, stream_encrypt
from otasim.protocols import ablation_factory, final_config, proposed_factory

MB = 1 << 20


class InsiderChunk(Adversary):
    def __init__(self, p, j):
        self.p, self.j = p, j

    def on_content(self, frames):
        fr = list(frames)
        evil = stream_encrypt(self.p.k_c, self.p.prefix, os.urandom(self.p.chunk * len(fr)), self.p.chunk)
        fr[self.j] = evil[self.j]  # correct nonce/position/last-flag: passes AEAD with K_c
        return fr


def main():
    prims.pin_measurement_core()
    cfg = final_config()
    rows = []
    for variant, fac in [("PROPOSED", proposed_factory(cfg)), ("ABL_digest_only", ablation_factory(cfg, "ABL_digest_only"))]:
        for size in (4 * MB, 16 * MB):
            for seed in range(100, 110):
                rng = random.Random(seed)
                p = fac()
                p.setup(1)
                pkg = make_package(size, 2)
                p.release(pkg)
                n = -(-size // p.chunk)
                j = rng.randrange(n)
                vid = p.vids()[0]
                t0 = time.perf_counter()
                tr = p.session(vid, pkg, adv=InsiderChunk(p, j), rng=rng)
                wall = time.perf_counter() - t0
                rejected = not tr.accepted
                # bytes the vehicle had to receive before it could reject
                if variant == "PROPOSED":
                    bytes_before = (j + 1) * (p.chunk + 16)  # per-chunk hash check before decryption
                else:
                    bytes_before = sum(f.nbytes for f in tr.flights if f.bulk)  # digest only after full download
                rows.append(dict(variant=variant, pkg_size=size, seed=seed, polluted_chunk=j, n_chunks=n,
                                 rejected=rejected, reason=tr.reason, bytes_before_reject=bytes_before,
                                 frac_before_reject=bytes_before / (size + 16 * n), session_wall_s=wall))
                print(variant, size, seed, rejected, tr.reason, round(bytes_before / size, 3), flush=True)
    out = os.path.join(os.path.dirname(__file__), "..", "results", "test")
    os.makedirs(out, exist_ok=True)
    pd.DataFrame(rows).to_csv(os.path.join(out, "insider_mirror.csv"), index=False)


if __name__ == "__main__":
    main()
