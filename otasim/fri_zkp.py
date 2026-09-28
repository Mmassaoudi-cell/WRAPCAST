"""Faithful implementation of the source paper's FRI/Merkle-based vehicle authentication.

Section IV-A (registration) and Table II steps 5-6 of Kumar et al. (IEEE TII 2026).
Unspecified parameters (documented in SOURCE_PAPER_AUDIT.md):
  * prime field: BabyBear p = 15*2^27 + 1 (2-adicity 27, generator 31)
  * domain size N = 64 (configurable), SHA-256 Merkle tree over 8-byte big-endian leaves
  * alpha drawn from {0,...,N-1} exactly as written in the paper
"""
from __future__ import annotations

import hashlib
import os
import secrets
import struct
from dataclasses import dataclass, field

P = 2013265921  # BabyBear
GEN = 31


def _inv(a: int) -> int:
    return pow(a % P, P - 2, P)


def root_of_unity(n: int) -> int:
    assert (P - 1) % n == 0
    w = pow(GEN, (P - 1) // n, P)
    assert pow(w, n, P) == 1 and pow(w, n // 2, P) != 1
    return w


def _leaf(v: int) -> bytes:
    return hashlib.sha256(struct.pack(">Q", v % P)).digest()


def _node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(a + b).digest()


class Merkle:
    def __init__(self, values: list[int]):
        n = len(values)
        assert n & (n - 1) == 0
        lvl = [_leaf(v) for v in values]
        self.levels = [lvl]
        while len(lvl) > 1:
            lvl = [_node(lvl[i], lvl[i + 1]) for i in range(0, len(lvl), 2)]
            self.levels.append(lvl)
        self.root = lvl[0]

    def path(self, idx: int) -> list[bytes]:
        out = []
        for lvl in self.levels[:-1]:
            out.append(lvl[idx ^ 1])
            idx >>= 1
        return out


def merkle_verify(root: bytes, idx: int, value: int, path: list[bytes]) -> bool:
    h = _leaf(value)
    for sib in path:
        h = _node(h, sib) if idx % 2 == 0 else _node(sib, h)
        idx >>= 1
    return h == root


def poly_eval(coeffs: list[int], x: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % P
    return acc


@dataclass
class VehicleCredential:
    vid: bytes
    pin: bytes
    r: bytes
    vpr: bytes
    coeffs: list[int]
    n: int
    alpha: int = 0
    tree_f: Merkle | None = None
    tree_fs: Merkle | None = None
    evals_f: list[int] = field(default_factory=list)
    evals_fs: list[int] = field(default_factory=list)


@dataclass
class TARecord:
    vid: bytes
    vpr: bytes
    alpha: int
    r_reg: bytes
    root_f: bytes
    root_fs: bytes
    n: int


def vehicle_register_step1(n: int = 64, degree: int | None = None, rng: secrets.SystemRandom | None = None):
    """AV: VID, PIN, r, VPR = h(VID||PIN||r); random degree-d f with coeffs in [-100,100]; tree over f(w^i)."""
    rng = rng or secrets.SystemRandom()
    d = degree if degree is not None else rng.randint(6, 12)
    vid, pin, r = os.urandom(16), os.urandom(4), os.urandom(16)
    vpr = hashlib.sha256(vid + pin + r).digest()
    coeffs = [rng.randint(-100, 100) % P for _ in range(d + 1)]
    if coeffs[-1] == 0:
        coeffs[-1] = 1
    w = root_of_unity(n)
    evals = [poly_eval(coeffs, pow(w, i, P)) for i in range(n)]
    cred = VehicleCredential(vid, pin, r, vpr, coeffs, n, tree_f=Merkle(evals), evals_f=evals)
    return cred, (vid, vpr, cred.tree_f.root)


def ta_register(msg, n: int, rng: secrets.SystemRandom | None = None):
    rng = rng or secrets.SystemRandom()
    vid, vpr, root_f = msg
    alpha = rng.randint(0, n - 1)  # "alpha in {0, N-1}" as written in the paper
    return alpha, os.urandom(16), (vid, vpr, root_f)


def vehicle_register_step2(cred: VehicleCredential, alpha: int) -> bytes:
    """AV: f*(x) = f_e(x) + alpha f_o(x) evaluated on D* = <w^2>, Merkle root sent to TA."""
    cred.alpha = alpha
    fe = cred.coeffs[0::2]
    fo = cred.coeffs[1::2]
    w2 = pow(root_of_unity(cred.n), 2, P)
    evals = []
    for i in range(cred.n // 2):
        x = pow(w2, i, P)
        evals.append((poly_eval(fe, x) + alpha * poly_eval(fo, x)) % P)
    cred.evals_fs = evals
    cred.tree_fs = Merkle(evals)
    return cred.tree_fs.root


# ------------------------------------------------------------------ Phase II authentication
def server_challenge(n: int, rng: secrets.SystemRandom | None = None):
    rng = rng or secrets.SystemRandom()
    return rng.randint(0, n // 2 - 1), rng.randint(0, 1), os.urandom(16)  # i_val, t, R_auth


def vehicle_respond(cred: VehicleCredential, i_val: int, t: int):
    """Table II step 4: path P_t, A_y = f(w^i), B_y = f(w^{N/2+i}), C_y = f*(w^{2i})."""
    n = cred.n
    path = cred.tree_f.path(i_val) if t == 0 else cred.tree_fs.path(i_val)
    a_y = cred.evals_f[i_val]
    b_y = cred.evals_f[n // 2 + i_val]
    c_y = cred.evals_fs[i_val]
    return path, a_y, b_y, c_y


def server_verify(rec: TARecord, i_val: int, t: int, path, a_y: int, b_y: int, c_y: int) -> bool:
    """Table II step 6: verify path, then C_y == L(alpha) (Eq. 4)."""
    n = rec.n
    if t == 0:
        ok = merkle_verify(rec.root_f, i_val, a_y, path)
    else:
        ok = merkle_verify(rec.root_fs, i_val, c_y, path)
    if not ok:
        return False
    w = root_of_unity(n)
    wi_inv = _inv(pow(w, i_val, P))
    L = ((1 + rec.alpha * wi_inv) * a_y + (1 - rec.alpha * wi_inv) * b_y) % P * _inv(2) % P
    return L == c_y % P


def encode_response(path, a_y, b_y, c_y) -> bytes:
    return bytes([len(path)]) + b"".join(path) + struct.pack(">QQQ", a_y, b_y, c_y)


def decode_response(buf: bytes, n: int):
    depth = buf[0]
    path = [buf[1 + 32 * k : 33 + 32 * k] for k in range(depth)]
    a_y, b_y, c_y = struct.unpack(">QQQ", buf[1 + 32 * depth : 25 + 32 * depth])
    return path, a_y, b_y, c_y
