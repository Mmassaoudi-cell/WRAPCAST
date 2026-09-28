"""Uniform wrappers around the cryptographic primitives used by all protocols.

Backends
--------
* liboqs 0.16 (C, via liboqs-python): ML-KEM, Classic McEliece, HQC, FrodoKEM,
  ML-DSA, Falcon, SLH-DSA.
* pyca/cryptography 50 (OpenSSL 3.x): X25519, Ed25519, ECDSA-P256, RSA, FFDH,
  AES-GCM, HKDF, SHA-2/3.

Every KEM exposes keygen() -> (pk, sk), encaps(pk) -> (ct, ss), decaps(sk, ct) -> ss.
Every signature scheme exposes keygen() -> (pk, sk), sign(sk, m) -> sig,
verify(pk, m, sig) -> bool.  Keys are opaque Python objects or bytes; sizes of
everything that goes on the wire are reported through .pk_len/.ct_len/.sig_len
and are always taken from the real serialized objects.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
import warnings
from dataclasses import dataclass

import ctypes

warnings.filterwarnings("ignore")
# liboqs 0.16.0 built locally with -DOQS_OPT_TARGET=auto (AVX2 where liboqs enables it on Windows).
os.environ.setdefault("OQS_INSTALL_PATH", os.path.expanduser("~/_oqs_avx2"))
import oqs  # noqa: E402

# liboqs' default Windows RNG costs ~0.3 ms per call (platform artifact); route it to the
# OS CSPRNG through os.urandom so that timings reflect the algorithms, not the RNG shim.
_RNGCB = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)


def _fill_random(buf, n):
    ctypes.memmove(buf, os.urandom(n), n)


_rng_cb = _RNGCB(_fill_random)
_lib = oqs.oqs.native()
_lib.OQS_randombytes_custom_algorithm.argtypes = [_RNGCB]
_lib.OQS_randombytes_custom_algorithm(_rng_cb)


def pin_measurement_core(core: int | None = None) -> None:
    """Pin the process to one core (env OTA_CORE, default 2) at high priority for stable timing."""
    core = int(os.environ.get("OTA_CORE", "2")) if core is None else core
    try:
        import psutil

        p = psutil.Process()
        p.cpu_affinity([core])
        p.nice(psutil.HIGH_PRIORITY_CLASS)
    except Exception:
        pass
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import dh, ec, ed25519, padding, rsa, x25519  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

RAW = serialization.Encoding.Raw
RAWPUB = serialization.PublicFormat.Raw


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def sha3_256(*parts: bytes) -> bytes:
    h = hashlib.sha3_256()
    for p in parts:
        h.update(p)
    return h.digest()


def hkdf(ikm: bytes, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def hmac256(key: bytes, *parts: bytes) -> bytes:
    h = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        h.update(p)
    return h.digest()


def ct_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


# ----------------------------------------------------------------------------- KEMs
class KEM:
    name: str
    pk_len: int
    ct_len: int
    post_quantum: bool = True

    def keygen(self):  # -> (pk, sk)
        raise NotImplementedError

    def encaps(self, pk):  # -> (ct, ss)
        raise NotImplementedError

    def decaps(self, sk, ct):  # -> ss
        raise NotImplementedError


class OQSKEM(KEM):
    def __init__(self, alg: str):
        self.name = alg
        with oqs.KeyEncapsulation(alg) as k:
            self.pk_len = k.details["length_public_key"]
            self.ct_len = k.details["length_ciphertext"]
            self.sk_len = k.details["length_secret_key"]
        self._enc = oqs.KeyEncapsulation(alg)  # stateless encapsulator

    def keygen(self):
        k = oqs.KeyEncapsulation(self.name)
        pk = k.generate_keypair()
        return pk, k  # the oqs object holds the secret key

    def encaps(self, pk):
        ct, ss = self._enc.encap_secret(pk)
        return ct, ss

    def decaps(self, sk, ct):
        return sk.decap_secret(ct)


class X25519KEM(KEM):
    """DHKEM-style wrapper of X25519 (classical, not PQ)."""

    name = "X25519"
    pk_len = 32
    ct_len = 32
    post_quantum = False

    def keygen(self):
        sk = x25519.X25519PrivateKey.generate()
        return sk.public_key().public_bytes(RAW, RAWPUB), sk

    def encaps(self, pk):
        e = x25519.X25519PrivateKey.generate()
        ct = e.public_key().public_bytes(RAW, RAWPUB)
        z = e.exchange(x25519.X25519PublicKey.from_public_bytes(pk))
        return ct, sha256(b"x25519kem", z, ct, pk)

    def decaps(self, sk, ct):
        z = sk.exchange(x25519.X25519PublicKey.from_public_bytes(ct))
        pk = sk.public_key().public_bytes(RAW, RAWPUB)
        return sha256(b"x25519kem", z, ct, pk)


class XWingKEM(KEM):
    """X-Wing hybrid KEM (draft-connolly-cfrg-xwing-kem): ML-KEM-768 + X25519.

    ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
    """

    name = "X-Wing(ML-KEM-768+X25519)"
    LABEL = b"\\.//^\\"

    def __init__(self):
        self.m = OQSKEM("ML-KEM-768")
        self.pk_len = self.m.pk_len + 32
        self.ct_len = self.m.ct_len + 32

    def keygen(self):
        pkm, skm = self.m.keygen()
        skx = x25519.X25519PrivateKey.generate()
        pkx = skx.public_key().public_bytes(RAW, RAWPUB)
        return pkm + pkx, (skm, skx, pkx)

    def encaps(self, pk):
        pkm, pkx = pk[: self.m.pk_len], pk[self.m.pk_len:]
        e = x25519.X25519PrivateKey.generate()
        ctx = e.public_key().public_bytes(RAW, RAWPUB)
        ssx = e.exchange(x25519.X25519PublicKey.from_public_bytes(pkx))
        ctm, ssm = self.m.encaps(pkm)
        return ctm + ctx, sha3_256(ssm, ssx, ctx, pkx, self.LABEL)

    def decaps(self, sk, ct):
        skm, skx, pkx = sk
        ctm, ctx = ct[: self.m.ct_len], ct[self.m.ct_len:]
        ssm = self.m.decaps(skm, ctm)
        ssx = skx.exchange(x25519.X25519PublicKey.from_public_bytes(ctx))
        return sha3_256(ssm, ssx, ctx, pkx, self.LABEL)


# RFC 3526 group 14 (2048-bit MODP)
_P2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_DH2048 = dh.DHParameterNumbers(_P2048, 2).parameters()


class FFDHKEM(KEM):
    """Finite-field DH-2048 (RFC 3526 group 14) used as an ephemeral KEM."""

    name = "DH-2048"
    pk_len = 256
    ct_len = 256
    post_quantum = False

    def keygen(self):
        sk = _DH2048.generate_private_key()
        return sk.public_key().public_numbers().y.to_bytes(256, "big"), sk

    def encaps(self, pk):
        e = _DH2048.generate_private_key()
        peer = dh.DHPublicNumbers(int.from_bytes(pk, "big"), _DH2048.parameter_numbers()).public_key()
        ct = e.public_key().public_numbers().y.to_bytes(256, "big")
        return ct, sha256(b"dhkem", e.exchange(peer), ct, pk)

    def decaps(self, sk, ct):
        peer = dh.DHPublicNumbers(int.from_bytes(ct, "big"), _DH2048.parameter_numbers()).public_key()
        pk = sk.public_key().public_numbers().y.to_bytes(256, "big")
        return sha256(b"dhkem", sk.exchange(peer), ct, pk)


class RSAKEM(KEM):
    """RSA-2048-OAEP key transport of a random 32-byte secret (ephemeral key pair)."""

    name = "RSA-2048-OAEP"
    ct_len = 256
    post_quantum = False

    def __init__(self, bits: int = 2048):
        self.bits = bits
        self.pk_len = 294  # DER SubjectPublicKeyInfo of RSA-2048
        self._pad = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    def keygen(self):
        sk = rsa.generate_private_key(public_exponent=65537, key_size=self.bits)
        pk = sk.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return pk, sk

    def encaps(self, pk):
        ss = os.urandom(32)
        ct = serialization.load_der_public_key(pk).encrypt(ss, self._pad)
        return ct, ss

    def decaps(self, sk, ct):
        return sk.decrypt(ct, self._pad)


# ----------------------------------------------------------------------------- signatures
class SIG:
    name: str
    pk_len: int
    sig_len: int
    post_quantum: bool = True


class OQSSIG(SIG):
    def __init__(self, alg: str):
        self.name = alg
        with oqs.Signature(alg) as s:
            self.pk_len = s.details["length_public_key"]
            self.sig_len = s.details["length_signature"]  # maximum (Falcon is variable)
        self._ver = oqs.Signature(alg)

    def keygen(self):
        s = oqs.Signature(self.name)
        pk = s.generate_keypair()
        return pk, s

    def sign(self, sk, m: bytes) -> bytes:
        return sk.sign(m)

    def verify(self, pk, m: bytes, sig: bytes) -> bool:
        try:
            return bool(self._ver.verify(m, sig, pk))
        except Exception:
            return False


class Ed25519SIG(SIG):
    name = "Ed25519"
    pk_len = 32
    sig_len = 64
    post_quantum = False

    def keygen(self):
        sk = ed25519.Ed25519PrivateKey.generate()
        return sk.public_key().public_bytes(RAW, RAWPUB), sk

    def sign(self, sk, m):
        return sk.sign(m)

    def verify(self, pk, m, sig):
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(sig, m)
            return True
        except Exception:
            return False


class ECDSAP256SIG(SIG):
    name = "ECDSA-P256"
    pk_len = 65
    sig_len = 72
    post_quantum = False

    def keygen(self):
        sk = ec.generate_private_key(ec.SECP256R1())
        return sk.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint), sk

    def sign(self, sk, m):
        return sk.sign(m, ec.ECDSA(hashes.SHA256()))

    def verify(self, pk, m, sig):
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk).verify(sig, m, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


class RSAPSSSIG(SIG):
    name = "RSA-2048-PSS"
    pk_len = 294
    sig_len = 256
    post_quantum = False

    def __init__(self, bits: int = 2048):
        self.bits = bits
        self._pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)

    def keygen(self):
        sk = rsa.generate_private_key(public_exponent=65537, key_size=self.bits)
        return sk.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo), sk

    def sign(self, sk, m):
        return sk.sign(m, self._pad, hashes.SHA256())

    def verify(self, pk, m, sig):
        try:
            serialization.load_der_public_key(pk).verify(sig, m, self._pad, hashes.SHA256())
            return True
        except Exception:
            return False


class CompositeSIG(SIG):
    """AND-composite of two signatures (both must verify)."""

    def __init__(self, a: SIG, b: SIG):
        self.a, self.b = a, b
        self.name = f"{a.name}+{b.name}"
        self.pk_len = a.pk_len + b.pk_len
        self.sig_len = a.sig_len + b.sig_len

    def keygen(self):
        pa, sa = self.a.keygen()
        pb, sb = self.b.keygen()
        return (pa, pb), (sa, sb)

    def sign(self, sk, m):
        sa = self.a.sign(sk[0], m)
        sb = self.b.sign(sk[1], m)
        return struct.pack(">H", len(sa)) + sa + sb

    def verify(self, pk, m, sig):
        n = struct.unpack(">H", sig[:2])[0]
        return self.a.verify(pk[0], m, sig[2 : 2 + n]) and self.b.verify(pk[1], m, sig[2 + n :])


# ----------------------------------------------------------------------------- registry
_KEMS = {}
_SIGS = {}


def kem(name: str) -> KEM:
    if name not in _KEMS:
        if name == "X25519":
            _KEMS[name] = X25519KEM()
        elif name == "X-Wing":
            _KEMS[name] = XWingKEM()
        elif name == "DH-2048":
            _KEMS[name] = FFDHKEM()
        elif name == "RSA-2048":
            _KEMS[name] = RSAKEM()
        else:
            _KEMS[name] = OQSKEM(name)
    return _KEMS[name]


def sig(name: str) -> SIG:
    if name not in _SIGS:
        if name == "Ed25519":
            _SIGS[name] = Ed25519SIG()
        elif name == "ECDSA-P256":
            _SIGS[name] = ECDSAP256SIG()
        elif name == "RSA-2048":
            _SIGS[name] = RSAPSSSIG()
        elif "+" in name:
            a, b = name.split("+", 1)
            _SIGS[name] = CompositeSIG(sig(a), sig(b))
        else:
            _SIGS[name] = OQSSIG(name)
    return _SIGS[name]


# ----------------------------------------------------------------------------- AEAD helpers
@dataclass
class AEAD:
    key: bytes

    def __post_init__(self):
        self._g = AESGCM(self.key)

    def seal(self, nonce: bytes, pt: bytes, aad: bytes | None = None) -> bytes:
        return self._g.encrypt(nonce, pt, aad)

    def open(self, nonce: bytes, ct: bytes, aad: bytes | None = None) -> bytes:
        return self._g.decrypt(nonce, ct, aad)
