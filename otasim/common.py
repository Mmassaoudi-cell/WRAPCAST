"""Shared infrastructure: TLV encoding, timed execution traces, content formats, certificates.

A protocol session is executed *for real* (real keys, real ciphertexts, real signature
checks).  While executing, it records a Trace: an ordered list of Flights.  Each Flight
says which party sent it, how many bytes went on the wire, and how much CPU the sender
spent producing it (measured with perf_counter).  The network simulator (netsim.py)
replays traces on a channel model; the security suite (attacks.py) mutates flights and
checks whether the receiving party rejects.
"""
from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field

from . import prims as P

# ----------------------------------------------------------------------------- TLV


def tlv(*items: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(x)) + x for x in items)


def untlv(buf: bytes) -> list[bytes]:
    out, i = [], 0
    while i < len(buf):
        (n,) = struct.unpack(">I", buf[i : i + 4])
        out.append(buf[i + 4 : i + 4 + n])
        i += 4 + n
    return out


def u64(x: int) -> bytes:
    return struct.pack(">Q", x)


def rd64(b: bytes) -> int:
    return struct.unpack(">Q", b)[0]


class Reject(Exception):
    """Raised by a receiving party when a check fails (the update is not installed)."""


# ----------------------------------------------------------------------------- trace
@dataclass
class Flight:
    src: str  # "V" or "S" (or "CDN")
    label: str
    nbytes: int
    cpu: float  # seconds of CPU spent by the sender before sending
    bulk: bool = False  # package content
    multicastable: bool = False  # identical bytes for every vehicle (encrypt-once / plaintext)
    batched: bool = False  # server work that is amortised across a batch window (see netsim)


@dataclass
class Trace:
    flights: list[Flight] = field(default_factory=list)
    final_vehicle_cpu: float = 0.0  # vehicle processing after the last flight (decrypt/verify/install)
    final_server_cpu: float = 0.0
    accepted: bool = False
    installed_ok: bool = False  # installed image == genuine image
    reason: str = ""
    resumable: bool = False  # content download can resume after a broken connection without restart
    notes: dict = field(default_factory=dict)

    # per-session wire accounting
    def bytes_by(self, src: str) -> int:
        return sum(f.nbytes for f in self.flights if f.src == src)

    def cpu_by(self, src: str) -> float:
        return sum(f.cpu for f in self.flights if f.src == src)


class Timer:
    """with Timer() as t: ...; t.s  (seconds)."""

    __slots__ = ("t0", "s")

    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *a):
        self.s = time.perf_counter() - self.t0


class Adversary:
    """Default = passive network.  Subclasses in attacks.py override the hooks."""

    name = "none"

    def on_msg(self, label: str, src: str, msg: bytes) -> bytes:
        return msg

    def on_content(self, frames: list[bytes]) -> list[bytes]:
        return frames


class Wire:
    """Sends a message through the adversary and records the flight."""

    def __init__(self, trace: Trace, adv: Adversary):
        self.tr, self.adv = trace, adv

    def send(self, src: str, label: str, msg: bytes, cpu: float, **kw) -> bytes:
        self.tr.flights.append(Flight(src, label, len(msg), cpu, **kw))
        return self.adv.on_msg(label, src, msg)

    def send_content(self, src: str, label: str, frames: list[bytes], cpu: float, nbytes: int | None = None, **kw):
        n = nbytes if nbytes is not None else sum(len(f) for f in frames)
        self.tr.flights.append(Flight(src, label, n, cpu, bulk=True, **kw))
        return self.adv.on_content(frames)


# ----------------------------------------------------------------------------- package
@dataclass
class Package:
    image: bytes
    version: int
    hw_id: bytes = b"ECU-ADAS-01"
    release_id: bytes = field(default_factory=lambda: os.urandom(16))

    @property
    def digest(self) -> bytes:
        return P.sha256(self.image)


def make_package(size: int, version: int = 2) -> Package:
    return Package(os.urandom(size), version)


# ----------------------------------------------------------------------------- content formats
def source_frames_encrypt(key: bytes, data: bytes, chunk: int = 4096) -> list[bytes]:
    """Source paper framing (Prop. 4): per-chunk AES-256-GCM, fresh 12-B IV, no sequence binding.

    frame = len(IV)=12 | IV | len(ct) | ct | len(tag)=16 | tag
    """
    a = P.AEAD(key)
    out = []
    for i in range(0, len(data), chunk):
        iv = os.urandom(12)
        ct = a.seal(iv, data[i : i + chunk])
        out.append(struct.pack(">I", 12) + iv + struct.pack(">I", len(ct) - 16) + ct[:-16] + struct.pack(">I", 16) + ct[-16:])
    return out


def source_frames_decrypt(key: bytes, frames: list[bytes]) -> bytes:
    a = P.AEAD(key)
    out = []
    for f in frames:
        iv = f[4:16]
        (n,) = struct.unpack(">I", f[16:20])
        ct = f[20 : 20 + n]
        tag = f[24 + n : 40 + n]
        try:
            out.append(a.open(iv, ct + tag))
        except Exception as e:
            raise Reject("frame auth failed") from e
    return b"".join(out)


def tls_records_encrypt(key: bytes, iv: bytes, data: bytes, rec: int = 16384) -> list[bytes]:
    """TLS 1.3 record protection: nonce = iv XOR seq, AAD = 5-byte header, close_notify at end."""
    a = P.AEAD(key)
    out = []
    ivn = int.from_bytes(iv, "big")
    seq = 0
    chunks = [data[i : i + rec] for i in range(0, len(data), rec)] + [b"\x01\x00close_notify"]
    for c in chunks:
        ctype = b"\x15" if c.startswith(b"\x01\x00close") else b"\x17"
        body = c + ctype
        hdr = b"\x17\x03\x03" + struct.pack(">H", len(body) + 16)
        nonce = (ivn ^ seq).to_bytes(12, "big")
        out.append(hdr + a.seal(nonce, body, hdr))
        seq += 1
    return out


def tls_records_decrypt(key: bytes, iv: bytes, records: list[bytes]) -> bytes:
    a = P.AEAD(key)
    ivn = int.from_bytes(iv, "big")
    out = []
    closed = False
    for seq, r in enumerate(records):
        hdr, body = r[:5], r[5:]
        try:
            pt = a.open((ivn ^ seq).to_bytes(12, "big"), body, hdr)
        except Exception as e:
            raise Reject("record auth failed") from e
        if pt[-1:] == b"\x15":
            closed = True
            break
        out.append(pt[:-1])
    if not closed:
        raise Reject("truncated (no close_notify)")
    return b"".join(out)


def stream_encrypt(key: bytes, prefix: bytes, data: bytes, chunk: int) -> list[bytes]:
    """STREAM (Hoang et al., CRYPTO'15) with AES-256-GCM: nonce = prefix7 | ctr32 | last8."""
    a = P.AEAD(key)
    chunks = [data[i : i + chunk] for i in range(0, len(data), chunk)] or [b""]
    out = []
    last = len(chunks) - 1
    for i, c in enumerate(chunks):
        nonce = prefix[:7] + struct.pack(">I", i) + (b"\x01" if i == last else b"\x00")
        out.append(a.seal(nonce, c, prefix))
    return out


def stream_decrypt(key: bytes, prefix: bytes, frames: list[bytes]) -> bytes:
    a = P.AEAD(key)
    out = []
    last = len(frames) - 1
    for i, f in enumerate(frames):
        nonce = prefix[:7] + struct.pack(">I", i) + (b"\x01" if i == last else b"\x00")
        try:
            out.append(a.open(nonce, f, prefix))
        except Exception as e:
            raise Reject("stream chunk auth failed") from e
    return b"".join(out)


# ----------------------------------------------------------------------------- certificates
X509_OVERHEAD = 300  # bytes of X.509 fields besides SPKI and signature (subject, issuer, validity, extensions)


@dataclass
class Cert:
    subject: bytes
    pk: object  # public key (bytes or tuple for composites)
    pk_bytes: bytes
    sig: bytes
    issuer_sig_alg: str

    def tbs(self) -> bytes:
        return tlv(self.subject, self.pk_bytes)

    @property
    def size(self) -> int:
        return X509_OVERHEAD + len(self.pk_bytes) + len(self.sig)

    def encode(self) -> bytes:
        return tlv(self.subject, self.pk_bytes, self.sig) + b"\x00" * X509_OVERHEAD


def pk_to_bytes(pk) -> bytes:
    if isinstance(pk, tuple):
        return b"".join(pk_to_bytes(x) for x in pk)
    return pk


def issue_cert(subject: bytes, pk, issuer_sig: P.SIG, issuer_sk) -> Cert:
    pkb = pk_to_bytes(pk)
    c = Cert(subject, pk, pkb, b"", issuer_sig.name)
    c.sig = issuer_sig.sign(issuer_sk, c.tbs())
    return c


def verify_cert(c: Cert, issuer_sig: P.SIG, issuer_pk) -> bool:
    return issuer_sig.verify(issuer_pk, c.tbs(), c.sig)
