"""Security conformance suite.

Every test runs a real protocol session in which the network or the distribution server
deviates from the honest behaviour, and records whether the vehicle *accepted and installed
something other than the genuine image* (a violation) or rejected.  The benign test measures
false rejections.  Tests are protocol-agnostic: they only use the public session() API.

  benign            honest run: must install the genuine image          (false-rejection rate)
  tamper_chunk      one byte of one content frame flipped in transit
  reorder_chunks    two content frames swapped in transit
  truncate          trailing content frames dropped in transit
  replay_server     every server flight replaced by the same flight of an earlier session
  misdelivery       authorization response of vehicle A delivered to vehicle B
  malicious_server  distribution server (holds all *online* keys) ships a different image
  rollback_server   distribution server re-serves an older, genuinely released image as "latest"
  stale_metadata    vehicle clock 60 days after release (frozen/stale update information)
  unregistered      a device that was never provisioned requests the update
"""
from __future__ import annotations

import os
import random

from .common import Adversary, make_package
from .protocols import build


class FlipByte(Adversary):
    name = "tamper_chunk"

    def __init__(self, rng):
        self.rng = rng

    def on_content(self, frames):
        if not frames:
            return frames
        fr = list(frames)
        i = self.rng.randrange(len(fr))
        b = bytearray(fr[i])
        j = self.rng.randrange(len(b))
        b[j] ^= 0x01
        fr[i] = bytes(b)
        return fr


class Reorder(Adversary):
    name = "reorder_chunks"

    def __init__(self, rng):
        self.rng = rng

    def on_content(self, frames):
        fr = list(frames)
        body = list(range(1 if len(fr) > 2 else 0, len(fr)))  # keep a leading header frame in place
        if len(body) >= 2:
            i, j = self.rng.sample(body[:-1] if len(body) > 2 else body, 2)
            fr[i], fr[j] = fr[j], fr[i]
        return fr


class Truncate(Adversary):
    name = "truncate"

    def on_content(self, frames):
        return list(frames[:-2]) if len(frames) > 3 else list(frames[:-1])


class Recorder(Adversary):
    def __init__(self):
        self.log = {}

    def on_msg(self, label, src, msg):
        if src == "S":
            self.log[label] = msg
        return msg

    def on_content(self, frames):
        self.log["__content__"] = frames
        return frames


class ReplayServer(Adversary):
    name = "replay_server"

    def __init__(self, log):
        self.log = log

    def on_msg(self, label, src, msg):
        return self.log.get(label, msg) if src == "S" else msg

    def on_content(self, frames):
        return self.log.get("__content__", frames)


TESTS = ["benign", "tamper_chunk", "reorder_chunks", "truncate", "replay_server", "misdelivery",
         "malicious_server", "rollback_server", "stale_metadata", "unregistered"]


def _fresh(name, n=2, size=256 * 1024, version=2, factory=None):
    p = factory() if factory else build(name)
    p.setup(n)
    pkg = make_package(size, version)
    p.release(pkg)
    return p, pkg


def violation(tr, pkg) -> bool:
    """Attack succeeds iff the vehicle accepted and ended up with anything but the genuine image."""
    return bool(tr.accepted and not tr.installed_ok)


def run_test(name: str, test: str, seed: int, size: int = 256 * 1024, factory=None) -> dict:
    rng = random.Random(seed)
    p, pkg = _fresh(name, 2, size, factory=factory)
    va, vb = p.vids()[:2]
    out = dict(protocol=name, test=test, seed=seed)
    if test == "benign":
        tr = p.session(va, pkg, rng=rng)
        out.update(accepted=tr.accepted, violation=False, false_reject=not (tr.accepted and tr.installed_ok),
                   reason=tr.reason)
        return out
    if test in ("tamper_chunk", "reorder_chunks", "truncate"):
        adv = {"tamper_chunk": FlipByte(rng), "reorder_chunks": Reorder(rng), "truncate": Truncate()}[test]
        tr = p.session(va, pkg, adv=adv, rng=rng)
    elif test == "replay_server":
        rec = Recorder()
        p.session(va, pkg, adv=rec, rng=rng)
        p.vehicles[va].current_version = 1  # vehicle requests the same update again
        tr = p.session(va, pkg, adv=ReplayServer(rec.log), rng=rng)
        # replaying the genuine image is not a violation by itself: count acceptance of a replayed session
        out.update(accepted=tr.accepted, violation=bool(tr.accepted), reason=tr.reason)
        return out
    elif test == "misdelivery":
        rec = Recorder()
        p.session(va, pkg, adv=rec, rng=rng)
        tr = p.session(vb, pkg, adv=ReplayServer(rec.log), rng=rng)
        out.update(accepted=tr.accepted, violation=bool(tr.accepted), reason=tr.reason)
        return out
    elif test == "malicious_server":
        evil = os.urandom(len(pkg.image))
        tr = p.session(va, pkg, rng=rng, server_image=evil)
    elif test == "rollback_server":
        old = make_package(size, version=2)
        p.release(old)
        p.session(va, old, rng=rng)  # vehicle legitimately installs v2
        new = make_package(size, version=3)
        p.release(new)
        p.session(vb, new, rng=rng)  # the fleet moves on to v3 ...
        p.vehicles[va].current_version = 3  # ... and vehicle A is at v3
        p.release(old)  # the old release (genuine artefacts) is re-served as "latest"
        tr = p.session(va, old, rng=rng, server_version=4)
        out.update(accepted=tr.accepted, violation=bool(tr.accepted), reason=tr.reason)
        return out
    elif test == "stale_metadata":
        p.vehicles[va].clock += 60 * 86400
        tr = p.session(va, pkg, rng=rng)
        out.update(accepted=tr.accepted, violation=bool(tr.accepted), reason=tr.reason)
        return out
    elif test == "unregistered":
        ghost = make_ghost(p)
        try:
            tr = p.session(ghost, pkg, rng=rng)
            out.update(accepted=tr.accepted, violation=bool(tr.accepted), reason=tr.reason)
        except KeyError:  # the server has no registration record for this identity
            out.update(accepted=False, violation=False, reason="rejected (no registration record)")
        return out
    else:
        raise ValueError(test)
    out.update(accepted=tr.accepted, violation=violation(tr, pkg), reason=tr.reason)
    return out


def make_ghost(p):
    """A device with self-made credentials that were never provisioned by the OEM/TA."""
    from . import fri_zkp as Z
    from . import prims as P
    from .common import issue_cert
    from .protocols import KEMTLSOTA, SourceOTA, TLS13OTA, VehicleState, WrapOnceOTA

    vid = os.urandom(16)
    vs = VehicleState(vid)
    if isinstance(p, SourceOTA):
        cred, _ = Z.vehicle_register_step1(p.n_dom)
        Z.vehicle_register_step2(cred, 1)
        cred.vid = vid
        vs.keys["cred"] = cred
    elif isinstance(p, TLS13OTA):
        pk, sk = p.sig_c.keygen()
        vs.keys.update(cert=issue_cert(vid, pk, p.sig_c, sk), sk=sk)  # self-signed
    elif isinstance(p, KEMTLSOTA):
        pk, sk = p.kem.keygen()
        cpk, csk = p.ca.keygen()
        vs.keys.update(cert=issue_cert(vid, pk, p.ca, csk), sk=sk, pk=pk)
    elif isinstance(p, WrapOnceOTA):
        pk, sk = p.kem.keygen()
        vs.keys.update(pk=pk, sk=sk)
    p.vehicles[vid] = vs  # vehicle-side state only; not added to any server registry
    return vid
