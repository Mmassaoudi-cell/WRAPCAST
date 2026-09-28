"""All OTA protocol implementations (benchmarks + candidates), executed with real cryptography.

Families
--------
SourceOTA   : Kumar et al. (IEEE TII 2026) as specified in Table II + Sec. IV, parameterised by
              (KEM, signature) to also instantiate the paper's own DH / RSA / McEliece+SPHINCS+
              baselines.
TLS13OTA    : TLS 1.3 (1-RTT, mutual certificate authentication) + HTTP GET of the image,
              optionally with Uptane metadata verification and/or an OEM-signed manifest.
KEMTLSOTA   : KEMTLS with client authentication (Schwabe-Stebila-Wiggers), optionally + OEM manifest.
WrapOnceOTA : encrypt-once content + per-vehicle KEM key wrapping + (batched) authorization.
"""
from __future__ import annotations

import os
import random
import secrets
import statistics
import struct
from dataclasses import dataclass, field

from . import fri_zkp as Z
from . import prims as P
from .common import (Adversary, Package, Reject, Timer, Trace, Wire, issue_cert, rd64, source_frames_decrypt,
                     source_frames_encrypt, stream_decrypt, stream_encrypt, tls_records_decrypt, tls_records_encrypt,
                     tlv, u64, untlv, verify_cert)

DAY = 86400


@dataclass
class VehicleState:
    vid: bytes
    current_version: int = 1
    clock: int = 1_000_000  # vehicle's notion of time (s)
    keys: dict = field(default_factory=dict)


def _enc(key: bytes, m: bytes) -> bytes:
    iv = os.urandom(12)
    return iv + P.AEAD(key).seal(iv, m)


def _dec(key: bytes, c: bytes) -> bytes:
    try:
        return P.AEAD(key).open(c[:12], c[12:])
    except Exception as e:
        raise Reject("channel auth failed") from e


class Protocol:
    name = "base"
    short = "base"
    pq_confidentiality = True
    content_resumable = False  # can a broken download continue without a new handshake?

    def __init__(self):
        self.vehicles: dict[bytes, VehicleState] = {}
        self.release_cpu = 0.0
        self._bulk_samples: dict[tuple, list[tuple[float, float]]] = {}
        self.now = 1_000_000

    # ---- calibration of bulk (package-size-proportional) CPU for large fleets
    def _bulk_key(self, pkg: Package):
        return (len(pkg.image),)

    def _record_bulk(self, pkg, s_cpu, v_cpu):
        self._bulk_samples.setdefault(self._bulk_key(pkg), []).append((s_cpu, v_cpu))

    def _sample_bulk(self, pkg, rng: random.Random):
        return rng.choice(self._bulk_samples[self._bulk_key(pkg)])

    def has_bulk_samples(self, pkg, k: int) -> bool:
        return len(self._bulk_samples.get(self._bulk_key(pkg), [])) >= k

    def setup(self, n: int):
        raise NotImplementedError

    def release(self, pkg: Package):
        self.release_cpu = 0.0

    def session(self, vid: bytes, pkg: Package, adv: Adversary | None = None, bulk_real: bool = True,
                rng: random.Random | None = None, server_image: bytes | None = None,
                server_version: int | None = None) -> Trace:
        raise NotImplementedError

    def vids(self):
        return list(self.vehicles)


# =============================================================================== SOURCE
class SourceOTA(Protocol):
    """Kumar et al. 2026, Table II.  server_image/server_version emulate a compromised server."""

    family = "source"

    def __init__(self, kem="ML-KEM-768", sig="ML-DSA-65", n_dom=64, chunk=4096, name=None, short=None):
        super().__init__()
        self.kem, self.sig = P.kem(kem), P.sig(sig)
        self.n_dom, self.chunk = n_dom, chunk
        self.name = name or f"Source[{kem}+{sig}]"
        self.short = short or self.name
        self.pq_confidentiality = self.kem.post_quantum
        self.reg_times: list[dict] = []

    def setup(self, n: int):
        self.pk_D, self.sk_D = self.sig.keygen()
        self.cookie_secret = os.urandom(32)
        self.db: dict[bytes, Z.TARecord] = {}
        for _ in range(n):
            self.register_vehicle()

    def register_vehicle(self):
        with Timer() as tv1:
            cred, msg = Z.vehicle_register_step1(self.n_dom)
        with Timer() as tta:
            alpha, r_reg, _ = Z.ta_register(msg, self.n_dom)
        with Timer() as tv2:
            root_fs = Z.vehicle_register_step2(cred, alpha)
        with Timer() as tta2:
            self.db[cred.vid] = Z.TARecord(cred.vid, cred.vpr, alpha, r_reg, cred.tree_f.root, root_fs, self.n_dom)
        vs = VehicleState(cred.vid)
        vs.keys["cred"] = cred
        self.vehicles[cred.vid] = vs
        # registration messages: (VID,VPR,MR_f) ; (alpha,R_reg) ; (MR_f*)
        self.reg_times.append(dict(vehicle_cpu=tv1.s + tv2.s, ta_cpu=tta.s + tta2.s,
                                   bytes_v2ta=16 + 32 + 32 + 32, bytes_ta2v=8 + 16))
        return cred.vid

    def session(self, vid, pkg, adv=None, bulk_real=True, rng=None, server_image=None, server_version=None):
        adv = adv or Adversary()
        rng = rng or random.Random()
        tr = Trace()
        w = Wire(tr, adv)
        veh = self.vehicles[vid]
        latest = server_version if server_version is not None else pkg.version
        image = server_image if server_image is not None else pkg.image
        try:
            # 1) V -> S : <VID, Update_Request>
            with Timer() as t:
                m1 = tlv(vid, b"Update_Request")
            m1 = w.send("V", "update_request", m1, t.s)
            # S: stateless cookie C_s
            with Timer() as t:
                rvid, _ = untlv(m1)
                cookie = P.hmac256(self.cookie_secret, rvid, u64(self.now // 60))
                m2 = tlv(cookie)
            m2 = w.send("S", "cookie", m2, t.s)
            with Timer() as t:
                (c_echo,) = untlv(m2)
                m3 = tlv(vid, c_echo)
            m3 = w.send("V", "cookie_echo", m3, t.s)
            # S: validate cookie, ephemeral KEM keypair, sigma = Sign_skD(h(pk_K)), N_s
            with Timer() as t:
                rvid, c_in = untlv(m3)
                if not P.ct_eq(c_in, P.hmac256(self.cookie_secret, rvid, u64(self.now // 60))):
                    raise Reject("cookie")
                pk_K, sk_K = self.kem.keygen()
                sigma = self.sig.sign(self.sk_D, P.sha256(pk_K))
                n_s = os.urandom(16)
                m4 = tlv(pk_K, sigma, c_in, n_s)
            m4 = w.send("S", "kem_pk_sig", m4, t.s)
            # V: verify sigma, encapsulate, K_AES = HKDF(ss)
            with Timer() as t:
                pk_K2, sigma2, c2, n_s2 = untlv(m4)
                if not self.sig.verify(self.pk_D, P.sha256(pk_K2), sigma2):
                    raise Reject("server signature")
                ct, ss = self.kem.encaps(pk_K2)
                k_v = P.hkdf(ss, b"OTA-AES256-GCM")
                m5 = tlv(ct, c2, n_s2, b"check_latest_version")
            m5 = w.send("V", "kem_ct", m5, t.s)
            # S: check cookie + nonce, decapsulate, send latest version
            with Timer() as t:
                ct_in, c3, n_s3, _ = untlv(m5)
                if not (P.ct_eq(c3, c_in) and P.ct_eq(n_s3, n_s)):
                    raise Reject("nonce/cookie")
                k_s = P.hkdf(self.kem.decaps(sk_K, ct_in), b"OTA-AES256-GCM")
                del sk_K  # ephemeral key destroyed
                m6 = _enc(k_s, tlv(u64(latest), n_s))
            m6 = w.send("S", "latest_version", m6, t.s)
            # V: compare versions, request package
            with Timer() as t:
                lv, n_s4 = untlv(_dec(k_v, m6))
                if not P.ct_eq(n_s4, n_s2):
                    raise Reject("nonce")
                if rd64(lv) <= veh.current_version:
                    raise Reject("no newer version")
                m7 = _enc(k_v, tlv(b"GET", lv, n_s2))
            m7 = w.send("V", "get_latest", m7, t.s)
            # S: fetch registration record, send ZKP challenge
            with Timer() as t:
                _, _, n_s5 = untlv(_dec(k_s, m7))
                if not P.ct_eq(n_s5, n_s):
                    raise Reject("nonce")
                rec = self.db[vid]
                i_val, tb, r_auth = Z.server_challenge(rec.n)
                m8 = _enc(k_s, tlv(rec.vpr, u64(tb), u64(i_val), r_auth, n_s))
            m8 = w.send("S", "zkp_challenge", m8, t.s)
            # V: compute proof
            with Timer() as t:
                vpr, tb2, iv2, r_auth2, n_s6 = untlv(_dec(k_v, m8))
                if not P.ct_eq(n_s6, n_s2):
                    raise Reject("nonce")
                resp = Z.vehicle_respond(veh.keys["cred"], rd64(iv2), rd64(tb2))
                m9 = _enc(k_v, tlv(Z.encode_response(*resp), r_auth2, n_s2))
            m9 = w.send("V", "zkp_response", m9, t.s)
            # S: verify proof, encrypt package in 4 KB AES-GCM frames
            with Timer() as t:
                resp_b, r_auth3, n_s7 = untlv(_dec(k_s, m9))
                if not (P.ct_eq(r_auth3, r_auth) and P.ct_eq(n_s7, n_s)):
                    raise Reject("R_auth")
                if not Z.server_verify(rec, i_val, tb, *Z.decode_response(resp_b, rec.n)):
                    raise Reject("ZKP")
                tr.notes["vehicle_authenticated"] = True
                hdr = _enc(k_s, tlv(n_s, r_auth))
            zkp_cpu = t.s
            n_frames = -(-len(image) // self.chunk)
            wire_bytes = len(hdr) + len(image) + n_frames * 40
            if bulk_real:
                with Timer() as te:
                    frames = source_frames_encrypt(k_s, image, self.chunk)
                s_bulk = te.s
            else:
                frames = None
                s_bulk, v_bulk = self._sample_bulk(pkg, rng)
            tr.notes.update(zkp_server_cpu=zkp_cpu, bulk_server_cpu=s_bulk)
            frames_rx = w.send_content("S", "package", ([hdr] + frames) if frames else [], zkp_cpu + s_bulk,
                                       nbytes=wire_bytes)
            # V: check header, decrypt frames, install (no end-to-end image signature exists)
            if bulk_real:
                with Timer() as t:
                    n_s8, r_auth4 = untlv(_dec(k_v, frames_rx[0]))
                    if not (P.ct_eq(n_s8, n_s2) and P.ct_eq(r_auth4, r_auth2)):
                        raise Reject("R_auth")
                    img = source_frames_decrypt(k_v, frames_rx[1:])
                tr.final_vehicle_cpu = t.s
                self._record_bulk(pkg, s_bulk, t.s)
                tr.installed_ok = img == pkg.image
            else:
                tr.final_vehicle_cpu = v_bulk
                tr.installed_ok = True
                tr.notes["bulk"] = "calibrated"
            tr.accepted = True
            veh.current_version = latest
        except Reject as e:
            tr.accepted, tr.reason = False, str(e)
        return tr


# =============================================================================== Uptane metadata helper
class UptaneRepo:
    """Minimal Uptane: image repo (offline targets key), timestamp/snapshot (online), director (online)."""

    def __init__(self, sig: P.SIG):
        self.sig = sig
        self.root_pk, self.root_sk = sig.keygen()
        self.targets_pk, self.targets_sk = sig.keygen()  # offline (OEM)
        self.snap_pk, self.snap_sk = sig.keygen()
        self.ts_pk, self.ts_sk = sig.keygen()
        self.dir_pk, self.dir_sk = sig.keygen()

    def release(self, pkg: Package, now: int):
        body = tlv(b"targets", pkg.hw_id, u64(pkg.version), u64(len(pkg.image)), pkg.digest, u64(now + 365 * DAY))
        self.targets = tlv(body, self.sig.sign(self.targets_sk, body))
        sbody = tlv(b"snapshot", P.sha256(self.targets), u64(now + 7 * DAY))
        self.snapshot = tlv(sbody, self.sig.sign(self.snap_sk, sbody))
        tbody = tlv(b"timestamp", P.sha256(self.snapshot), u64(now + DAY))
        self.timestamp = tlv(tbody, self.sig.sign(self.ts_sk, tbody))

    def director_targets(self, vid: bytes, pkg: Package, now: int, image_digest=None, version=None):
        body = tlv(b"director", vid, pkg.hw_id, u64(version if version is not None else pkg.version),
                   image_digest or pkg.digest, u64(now + DAY))
        return tlv(body, self.sig.sign(self.dir_sk, body))

    def verify_all(self, bundle: bytes, vid: bytes, veh: VehicleState, forged_targets: bytes | None = None):
        ts, snap, targ, dirt = untlv(bundle)
        s = self.sig

        def chk(blob, pk):
            body, sg = untlv(blob)
            if not s.verify(pk, body, sg):
                raise Reject("uptane signature")
            return untlv(body)

        tsb = chk(ts, self.ts_pk)
        if rd64(tsb[2]) < veh.clock:
            raise Reject("timestamp expired (freeze)")
        if not P.ct_eq(tsb[1], P.sha256(snap)):
            raise Reject("snapshot hash")
        sb = chk(snap, self.snap_pk)
        if not P.ct_eq(sb[1], P.sha256(targ)):
            raise Reject("targets hash")
        tb = chk(targ, self.targets_pk)
        db = chk(dirt, self.dir_pk)
        if db[1] != vid:
            raise Reject("director vid")
        if not (P.ct_eq(db[4], tb[4]) and db[3] == tb[2]):
            raise Reject("director/image repo disagree")
        if rd64(tb[2]) <= veh.current_version:
            raise Reject("rollback")
        if rd64(db[5]) < veh.clock or rd64(tb[5]) < veh.clock:
            raise Reject("expired")
        return tb[4], rd64(tb[3]), rd64(tb[2])


# =============================================================================== OEM manifest helper
class OEMSigner:
    """Offline OEM release key: signs (release_id, hw, version, expiry, size, digest-of-content)."""

    def __init__(self, sig: P.SIG):
        self.sig = sig
        self.pk, self.sk = sig.keygen()

    def manifest(self, pkg: Package, now: int, content_digest: bytes, extra: bytes = b""):
        body = tlv(b"manifest", pkg.release_id, pkg.hw_id, u64(pkg.version), u64(now + 30 * DAY),
                   u64(len(pkg.image)), content_digest, extra)
        return body, self.sig.sign(self.sk, body)

    def verify(self, body: bytes, sg: bytes, veh: VehicleState, hw: bytes):
        if not self.sig.verify(self.pk, body, sg):
            raise Reject("OEM signature")
        f = untlv(body)
        if f[2] != hw:
            raise Reject("hw mismatch")
        if rd64(f[3]) <= veh.current_version:
            raise Reject("rollback")
        if rd64(f[4]) < veh.clock:
            raise Reject("manifest expired (freeze)")
        return f


# =============================================================================== TLS 1.3 family
class TLS13OTA(Protocol):
    family = "tls13"

    def __init__(self, kem="X25519", sig_server="ECDSA-P256", sig_client="ECDSA-P256", uptane_sig=None,
                 oem_sig=None, record=16384, name=None, short=None):
        super().__init__()
        self.kem = P.kem(kem)
        self.sig_s, self.sig_c = P.sig(sig_server), P.sig(sig_client)
        self.uptane = UptaneRepo(P.sig(uptane_sig)) if uptane_sig else None
        self.oem = OEMSigner(P.sig(oem_sig)) if oem_sig else None
        self.record = record
        self.name = name or f"TLS1.3[{kem}/{sig_server}]"
        self.short = short or self.name
        self.pq_confidentiality = self.kem.post_quantum
        self.content_resumable = True  # HTTP range request over a fresh TLS session

    def setup(self, n):
        s = self.sig_s
        self.root_pk, self.root_sk = s.keygen()
        self.int_pk, self.int_sk = s.keygen()
        self.int_cert = issue_cert(b"OEM-Intermediate-CA", self.int_pk, s, self.root_sk)
        self.srv_pk, self.srv_sk = s.keygen()
        self.srv_cert = issue_cert(b"ota.oem.example", self.srv_pk, s, self.int_sk)
        # vehicle CA uses the client signature algorithm
        self.vca_pk, self.vca_sk = self.sig_c.keygen()
        for i in range(n):
            vid = os.urandom(16)
            vpk, vsk = self.sig_c.keygen()
            vs = VehicleState(vid)
            vs.keys.update(cert=issue_cert(vid, vpk, self.sig_c, self.vca_sk), sk=vsk)
            self.vehicles[vid] = vs

    def release(self, pkg):
        with Timer() as t:
            if self.uptane:
                self.uptane.release(pkg, self.now)
            if self.oem:
                self.man_body, self.man_sig = self.oem.manifest(pkg, self.now, pkg.digest)
        self.release_cpu = t.s

    def session(self, vid, pkg, adv=None, bulk_real=True, rng=None, server_image=None, server_version=None):
        adv = adv or Adversary()
        rng = rng or random.Random()
        tr = Trace(resumable=True)
        w = Wire(tr, adv)
        veh = self.vehicles[vid]
        image = server_image if server_image is not None else pkg.image
        version = server_version if server_version is not None else pkg.version
        try:
            with Timer() as t:  # ClientHello
                epk, esk = self.kem.keygen()
                ch = tlv(b"CH", os.urandom(32), epk, b"\x00" * 120)
            ch = w.send("V", "client_hello", ch, t.s)
            with Timer() as t:  # ServerHello .. Finished
                _, _, epk_in, _ = untlv(ch)
                ct, ss = self.kem.encaps(epk_in)
                sh = tlv(b"SH", os.urandom(32), ct)
                h1 = P.sha256(ch, sh)
                hs_s = P.hkdf(ss, b"s hs traffic" + h1)
                hs_c = P.hkdf(ss, b"c hs traffic" + h1)
                certs = self.srv_cert.encode() + self.int_cert.encode()
                h2 = P.sha256(ch, sh, certs)
                cv = self.sig_s.sign(self.srv_sk, b" " * 64 + b"TLS 1.3, server CertificateVerify\x00" + h2)
                fin = P.hmac256(P.hkdf(hs_s, b"finished"), P.sha256(ch, sh, certs, cv))
                flight2 = sh + _enc(hs_s, tlv(b"EE+CR", certs, cv, fin))
            fl2 = w.send("S", "server_flight", flight2, t.s)
            with Timer() as t:  # client: verify chain, CV, Finished; send cert, CV, Finished, GET
                sh_in = fl2[: len(sh)]
                _, _, ct_in = untlv(sh_in)
                ss_c = self.kem.decaps(esk, ct_in)
                h1c = P.sha256(ch, sh_in)
                hs_s_c = P.hkdf(ss_c, b"s hs traffic" + h1c)
                hs_c_c = P.hkdf(ss_c, b"c hs traffic" + h1c)
                _, certs_in, cv_in, fin_in = untlv(_dec(hs_s_c, fl2[len(sh):]))
                if not verify_cert(self.int_cert, self.sig_s, self.root_pk):
                    raise Reject("chain")
                if not verify_cert(self.srv_cert, self.sig_s, self.int_pk):
                    raise Reject("chain")
                if not self.sig_s.verify(self.srv_pk, b" " * 64 + b"TLS 1.3, server CertificateVerify\x00" +
                                         P.sha256(ch, sh_in, certs_in), cv_in):
                    raise Reject("server CertificateVerify")
                if not P.ct_eq(fin_in, P.hmac256(P.hkdf(hs_s_c, b"finished"), P.sha256(ch, sh_in, certs_in, cv_in))):
                    raise Reject("server Finished")
                ccert = veh.keys["cert"].encode()
                hc = P.sha256(ch, sh_in, certs_in, cv_in, fin_in, ccert)
                ccv = self.sig_c.sign(veh.keys["sk"], b" " * 64 + b"TLS 1.3, client CertificateVerify\x00" + hc)
                cfin = P.hmac256(P.hkdf(hs_c_c, b"finished"), hc, ccv)
                app_c = P.hkdf(ss_c, b"c ap traffic" + hc)
                app_s = P.hkdf(ss_c, b"s ap traffic" + hc)
                fl3 = _enc(hs_c_c, tlv(ccert, ccv, cfin)) + _enc(app_c, b"GET /update HTTP/1.1")
            fl3 = w.send("V", "client_flight", fl3, t.s)
            with Timer() as t:  # server verifies client auth
                cblob_len = len(fl3) - (12 + 16 + len(b"GET /update HTTP/1.1"))
                ccert_in, ccv_in, cfin_in = untlv(_dec(hs_c, fl3[:cblob_len]))
                vcert = self.vehicles[vid].keys["cert"]
                if not verify_cert(vcert, self.sig_c, self.vca_pk):
                    raise Reject("client chain")
                hcs = P.sha256(ch, sh, certs, cv, fin, ccert_in)
                if not self.sig_c.verify(vcert.pk, b" " * 64 + b"TLS 1.3, client CertificateVerify\x00" + hcs, ccv_in):
                    raise Reject("client CertificateVerify")
                if not P.ct_eq(cfin_in, P.hmac256(P.hkdf(hs_c, b"finished"), hcs, ccv_in)):
                    raise Reject("client Finished")
                tr.notes["vehicle_authenticated"] = True
                app_s_s = P.hkdf(ss, b"s ap traffic" + hcs)
                ivs = P.hkdf(app_s_s, b"iv", 12)
                pre = b""
                if self.uptane:
                    ddig = P.sha256(image) if server_image is not None else None
                    meta = tlv(self.uptane.timestamp, self.uptane.snapshot, self.uptane.targets,
                               self.uptane.director_targets(vid, pkg, self.now, ddig, version))
                    pre = meta
                elif self.oem:
                    pre = tlv(self.man_body, self.man_sig)
            s_pre = t.s
            if self.uptane:
                with Timer() as t:
                    recs = tls_records_encrypt(app_s_s, ivs, pre, self.record)
                recs = w.send_content("S", "uptane_metadata", recs, s_pre + t.s)
                with Timer() as t:
                    meta_in = tls_records_decrypt(app_s, P.hkdf(app_s, b"iv", 12), recs)
                    exp_digest, exp_len, exp_ver = self.uptane.verify_all(meta_in, vid, veh)
                    get2 = _enc(app_c, b"GET /image HTTP/1.1")
                w.send("V", "get_image", get2, t.s)
                s_pre = 0.0
                ivs = P.hkdf(app_s_s, b"iv2", 12)
            # image transfer
            n_rec = -(-len(image) // self.record) + 1
            wire = len(image) + n_rec * (5 + 16 + 1) + (len(pre) if (self.oem and not self.uptane) else 0)
            if bulk_real:
                with Timer() as te:
                    payload = (tlv(pre, image) if (self.oem and not self.uptane) else image)
                    recs = tls_records_encrypt(app_s_s, ivs, payload, self.record)
                s_bulk = te.s
            else:
                recs = []
                s_bulk, v_bulk = self._sample_bulk(pkg, rng)
            recs = w.send_content("S", "package", recs, s_pre + s_bulk, nbytes=wire)
            if bulk_real:
                with Timer() as t:
                    ivc = P.hkdf(app_s, b"iv2" if self.uptane else b"iv", 12)
                    data = tls_records_decrypt(app_s, ivc, recs)
                    if self.uptane:
                        img = data
                        if not P.ct_eq(P.sha256(img), exp_digest) or len(img) != exp_len:
                            raise Reject("image hash != Uptane targets")
                    elif self.oem:
                        mb, img = untlv(data)
                        body, sg = untlv(mb)
                        f = self.oem.verify(body, sg, veh, pkg.hw_id)
                        if not P.ct_eq(P.sha256(img), f[6]):
                            raise Reject("image hash != OEM manifest")
                    else:
                        img = data
                tr.final_vehicle_cpu = t.s
                self._record_bulk(pkg, s_bulk, t.s)
                tr.installed_ok = img == pkg.image
            else:
                tr.final_vehicle_cpu = v_bulk
                tr.installed_ok = True
                tr.notes["bulk"] = "calibrated"
            tr.accepted = True
            veh.current_version = version
        except Reject as e:
            tr.accepted, tr.reason = False, str(e)
        return tr


# =============================================================================== KEMTLS family
class KEMTLSOTA(Protocol):
    """KEMTLS with client authentication (static KEM keys certified by a signature CA)."""

    family = "kemtls"

    def __init__(self, kem="ML-KEM-768", ca_sig="ML-DSA-65", oem_sig=None, record=16384, name=None, short=None):
        super().__init__()
        self.kem, self.ca = P.kem(kem), P.sig(ca_sig)
        self.oem = OEMSigner(P.sig(oem_sig)) if oem_sig else None
        self.record = record
        self.name = name or f"KEMTLS[{kem}/{ca_sig}]"
        self.short = short or self.name
        self.content_resumable = True

    def setup(self, n):
        self.root_pk, self.root_sk = self.ca.keygen()
        self.int_pk, self.int_sk = self.ca.keygen()
        self.int_cert = issue_cert(b"OEM-Intermediate-CA", self.int_pk, self.ca, self.root_sk)
        self.srv_pk, self.srv_sk = self.kem.keygen()
        self.srv_cert = issue_cert(b"ota.oem.example", self.srv_pk, self.ca, self.int_sk)
        for i in range(n):
            vid = os.urandom(16)
            pk, sk = self.kem.keygen()
            vs = VehicleState(vid)
            vs.keys.update(cert=issue_cert(vid, pk, self.ca, self.int_sk), sk=sk, pk=pk)
            self.vehicles[vid] = vs

    def release(self, pkg):
        with Timer() as t:
            if self.oem:
                self.man_body, self.man_sig = self.oem.manifest(pkg, self.now, pkg.digest)
        self.release_cpu = t.s

    def session(self, vid, pkg, adv=None, bulk_real=True, rng=None, server_image=None, server_version=None):
        adv = adv or Adversary()
        rng = rng or random.Random()
        tr = Trace(resumable=True)
        w = Wire(tr, adv)
        veh = self.vehicles[vid]
        image = server_image if server_image is not None else pkg.image
        version = server_version if server_version is not None else pkg.version
        try:
            with Timer() as t:
                epk, esk = self.kem.keygen()
                ch = tlv(b"CH", os.urandom(32), epk)
            ch = w.send("V", "client_hello", ch, t.s)
            with Timer() as t:
                _, _, epk_in = untlv(ch)
                ct_e, ss_e = self.kem.encaps(epk_in)
                sh = tlv(b"SH", ct_e)
                k1 = P.hkdf(ss_e, b"hs1" + P.sha256(ch, sh))
                certs = self.srv_cert.encode() + self.int_cert.encode()
                fl2 = sh + _enc(k1, tlv(certs, b"CertificateRequest"))
            fl2 = w.send("S", "server_hello_cert", fl2, t.s)
            with Timer() as t:
                sh_in = fl2[: len(sh)]
                _, ct_e_in = untlv(sh_in)
                ss_e_c = self.kem.decaps(esk, ct_e_in)
                k1c = P.hkdf(ss_e_c, b"hs1" + P.sha256(ch, sh_in))
                certs_in, _ = untlv(_dec(k1c, fl2[len(sh):]))
                if not (verify_cert(self.int_cert, self.ca, self.root_pk) and verify_cert(self.srv_cert, self.ca, self.int_pk)):
                    raise Reject("chain")
                ct_s, ss_s = self.kem.encaps(self.srv_cert.pk)
                k2c = P.hkdf(ss_e_c + ss_s, b"hs2" + P.sha256(ch, sh_in, certs_in, ct_s))
                fl3 = ct_s + _enc(k2c, veh.keys["cert"].encode())
            fl3 = w.send("V", "client_kem_cert", fl3, t.s)
            with Timer() as t:
                ct_s_in = fl3[: self.kem.ct_len]
                ss_s_s = self.kem.decaps(self.srv_sk, ct_s_in)
                k2 = P.hkdf(ss_e + ss_s_s, b"hs2" + P.sha256(ch, sh, certs, ct_s_in))
                _dec(k2, fl3[self.kem.ct_len:])
                vcert = self.vehicles[vid].keys["cert"]
                if not verify_cert(vcert, self.ca, self.int_pk):
                    raise Reject("client chain")
                ct_c, ss_c = self.kem.encaps(vcert.pk)
                ms = P.hkdf(ss_e + ss_s_s + ss_c, b"master" + P.sha256(ch, sh, certs, fl3, ct_c))
                sfin = P.hmac256(P.hkdf(ms, b"s fin"), P.sha256(ch, sh, certs, fl3, ct_c))
                fl4 = ct_c + _enc(k2, sfin)
            fl4 = w.send("S", "server_kem_finished", fl4, t.s)
            with Timer() as t:
                ct_c_in = fl4[: self.kem.ct_len]
                ss_c_c = self.kem.decaps(veh.keys["sk"], ct_c_in)
                msc = P.hkdf(ss_e_c + ss_s + ss_c_c, b"master" + P.sha256(ch, sh_in, certs_in, fl3, ct_c_in))
                sfin_in = _dec(k2c, fl4[self.kem.ct_len:])
                if not P.ct_eq(sfin_in, P.hmac256(P.hkdf(msc, b"s fin"), P.sha256(ch, sh_in, certs_in, fl3, ct_c_in))):
                    raise Reject("server Finished")
                cfin = P.hmac256(P.hkdf(msc, b"c fin"), sfin_in)
                fl5 = _enc(P.hkdf(msc, b"c ap"), tlv(cfin, b"GET /update HTTP/1.1"))
            fl5 = w.send("V", "client_finished_get", fl5, t.s)
            with Timer() as t:
                cfin_in, _ = untlv(_dec(P.hkdf(ms, b"c ap"), fl5))
                if not P.ct_eq(cfin_in, P.hmac256(P.hkdf(ms, b"c fin"), sfin)):
                    raise Reject("client Finished")
                tr.notes["vehicle_authenticated"] = True
                app = P.hkdf(ms, b"s ap")
                ivs = P.hkdf(app, b"iv", 12)
                pre = tlv(self.man_body, self.man_sig) if self.oem else b""
            s_pre = t.s
            n_rec = -(-len(image) // self.record) + 1
            wire = len(image) + n_rec * 22 + len(pre)
            if bulk_real:
                with Timer() as te:
                    recs = tls_records_encrypt(app, ivs, tlv(pre, image) if self.oem else image, self.record)
                s_bulk = te.s
            else:
                recs = []
                s_bulk, v_bulk = self._sample_bulk(pkg, rng)
            recs = w.send_content("S", "package", recs, s_pre + s_bulk, nbytes=wire)
            if bulk_real:
                with Timer() as t:
                    appc = P.hkdf(msc, b"s ap")
                    data = tls_records_decrypt(appc, P.hkdf(appc, b"iv", 12), recs)
                    if self.oem:
                        mb, img = untlv(data)
                        body, sg = untlv(mb)
                        f = self.oem.verify(body, sg, veh, pkg.hw_id)
                        if not P.ct_eq(P.sha256(img), f[6]):
                            raise Reject("image hash != OEM manifest")
                    else:
                        img = data
                tr.final_vehicle_cpu = t.s
                self._record_bulk(pkg, s_bulk, t.s)
                tr.installed_ok = img == pkg.image
            else:
                tr.final_vehicle_cpu = v_bulk
                tr.installed_ok = True
                tr.notes["bulk"] = "calibrated"
            tr.accepted = True
            veh.current_version = version
        except Reject as e:
            tr.accepted, tr.reason = False, str(e)
        return tr


# =============================================================================== encrypt-once family
def merkle_root_and_path(leaves: list[bytes], idx: int):
    lvl = leaves[:]
    path = []
    while len(lvl) > 1:
        if len(lvl) % 2:
            lvl.append(lvl[-1])
        path.append(lvl[idx ^ 1])
        lvl = [P.sha256(b"\x01", lvl[i], lvl[i + 1]) for i in range(0, len(lvl), 2)]
        idx >>= 1
    return lvl[0], path


def merkle_check(root: bytes, leaf: bytes, idx: int, path: list[bytes]) -> bool:
    h = leaf
    for sib in path:
        h = P.sha256(b"\x01", h, sib) if idx % 2 == 0 else P.sha256(b"\x01", sib, h)
        idx >>= 1
    return P.ct_eq(h, root)


class WrapOnceOTA(Protocol):
    """Encrypt-once STREAM content + per-vehicle KEM key wrap + (batched) Director authorization.

    batch:     None -> one Director signature per token; int B -> Merkle batch, one signature per window.
    fs:        add a fresh ephemeral ML-KEM-768 key from the vehicle (forward secrecy of k_v).
    Ablation switches (defaults = full design):
    per_vehicle_content  False: content encrypted once per release; True: encrypted per vehicle by the server.
    chunk_auth           "hashlist": OEM-signed per-chunk hash list (verify-before-decrypt, any mirror);
                         "digest":   OEM signs only the plaintext digest (verify after full download).
    oem_offline          True: manifest signed by the offline OEM key; False: by the online Director key.
    report               True: key-confirmation install report (implicit vehicle authentication).
    """

    family = "wraponce"
    content_resumable = True

    def __init__(self, kem="X-Wing", dir_sig="ML-DSA-65", oem_sig="ML-DSA-65", chunk=65536, batch=None, fs=False,
                 name=None, short=None, per_vehicle_content=False, chunk_auth="hashlist", oem_offline=True,
                 report=True):
        super().__init__()
        self.kem, self.dsig, self.osig = P.kem(kem), P.sig(dir_sig), P.sig(oem_sig)
        self.eph = P.kem("ML-KEM-768") if fs else None
        self.chunk, self.batch, self.fs = chunk, batch, fs
        self.per_vehicle_content = per_vehicle_content
        self.chunk_auth = "digest" if per_vehicle_content else chunk_auth
        self.oem_offline, self.report = oem_offline, report
        self.name = name or f"WrapOnce[{kem}/{dir_sig}/{chunk // 1024}K/batch={batch}/fs={fs}]"
        self.short = short or self.name
        self.pq_confidentiality = self.kem.post_quantum
        self.batch_sign_cpu: list[float] = []

    def setup(self, n):
        self.oem = OEMSigner(self.osig)
        self.dir_pk, self.dir_sk = self.dsig.keygen()
        self.registry = {}  # Director database: VID -> provisioned static KEM public key
        for i in range(n):
            vid = os.urandom(16)
            pk, sk = self.kem.keygen()
            vs = VehicleState(vid)
            vs.keys.update(pk=pk, sk=sk)
            self.vehicles[vid] = vs
            self.registry[vid] = pk

    # ---- manifest signing: offline OEM key (default) or online Director key (ablation)
    def _sign_manifest(self, pkg, content_digest, extra):
        if self.oem_offline:
            return self.oem.manifest(pkg, self.now, content_digest, extra)
        body = tlv(b"manifest", pkg.release_id, pkg.hw_id, u64(pkg.version), u64(self.now + 30 * DAY),
                   u64(len(pkg.image)), content_digest, extra)
        return body, self.dsig.sign(self.dir_sk, body)

    def _verify_manifest(self, body, sg, veh, hw):
        if self.oem_offline:
            return self.oem.verify(body, sg, veh, hw)
        if not self.dsig.verify(self.dir_pk, body, sg):
            raise Reject("manifest signature")
        f = untlv(body)
        if f[2] != hw:
            raise Reject("hw mismatch")
        if rd64(f[3]) <= veh.current_version:
            raise Reject("rollback")
        if rd64(f[4]) < veh.clock:
            raise Reject("manifest expired (freeze)")
        return f

    def _content(self, image, k_c, prefix):
        frames = stream_encrypt(k_c, prefix, image, self.chunk)
        if self.chunk_auth == "hashlist":
            hl = b"".join(P.sha256(f) for f in frames)
            digest = P.sha256(hl)
        else:
            hl = b""
            digest = P.sha256(image)
        return frames, hl, digest

    def release(self, pkg):
        with Timer() as t:
            self.k_c = os.urandom(32)
            self.prefix = os.urandom(16)
            if not self.per_vehicle_content:
                self.frames, self.hashlist, digest = self._content(pkg.image, self.k_c, self.prefix)
                extra = tlv(u64(self.chunk), u64(len(self.frames)), self.prefix)
            else:  # content is encrypted per vehicle in session(); the OEM signs the plaintext digest
                self.frames, self.hashlist, digest = None, b"", P.sha256(pkg.image)
                extra = tlv(u64(self.chunk), u64(-(-len(pkg.image) // self.chunk)), b"")
            self.man_body, self.man_sig = self._sign_manifest(pkg, digest, extra)
        self.release_cpu = t.s
        n_fr = -(-len(pkg.image) // self.chunk)
        self.content_bytes = len(pkg.image) + 16 * n_fr

    def _token(self, vid, pkg, n_v, pk_v, epk, k_c):
        ct_v, ss_v = self.kem.encaps(pk_v)
        ct_e, ss_e = (self.eph.encaps(epk) if self.fs else (b"", b""))
        k = P.hkdf(ss_v + ss_e, b"wrap" + vid + pkg.release_id + n_v, 64)
        k_wrap, k_conf = k[:32], k[32:]
        wrap = P.AEAD(k_wrap).seal(b"\x00" * 12, k_c, vid + pkg.release_id)
        tok = tlv(b"auth", vid, pkg.release_id, n_v, u64(self.now), u64(self.now + DAY), ct_v, ct_e, wrap)
        return tok, k_conf

    def session(self, vid, pkg, adv=None, bulk_real=True, rng=None, server_image=None, server_version=None):
        adv = adv or Adversary()
        rng = rng or random.Random()
        tr = Trace(resumable=True)
        w = Wire(tr, adv)
        veh = self.vehicles[vid]
        try:
            with Timer() as t:
                n_v = os.urandom(16)
                epk, esk = self.eph.keygen() if self.fs else (b"", None)
                req = tlv(vid, n_v, u64(veh.current_version), epk)
            req = w.send("V", "auth_request", req, t.s)
            # ---- Director: per-vehicle token (+ per-vehicle content in the ablation)
            with Timer() as t:
                rvid, rn, rcur, repk = untlv(req)
                if rvid not in self.registry:
                    raise Reject("unknown vehicle")
                if self.per_vehicle_content:
                    k_c, prefix = os.urandom(32), os.urandom(16)
                else:
                    k_c, prefix = self.k_c, self.prefix
                tok, k_conf_s = self._token(rvid, pkg, rn, self.registry[rvid], repk, k_c)
                leaf = P.sha256(b"\x00", tok)
            per_vehicle_cpu = t.s
            if self.batch:
                B = self.batch
                idx = rng.randrange(B)
                leaves = [os.urandom(32) for _ in range(B)]  # other vehicles' token hashes in this window
                leaves[idx] = leaf
                with Timer() as tb:
                    root, path = merkle_root_and_path(leaves, idx)
                    body = tlv(b"batch", root, u64(self.now), u64(self.now + DAY))
                    bsig = self.dsig.sign(self.dir_sk, body)
                self.batch_sign_cpu.append(tb.s)
                tr.notes["batch_sign_cpu"] = tb.s
                auth = tlv(tok, u64(idx), b"".join(path), body, bsig)
                srv_cpu = per_vehicle_cpu  # the shared batch cost is charged by netsim (amortised)
            else:
                with Timer() as tb:
                    dsg = self.dsig.sign(self.dir_sk, tok)
                auth = tlv(tok, b"", b"", b"", dsg)
                srv_cpu = per_vehicle_cpu + tb.s
            man_body, man_sig, hashlist, frames = self.man_body, self.man_sig, self.hashlist, self.frames
            srv_bulk = 0.0
            image = pkg.image
            if server_image is not None or server_version is not None:
                # compromised Director: controls every online key, never the offline OEM key
                image = server_image if server_image is not None else pkg.image
                fake = Package(image, server_version if server_version is not None else pkg.version,
                               pkg.hw_id, pkg.release_id)
                frames, hashlist, digest = self._content(image, k_c, prefix)
                extra = tlv(u64(self.chunk), u64(len(frames)), prefix)
                if self.oem_offline:
                    man_body, _ = self.oem.manifest(fake, self.now, digest, extra)  # no OEM signature available
                else:
                    man_body, man_sig = self._sign_manifest(fake, digest, extra)
            elif self.per_vehicle_content:
                if bulk_real or not self.has_bulk_samples(pkg, 1):
                    with Timer() as te:
                        frames, _, _ = self._content(image, k_c, prefix)
                    srv_bulk = te.s
                else:
                    srv_bulk = self._sample_bulk(pkg, rng)[0]
                    frames = None
            resp = tlv(auth, man_body, man_sig, hashlist, prefix if self.per_vehicle_content else b"")
            resp = w.send("S", "authorization", resp, srv_cpu, batched=bool(self.batch))
            # ---- Vehicle: verify Director authorization and manifest; unwrap K_c
            with Timer() as t:
                auth_in, mb, ms, hl, pv_prefix = untlv(resp)
                tok_in, idx_b, path_b, body_in, sg_in = untlv(auth_in)
                if self.batch:
                    root_in = untlv(body_in)[1]
                    path_in = [path_b[i:i + 32] for i in range(0, len(path_b), 32)]
                    if not merkle_check(root_in, P.sha256(b"\x00", tok_in), rd64(idx_b), path_in):
                        raise Reject("batch path")
                    if not self.dsig.verify(self.dir_pk, body_in, sg_in):
                        raise Reject("Director signature")
                elif not self.dsig.verify(self.dir_pk, tok_in, sg_in):
                    raise Reject("Director signature")
                tf = untlv(tok_in)
                if tf[1] != vid or not P.ct_eq(tf[3], n_v):
                    raise Reject("token not for this request (replay)")
                if rd64(tf[5]) < veh.clock:
                    raise Reject("token expired")
                mf = self._verify_manifest(mb, ms, veh, pkg.hw_id)
                if mf[1] != tf[2]:
                    raise Reject("release binding")
                if self.chunk_auth == "hashlist" and not P.ct_eq(P.sha256(hl), mf[6]):
                    raise Reject("hash list")
                _, nch, prefix_m = untlv(mf[7])
                prefix_v = pv_prefix if self.per_vehicle_content else prefix_m
                ss_v = self.kem.decaps(veh.keys["sk"], tf[6])
                ss_e = self.eph.decaps(esk, tf[7]) if self.fs else b""
                k = P.hkdf(ss_v + ss_e, b"wrap" + vid + tf[2] + n_v, 64)
                try:
                    k_c_v = P.AEAD(k[:32]).open(b"\x00" * 12, tf[8], vid + tf[2])
                except Exception as e:
                    raise Reject("unwrap") from e
                k_conf_v = k[32:]
            v_auth_cpu = t.s
            # ---- content
            src = "S" if self.per_vehicle_content else "CDN"
            mc = not self.per_vehicle_content
            if not self.per_vehicle_content:
                # new TCP connection to a content source (CDN/mirror/depot AP) before the GET
                w.send("V", "cdn_syn", b"\x00" * 60, 0.0)
                w.send("CDN", "cdn_synack", b"\x00" * 60, 0.0)
            w.send("V", "content_get", b"GET /release/" + tf[2].hex().encode() + b" HTTP/1.1\r\nRange: bytes=0-\r\n\r\n", 0.0)
            wire = self.content_bytes if frames is None else sum(len(f) for f in frames)
            real = (bulk_real or server_image is not None or not self.has_bulk_samples(pkg, 1)) and frames is not None
            if real:
                frames_rx = w.send_content(src, "package", list(frames), srv_bulk, nbytes=wire, multicastable=mc)
                with Timer() as t:
                    if len(frames_rx) != rd64(nch):
                        raise Reject("chunk count")
                    if self.chunk_auth == "hashlist":
                        hashes = [hl[i:i + 32] for i in range(0, len(hl), 32)]
                        for i, f in enumerate(frames_rx):  # verify-before-decrypt, per chunk
                            if not P.ct_eq(P.sha256(f), hashes[i]):
                                raise Reject(f"chunk {i} hash")
                        img = stream_decrypt(k_c_v, prefix_v, frames_rx)
                    else:
                        img = stream_decrypt(k_c_v, prefix_v, frames_rx)
                        if not P.ct_eq(P.sha256(img), mf[6]):
                            raise Reject("image digest")
                v_bulk = t.s
                self._record_bulk(pkg, srv_bulk, v_bulk)
                tr.installed_ok = img == pkg.image
            else:
                w.send_content(src, "package", [], srv_bulk, nbytes=wire, multicastable=mc)
                v_bulk = self._sample_bulk(pkg, rng)[1]
                tr.installed_ok = True
                tr.notes["bulk"] = "calibrated"
            if self.report:
                report = tlv(vid, tf[2], b"INSTALLED", P.hmac256(k_conf_v, vid, tf[2], n_v, b"INSTALLED"))
                report = w.send("V", "install_report", report, v_auth_cpu + v_bulk)
                with Timer() as t:  # key confirmation = implicit vehicle authentication
                    rv, rrel, st, mac = untlv(report)
                    ok = P.ct_eq(mac, P.hmac256(k_conf_s, rv, rrel, rn, st))
                tr.final_server_cpu = t.s
                tr.notes["vehicle_authenticated"] = ok
                tr.final_vehicle_cpu = 0.0
            else:
                tr.final_vehicle_cpu = v_auth_cpu + v_bulk
                tr.notes["vehicle_authenticated"] = False
            tr.accepted = True
            veh.current_version = rd64(mf[3])
        except Reject as e:
            tr.accepted, tr.reason = False, str(e)
        return tr


# =============================================================================== registry
def build(name: str) -> Protocol:
    """Benchmarks (B*) and candidates (C*). Names are the identifiers used in all CSV files."""
    R = {
        # --- source paper and the source paper's own baselines
        "B01_SOURCE_REPRO": lambda: SourceOTA("ML-KEM-768", "ML-DSA-65", short="Source (Kyber768+Dilithium3+FRI)"),
        "B02_SRC_DH2048": lambda: SourceOTA("DH-2048", "RSA-2048", short="Source-DH2048"),
        "B03_SRC_RSA2048": lambda: SourceOTA("RSA-2048", "RSA-2048", short="Source-RSA2048"),
        "B04_SRC_McE_SPHINCS": lambda: SourceOTA("Classic-McEliece-348864", "SLH_DSA_PURE_SHA2_128F",
                                                 short="Source-McEliece+SPHINCS+"),
        "B05_SRC_FALCON": lambda: SourceOTA("ML-KEM-768", "Falcon-512", short="Source-Kyber+Falcon"),
        # --- standard secure channels
        "B06_TLS13_CLASSIC": lambda: TLS13OTA("X25519", "ECDSA-P256", "ECDSA-P256", short="TLS1.3 (X25519/ECDSA)"),
        "B07_TLS13_PQHYBRID": lambda: TLS13OTA("X-Wing", "ML-DSA-65", "ML-DSA-44", short="PQ-TLS1.3 (X25519MLKEM768/ML-DSA)"),
        "B08_UPTANE_CLASSIC": lambda: TLS13OTA("X25519", "ECDSA-P256", "ECDSA-P256", uptane_sig="Ed25519",
                                               short="Uptane (Ed25519) over TLS1.3"),
        "B09_UPTANE_PQ": lambda: TLS13OTA("X-Wing", "ML-DSA-65", "ML-DSA-44", uptane_sig="ML-DSA-65",
                                          short="PQ-Uptane (ML-DSA-65) over PQ-TLS1.3"),
        "B10_KEMTLS": lambda: KEMTLSOTA("ML-KEM-768", "ML-DSA-65", short="KEMTLS-mutual (ML-KEM-768)"),
        # --- candidates
        "C1_SIGMA_PQ": lambda: TLS13OTA("X-Wing", "ML-DSA-65", "ML-DSA-44", oem_sig="ML-DSA-65",
                                        short="C1 signed-transcript + OEM manifest"),
        "C2_KEMAUTH": lambda: KEMTLSOTA("X-Wing", "ML-DSA-65", oem_sig="ML-DSA-65", short="C2 KEM-auth + OEM manifest"),
        "C3_WRAPONCE": lambda: WrapOnceOTA("X-Wing", "ML-DSA-65", "ML-DSA-65", 65536, None, False,
                                           short="C3 encrypt-once + per-vehicle wrap"),
        "C4_WRAPONCE_BATCH": lambda: WrapOnceOTA("X-Wing", "ML-DSA-65", "ML-DSA-65", 65536, 64, False,
                                                 short="C4 encrypt-once + batched wrap"),
    }
    return R[name]()


BENCHMARKS = ["B01_SOURCE_REPRO", "B02_SRC_DH2048", "B03_SRC_RSA2048", "B04_SRC_McE_SPHINCS", "B05_SRC_FALCON",
              "B06_TLS13_CLASSIC", "B07_TLS13_PQHYBRID", "B08_UPTANE_CLASSIC", "B09_UPTANE_PQ", "B10_KEMTLS"]
CANDIDATES = ["C1_SIGMA_PQ", "C2_KEMAUTH", "C3_WRAPONCE", "C4_WRAPONCE_BATCH"]


# =============================================================================== frozen final model
_CFG_PATH = os.path.join(os.path.dirname(__file__), "..", "FINAL_MODEL_CONFIG.yaml")


def final_config(path: str = _CFG_PATH) -> dict:
    import yaml

    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def proposed_factory(cfg: dict, **override):
    kw = dict(kem=cfg["crypto"]["kem"], dir_sig=cfg["crypto"]["director_signature"],
              oem_sig=cfg["crypto"]["oem_signature"], chunk=cfg["delivery"]["chunk_bytes"],
              batch=cfg["authorization"]["batch_max"] if cfg["authorization"]["batched"] else None,
              fs=cfg["authorization"]["forward_secret_ephemeral"], chunk_auth=cfg["delivery"]["chunk_auth"],
              oem_offline=True, report=cfg["authorization"]["key_confirmation_report"], short=cfg["name"])
    kw.update(override)
    return lambda: WrapOnceOTA(**kw)


def ablation_factory(cfg: dict, name: str):
    return {
        "ABL_per_vehicle_content": lambda: proposed_factory(cfg, per_vehicle_content=True, short="- encrypt-once")(),
        "ABL_no_batch": lambda: proposed_factory(cfg, batch=None, short="- batched authorization")(),
        "ABL_digest_only": lambda: proposed_factory(cfg, chunk_auth="digest", short="- chunk hash list")(),
        "ABL_pure_mlkem": lambda: proposed_factory(cfg, kem="ML-KEM-768", short="- hybrid (ML-KEM-768 only)")(),
        "ABL_online_manifest": lambda: proposed_factory(cfg, oem_offline=False, short="- offline OEM key")(),
        "ABL_no_report": lambda: proposed_factory(cfg, report=False, short="- key-confirmation report")(),
        "SENS_director_mldsa44": lambda: proposed_factory(cfg, dir_sig="ML-DSA-44", short="Director ML-DSA-44 (FIPS 204)")(),
        "PM_level5": lambda: proposed_factory(cfg, kem="ML-KEM-1024", dir_sig="ML-DSA-87", oem_sig="ML-DSA-87",
                                              short="NIST level 5 parameters")(),
    }[name]
