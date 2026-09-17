import struct
import time

from .base import Method
from .. import primitives as P

LBL1 = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
LBL2 = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LBL3 = b"mac1----"
COOKIE = bytes(16)
EMPTY = b""


def kdf(key, data, n):
    return P.noise_hkdf(P.hmac_blake2s, key, data, n)


def tai64n():
    now = time.time()
    return struct.pack(">QI", 0x400000000000000A + int(now), int((now % 1) * 1e9))


class PQWireGuard(Method):
    name = "PQ-WireGuard"
    setting = "KK"
    reference = "hulsing2021pqwg"
    flows = 3

    def static_keys(self):
        st = super().static_keys()
        st["sigma"] = P.rand(32)
        return st

    def static_secret_size(self, static):
        return self.kem.dk_pke_len + 32 + len(static["sigma"])

    def context(self, I, R):
        key = (I.id, R.id)
        if key not in self.cache:
            spk_i = I.static["ek"]
            spk_r = R.static["ek"]
            C1 = P.blake2s(LBL1)
            H1 = P.blake2s(C1 + LBL2)
            self.cache[key] = {
                "C1": C1,
                "H2": P.blake2s(H1 + spk_r),
                "psk": P.blake2s(bytes(a ^ b for a, b in zip(spk_i, spk_r))),
                "hid": P.blake2s(spk_i),
                "mac_r": P.blake2s(LBL3 + spk_r),
                "mac_i": P.blake2s(LBL3 + spk_i),
            }
        return self.cache[key]

    def steps(self, I, R):
        kem = self.kem
        ctx = self.context(I, R)
        C1 = ctx["C1"]
        H2 = ctx["H2"]
        psk = ctx["psk"]

        def init_hello(_):
            epk_i, esk_i, h_e = kem.eph_keygen(P.rand(32))
            sid_i = P.rand(4)
            shk1, ct1 = kem.encaps_internal(R.static["ek"], kdf(I.static["sigma"], P.rand(32), 1)[0], R.static["h"], False)
            C2 = kdf(C1, epk_i, 1)[0]
            H3 = P.blake2s(H2 + epk_i)
            C3, k3 = kdf(C2, shk1, 2)
            ltk = P.AEAD(k3).enc(0, ctx["hid"], H3)
            H4 = P.blake2s(H3 + ltk)
            C4, k4 = kdf(C3, psk, 2)
            tstamp = P.AEAD(k4).enc(0, tai64n(), H4)
            H5 = P.blake2s(H4 + tstamp)
            body = b"\x01\x00\x00\x00" + sid_i + epk_i + ct1 + ltk + tstamp
            m1 = P.blake2s_mac(ctx["mac_r"], body)
            m2 = P.blake2s_mac(COOKIE, body + m1)
            I.state = {"esk": esk_i, "h_e": h_e, "sid": sid_i, "C4": C4, "H5": H5}
            return body + m1 + m2

        def resp_hello(msg):
            body = msg[:-32]
            m1 = msg[-32:-16]
            if P.blake2s_mac(ctx["mac_r"], body) != m1 or P.blake2s_mac(COOKIE, body + m1) != msg[-16:]:
                raise ValueError("mac")
            off = 8
            sid_i = body[4:8]
            epk_i = body[off: off + kem.ek_len]
            off += kem.ek_len
            ct1 = body[off: off + kem.ct_len]
            off += kem.ct_len
            ltk = body[off: off + 48]
            tstamp = body[off + 48:]
            shk1 = kem.decaps(R.static["dk"], ct1)
            C2 = kdf(C1, epk_i, 1)[0]
            H3 = P.blake2s(H2 + epk_i)
            C3, k3 = kdf(C2, shk1, 2)
            if P.AEAD(k3).dec(0, ltk, H3) != ctx["hid"]:
                raise ValueError("identity")
            H4 = P.blake2s(H3 + ltk)
            C4, k4 = kdf(C3, psk, 2)
            P.AEAD(k4).dec(0, tstamp, H4)
            H5 = P.blake2s(H4 + tstamp)
            shk2, ct2 = kem.encaps_internal(epk_i, P.rand(32))
            shk3, ct3 = kem.encaps_internal(I.static["ek"], kdf(R.static["sigma"], P.rand(32), 1)[0], I.static["h"], False)
            sid_r = P.rand(4)
            C6 = kdf(C4, ct2, 1)[0]
            H6 = P.blake2s(H5 + ct2)
            C7 = kdf(C6, shk2, 1)[0]
            C8 = kdf(C7, shk3, 1)[0]
            C9, t9, k9 = kdf(C8, psk, 3)
            H9 = P.blake2s(H6 + t9)
            zero = P.AEAD(k9).enc(0, EMPTY, H9)
            C10, k10 = kdf(C9, EMPTY, 2)
            H10 = P.blake2s(H9 + zero)
            rbody = b"\x02\x00\x00\x00" + sid_r + sid_i + ct2 + ct3 + zero
            rm1 = P.blake2s_mac(ctx["mac_i"], rbody)
            rm2 = P.blake2s_mac(COOKIE, rbody + rm1)
            R.state = {"C10": C10, "k10": k10, "H10": H10, "sid_r": sid_r, "sid_i": sid_i}
            return rbody + rm1 + rm2

        def init_conf(msg):
            body = msg[:-32]
            m1 = msg[-32:-16]
            if P.blake2s_mac(ctx["mac_i"], body) != m1 or P.blake2s_mac(COOKIE, body + m1) != msg[-16:]:
                raise ValueError("mac")
            off = 12
            ct2 = body[off: off + kem.ct_len]
            off += kem.ct_len
            ct3 = body[off: off + kem.ct_len]
            zero = body[off + kem.ct_len:]
            sid_r = body[4:8]
            shk2 = kem.decaps_light(I.state["esk"], I.state["h_e"], ct2)
            shk3 = kem.decaps(I.static["dk"], ct3)
            C6 = kdf(I.state["C4"], ct2, 1)[0]
            H6 = P.blake2s(I.state["H5"] + ct2)
            C7 = kdf(C6, shk2, 1)[0]
            C8 = kdf(C7, shk3, 1)[0]
            C9, t9, k9 = kdf(C8, psk, 3)
            H9 = P.blake2s(H6 + t9)
            P.AEAD(k9).dec(0, zero, H9)
            C10, k10 = kdf(C9, EMPTY, 2)
            H10 = P.blake2s(H9 + zero)
            conf = P.AEAD(k10).enc(0, EMPTY, H10)
            cbody = b"\x03\x00\x00\x00" + I.state["sid"] + sid_r + conf
            cm1 = P.blake2s_mac(ctx["mac_r"], cbody)
            cm2 = P.blake2s_mac(COOKIE, cbody + cm1)
            tk_i, tk_r = kdf(C10, EMPTY, 2)
            I.key = tk_i + tk_r
            I.state = {}
            return cbody + cm1 + cm2

        def finish_r(msg):
            body = msg[:-32]
            m1 = msg[-32:-16]
            if P.blake2s_mac(ctx["mac_r"], body) != m1 or P.blake2s_mac(COOKIE, body + m1) != msg[-16:]:
                raise ValueError("mac")
            P.AEAD(R.state["k10"]).dec(0, body[12:], R.state["H10"])
            tk_i, tk_r = kdf(R.state["C10"], EMPTY, 2)
            R.key = tk_i + tk_r
            R.state = {}
            return None

        return [("I", init_hello), ("R", resp_hello), ("I", init_conf), ("R", finish_r)]
