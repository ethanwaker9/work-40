from .base import Method
from .. import primitives as P

TAG = 16


class HashObject:
    def __init__(self, label):
        self.state = P.sha256(label)

    def _expand(self, m, n):
        tmp = P.hmac_sha256(self.state, m)
        outs = []
        last = b""
        for i in range(n + 1):
            last = P.hmac_sha256(tmp, last + bytes([i]))
            outs.append(last)
        return outs

    def input(self, m):
        outs = self._expand(m, 1)
        self.state = outs[0]
        return outs[1]

    def finalize(self, m):
        outs = self._expand(m, 1)
        return outs[0], outs[1]


class NoiseState:
    def __init__(self, label, h=None):
        self.h = P.sha256(label) if h is None else h
        self.ck = HashObject(label)
        self.n = 0

    def mix(self, data):
        self.h = P.sha256(self.h + data)

    def enc(self, key, pl):
        c = P.AEAD(key).enc(self.n, pl, self.h)
        self.n += 1
        self.mix(c)
        return c

    def dec(self, key, c):
        pl = P.AEAD(key).dec(self.n, c, self.h)
        self.n += 1
        self.mix(c)
        return pl


def seec_rand(static, n):
    return P.aes256_prp(static["seec"], P.rand(n))


class PQNoiseKK(Method):
    name = "PQNoise-KK"
    setting = "KK"
    reference = "angel2022pqnoise"
    flows = 2
    LABEL = b"pqKK_label"

    def static_keys(self):
        st = super().static_keys()
        st["seec"] = P.rand(32)
        return st

    def static_secret_size(self, static):
        return self.kem.dk_pke_len + 32 + len(static["seec"])

    def premessage_hash(self, I, R):
        key = (I.id, R.id)
        if key not in self.cache:
            h = P.sha256(self.LABEL)
            h = P.sha256(h)
            h = P.sha256(h + I.static["ek"])
            self.cache[key] = P.sha256(h + R.static["ek"])
        return self.cache[key]

    def steps(self, I, R):
        kem = self.kem
        h0 = self.premessage_hash(I, R)

        def send_i(_):
            ns = NoiseState(self.LABEL, h0)
            kk_R, ct_R = kem.encaps_internal(R.static["ek"], seec_rand(I.static, 32), R.static["h"], False)
            ns.mix(ct_R)
            k0 = ns.ck.input(kk_R)
            ns.n = 0
            coins = seec_rand(I.static, 64)
            pk_e, sk_e = kem.keygen_internal(coins[:32], coins[32:])
            c = ns.enc(k0, pk_e)
            I.ns = ns
            I.state = {"ck": ns.ck.state, "h": ns.h, "n": ns.n, "sk_e": sk_e}
            return ct_R + c

        def recv_send_r(msg):
            ns = NoiseState(self.LABEL, h0)
            ct_R = msg[: kem.ct_len]
            ns.mix(ct_R)
            kk_R = kem.decaps(R.static["dk"], ct_R)
            k0 = ns.ck.input(kk_R)
            ns.n = 0
            pk_e = ns.dec(k0, msg[kem.ct_len:])
            kk_e, ct_e = kem.encaps_internal(pk_e, seec_rand(R.static, 32))
            ns.mix(ct_e)
            k1 = ns.ck.input(kk_e)
            ns.n = 0
            kk_I, ct_I = kem.encaps_internal(I.static["ek"], seec_rand(R.static, 32), I.static["h"], False)
            c1 = ns.enc(k1, ct_I)
            pk_I, pk_R = ns.ck.finalize(kk_I)
            ns.n = 0
            c2 = ns.enc(pk_R, b"")
            R.key = pk_I + pk_R
            return ct_e + c1 + c2

        def recv_i(msg):
            ns = I.ns
            ct_e = msg[: kem.ct_len]
            ns.mix(ct_e)
            kk_e = kem.decaps(I.state["sk_e"], ct_e)
            k1 = ns.ck.input(kk_e)
            ns.n = 0
            off = kem.ct_len
            ct_I = ns.dec(k1, msg[off: off + kem.ct_len + TAG])
            kk_I = kem.decaps(I.static["dk"], ct_I)
            pk_I, pk_R = ns.ck.finalize(kk_I)
            ns.n = 0
            ns.dec(pk_R, msg[off + kem.ct_len + TAG:])
            I.key = pk_I + pk_R
            I.state = {}
            del I.ns
            return None

        return [("I", send_i), ("R", recv_send_r), ("I", recv_i)]


class PQNoiseXX(Method):
    name = "PQNoise-XX"
    setting = "XX"
    reference = "angel2022pqnoise"
    flows = 4
    LABEL = b"pqXX_label"

    def static_keys(self):
        st = super().static_keys()
        st["seec"] = P.rand(32)
        return st

    def static_secret_size(self, static):
        return self.kem.dk_pke_len + 32 + len(static["seec"])

    def steps(self, I, R):
        kem = self.kem
        ctt = kem.ct_len + TAG
        pkt = kem.ek_len + TAG

        def send_i1(_):
            ns = NoiseState(self.LABEL)
            ns.mix(b"")
            coins = seec_rand(I.static, 64)
            pk_e, sk_e = kem.keygen_internal(coins[:32], coins[32:])
            ns.mix(pk_e)
            I.ns = ns
            I.state = {"ck": ns.ck.state, "h": ns.h, "sk_e": sk_e}
            return pk_e

        def recv_send_r1(msg):
            ns = NoiseState(self.LABEL)
            ns.mix(b"")
            ns.mix(msg)
            kk_e, ct_e = kem.encaps_internal(msg, seec_rand(R.static, 32))
            ns.mix(ct_e)
            k0 = ns.ck.input(kk_e)
            ns.n = 0
            c = ns.enc(k0, R.static["ek"])
            R.ns = ns
            R.k0 = k0
            R.state = {"ck": ns.ck.state, "h": ns.h, "n": ns.n, "k0": k0}
            return ct_e + c

        def recv_send_i2(msg):
            ns = I.ns
            ct_e = msg[: kem.ct_len]
            ns.mix(ct_e)
            kk_e = kem.decaps(I.state["sk_e"], ct_e)
            k0 = ns.ck.input(kk_e)
            ns.n = 0
            pk_R = ns.dec(k0, msg[kem.ct_len:])
            kk_R, ct_R = kem.encaps_internal(pk_R, seec_rand(I.static, 32))
            c1 = ns.enc(k0, ct_R)
            k1 = ns.ck.input(kk_R)
            ns.n = 0
            c2 = ns.enc(k1, I.static["ek"])
            I.k1 = k1
            I.state = {"ck": ns.ck.state, "h": ns.h, "n": ns.n, "k1": k1}
            return c1 + c2

        def recv_send_r2(msg):
            ns = R.ns
            ct_R = ns.dec(R.k0, msg[:ctt])
            kk_R = kem.decaps(R.static["dk"], ct_R)
            k1 = ns.ck.input(kk_R)
            ns.n = 0
            pk_I = ns.dec(k1, msg[ctt: ctt + pkt])
            kk_I, ct_I = kem.encaps_internal(pk_I, seec_rand(R.static, 32))
            c1 = ns.enc(k1, ct_I)
            pk_Ik, pk_Rk = ns.ck.finalize(kk_I)
            ns.n = 0
            c2 = ns.enc(pk_Rk, b"")
            R.key = pk_Ik + pk_Rk
            R.state = {}
            del R.ns, R.k0
            return c1 + c2

        def recv_i2(msg):
            ns = I.ns
            ct_I = ns.dec(I.k1, msg[:ctt])
            kk_I = kem.decaps(I.static["dk"], ct_I)
            pk_Ik, pk_Rk = ns.ck.finalize(kk_I)
            ns.n = 0
            ns.dec(pk_Rk, msg[ctt:])
            I.key = pk_Ik + pk_Rk
            I.state = {}
            del I.ns, I.k1
            return None

        return [("I", send_i1), ("R", recv_send_r1), ("I", recv_send_i2), ("R", recv_send_r2), ("I", recv_i2)]
