from .base import Method
from .. import primitives as P

HARDEN = b"PKX-ML/harden"
BIND = b"PKX-ML/bind"


class PKXBase(Method):
    reference = "this work"
    mode = "compact"

    def harden(self, static, r):
        return P.sha3_256(HARDEN + self.kem.z_of(static["dk"]) + r)

    def eph_keygen(self, seed):
        if self.mode == "compact":
            ek_e, dk_e, h_e = self.kem.eph_keygen(seed)
            return ek_e, {"dk_e": dk_e, "h_e": h_e}
        ek_e, dk_e = self.kem.keygen_internal(seed, P.rand(32))
        return ek_e, {"dk_e": dk_e}


class PKXKK(PKXBase):
    name = "PKX-ML (ours)"
    setting = "KK"
    flows = 2

    def label(self):
        return b"PKX-ML/KK/" + self.mode.encode() + b"/" + str(self.level).encode()

    def steps(self, I, R):
        kem = self.kem
        compact = self.mode == "compact"
        head = self.label() + I.id + R.id

        def i1(_):
            seed = P.rand(64)
            ek_e, st = self.eph_keygen(seed[:32])
            st["K1"], c1 = kem.encaps_internal(R.static["ek"], self.harden(I.static, seed[32:]), R.static["h"], False)
            I.state = st
            return ek_e + c1

        def r1(msg):
            ek_e = msg[: kem.ek_len]
            K1 = kem.decaps(R.static["dk"], msg[kem.ek_len:])
            seed = P.rand(64)
            K2, c2 = kem.encaps_internal(ek_e, seed[:32])
            if compact:
                K2 = P.sha3_256(BIND + K2 + c2)
            K3, c3 = kem.encaps_internal(I.static["ek"], self.harden(R.static, seed[32:]), I.static["h"], False)
            R.key = P.sha3_256(head + K1 + K2 + K3)
            return c2 + c3

        def i2(msg):
            c2 = msg[: kem.ct_len]
            if compact:
                K2 = P.sha3_256(BIND + kem.decaps_light(I.state["dk_e"], I.state["h_e"], c2) + c2)
            else:
                K2 = kem.decaps(I.state["dk_e"], c2)
            K3 = kem.decaps(I.static["dk"], msg[kem.ct_len:])
            I.key = P.sha3_256(head + I.state["K1"] + K2 + K3)
            I.state = {}
            return None

        return [("I", i1), ("R", r1), ("I", i2)]


class PKXKKFull(PKXKK):
    name = "PKX-ML full (ours)"
    mode = "full"


class PKXXX(PKXBase):
    name = "PKX-ML (ours)"
    setting = "XX"
    flows = 4

    def label(self):
        return b"PKX-ML/XX/" + self.mode.encode() + b"/" + str(self.level).encode()

    def bind(self, K2, c2):
        if self.mode == "compact":
            return P.sha3_256(BIND + K2 + c2)
        return K2

    def steps(self, I, R):
        kem = self.kem
        compact = self.mode == "compact"

        def i1(_):
            ek_e, st = self.eph_keygen(P.rand(32))
            I.state = st
            return ek_e

        def r1(msg):
            K2, c2 = kem.encaps_internal(msg, P.rand(32))
            Ke = self.bind(K2, c2)
            R.state = {"Ke": Ke}
            return c2 + P.xor_stream(Ke, R.static["ek"], b"PKX-ML/XX/R")

        def i2(msg):
            c2 = msg[: kem.ct_len]
            if compact:
                K2 = kem.decaps_light(I.state["dk_e"], I.state["h_e"], c2)
            else:
                K2 = kem.decaps(I.state["dk_e"], c2)
            Ke = self.bind(K2, c2)
            ek_R = P.xor_stream(Ke, msg[kem.ct_len:], b"PKX-ML/XX/R")
            K1, c1 = kem.encaps_internal(ek_R, self.harden(I.static, P.rand(32)))
            I.state = {"K1": K1, "Ke": Ke}
            return c1 + P.xor_stream(K1 + Ke, I.static["ek"], b"PKX-ML/XX/I")

        def r2(msg):
            K1 = kem.decaps(R.static["dk"], msg[: kem.ct_len])
            ek_I = P.xor_stream(K1 + R.state["Ke"], msg[kem.ct_len:], b"PKX-ML/XX/I")
            K3, c3 = kem.encaps_internal(ek_I, self.harden(R.static, P.rand(32)))
            R.key = P.sha3_256(self.label() + K1 + R.state["Ke"] + K3)
            R.state = {}
            return c3

        def i3(msg):
            K3 = kem.decaps(I.static["dk"], msg)
            I.key = P.sha3_256(self.label() + I.state["K1"] + I.state["Ke"] + K3)
            I.state = {}
            return None

        return [("I", i1), ("R", r1), ("I", i2), ("R", r2), ("I", i3)]


class PKXXXFull(PKXXX):
    name = "PKX-ML full (ours)"
    mode = "full"
