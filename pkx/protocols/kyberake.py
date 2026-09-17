from .base import Method
from .. import primitives as P


class KyberAKE(Method):
    name = "Kyber.AKE"
    setting = "KK"
    reference = "bos2018kyber"
    flows = 2

    def steps(self, I, R):
        kem = self.kem

        def p1(_):
            pk, sk = kem.keygen()
            K2, c2 = kem.encaps(R.static["ek"], R.static["h"], False)
            I.state = {"sk": sk, "K2": K2}
            return pk + c2

        def p2(msg):
            K, c = kem.encaps(msg[: kem.ek_len])
            K1, c1 = kem.encaps(I.static["ek"], I.static["h"], False)
            K2 = kem.decaps(R.static["dk"], msg[kem.ek_len:])
            R.key = P.sha3_256(K + K1 + K2)
            return c + c1

        def p3(msg):
            Kp = kem.decaps(I.state["sk"], msg[: kem.ct_len])
            K1p = kem.decaps(I.static["dk"], msg[kem.ct_len:])
            I.key = P.sha3_256(Kp + K1p + I.state["K2"])
            I.state = {}
            return None

        return [("I", p1), ("R", p2), ("I", p3)]
