from .base import Method
from .. import primitives as P


class KEXKKE(Method):
    name = "KEX-KKE"
    setting = "KK"
    reference = "dowling2026kex"
    flows = 2

    def steps(self, I, R):
        kem = self.kem

        def start(_):
            epk, esk = kem.keygen()
            k1, sct = kem.encaps(R.static["ek"], R.static["h"], False)
            I.state = {"esk": esk, "k1": k1}
            return epk + sct

        def reply(msg):
            epk = msg[: kem.ek_len]
            k1 = kem.decaps(R.static["dk"], msg[kem.ek_len:])
            k2, ect = kem.encaps(epk)
            k3, sct = kem.encaps(I.static["ek"], I.static["h"], False)
            R.key = P.sha3_256(k1 + k2 + k3)
            return ect + sct

        def proc(msg):
            k2 = kem.decaps(I.state["esk"], msg[: kem.ct_len])
            k3 = kem.decaps(I.static["dk"], msg[kem.ct_len:])
            I.key = P.sha3_256(I.state["k1"] + k2 + k3)
            I.state = {}
            return None

        return [("I", start), ("R", reply), ("I", proc)]


class KEXTTE(Method):
    name = "KEX-TTE"
    setting = "XX"
    reference = "dowling2026kex"
    flows = 4

    def steps(self, I, R):
        kem = self.kem

        def start(_):
            epk, esk = kem.keygen()
            I.state = {"esk": esk}
            return epk

        def reply(msg):
            k1, ctxt = kem.encaps(msg)
            R.state = {"k1": k1}
            return ctxt + R.static["ek"]

        def proc(msg):
            ctxt = msg[: kem.ct_len]
            k2, ctxt_R = kem.encaps(msg[kem.ct_len:])
            k1 = kem.decaps(I.state["esk"], ctxt)
            I.state = {"k1": k1, "k2": k2}
            return ctxt_R + I.static["ek"]

        def fin(msg):
            k3, ctxt_I = kem.encaps(msg[kem.ct_len:])
            k2 = kem.decaps(R.static["dk"], msg[: kem.ct_len])
            R.key = P.sha3_256(R.state["k1"] + k2 + k3)
            R.state = {}
            return ctxt_I

        def accept(msg):
            k3 = kem.decaps(I.static["dk"], msg)
            I.key = P.sha3_256(I.state["k1"] + I.state["k2"] + k3)
            I.state = {}
            return None

        return [("I", start), ("R", reply), ("I", proc), ("R", fin), ("I", accept)]
