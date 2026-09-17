import hashlib

from .base import Method
from .. import primitives as P
from ..meter import METER


class PWZAKE(Method):
    name = "PWZ-AKE"
    setting = "KK"
    reference = "pwz2023tighter"
    flows = 2

    def prefix(self, I, R):
        key = (I.id, R.id)
        if key not in self.cache:
            self.cache[key] = hashlib.sha3_256(I.static["ek"] + R.static["ek"])
        return self.cache[key]

    def finish(self, prefix, tail):
        METER.add("sym_hash", 1, len(tail))
        h = prefix.copy()
        h.update(tail)
        return h.digest()

    def steps(self, I, R):
        kem = self.kem
        prefix = self.prefix(I, R)

        def init(_):
            pk_t, sk_t = kem.keygen()
            K_j, ct_j = kem.encaps(R.static["ek"], R.static["h"], False)
            I.state = {"pk_t": pk_t, "sk_t": sk_t, "ct_j": ct_j, "K_j": K_j}
            return pk_t + ct_j

        def der_r(msg):
            pk_t = msg[: kem.ek_len]
            ct_j = msg[kem.ek_len:]
            K_j = kem.decaps(R.static["dk"], ct_j)
            K_t, ct_t = kem.encaps(pk_t)
            K_i, ct_i = kem.encaps(I.static["ek"], I.static["h"], False)
            R.key = self.finish(prefix, pk_t + ct_i + ct_j + ct_t + K_i + K_j + K_t)
            return ct_t + ct_i

        def der_i(msg):
            ct_t = msg[: kem.ct_len]
            ct_i = msg[kem.ct_len:]
            K_t = kem.decaps(I.state["sk_t"], ct_t)
            K_i = kem.decaps(I.static["dk"], ct_i)
            I.key = self.finish(prefix, I.state["pk_t"] + ct_i + I.state["ct_j"] + ct_t + K_i + I.state["K_j"] + K_t)
            I.state = {}
            return None

        return [("I", init), ("R", der_r), ("I", der_i)]
