from .base import Method
from .. import primitives as P


class FOAKE(Method):
    name = "FO-AKE"
    setting = "KK"
    reference = "hksu2020"
    flows = 2

    def static_keys(self):
        ek, dk = self.kem.keygen()
        return {"ek": ek, "dk": dk[: self.kem.dk_pke_len], "prf": P.rand(32)}

    def static_secret_size(self, static):
        return len(static["dk"]) + len(static["prf"])

    def G(self, m):
        return P.sha3_256(b"FOAKE/G" + m)

    def enc(self, pk, m, check):
        return self.kem.kpke_encrypt(pk, m, self.G(m), check)

    def steps(self, I, R):
        kem = self.kem
        ids = I.id + R.id

        def init(_):
            m_j = P.rand(32)
            c_j = self.enc(R.static["ek"], m_j, False)
            pk_t, sk_t = kem.kpke_keygen(P.rand(32))
            M = pk_t + c_j
            I.state = {"sk_t": sk_t, "m_j": m_j, "M": M}
            return M

        def der_resp(M):
            pk_t = M[: kem.ek_len]
            c_j = M[kem.ek_len:]
            m_i = P.rand(32)
            m_t = P.rand(32)
            c_i = self.enc(I.static["ek"], m_i, False)
            c_t = self.enc(pk_t, m_t, True)
            Mp = c_i + c_t
            m_jp = kem.kpke_decrypt(R.static["dk"], c_j)
            ok = self.enc(R.static["ek"], m_jp, False) == c_j
            k_ok = P.sha3_256(b"FOAKE/H" + m_i + m_jp + m_t + ids + M + Mp)
            k_rej = P.hmac_sha256(R.static["prf"], b"FOAKE/HR" + m_i + c_j + m_t + ids + M + Mp)
            R.key = k_ok if ok else k_rej
            return Mp

        def der_init(Mp):
            c_i = Mp[: kem.ct_len]
            c_t = Mp[kem.ct_len:]
            M = I.state["M"]
            m_ip = kem.kpke_decrypt(I.static["dk"], c_i)
            m_tp = kem.kpke_decrypt(I.state["sk_t"], c_t)
            ok = self.enc(I.static["ek"], m_ip, False) == c_i
            k_ok = P.sha3_256(b"FOAKE/H" + m_ip + I.state["m_j"] + m_tp + ids + M + Mp)
            k_rej = P.hmac_sha256(I.static["prf"], b"FOAKE/HL" + c_i + I.state["m_j"] + m_tp + ids + M + Mp)
            I.key = k_ok if ok else k_rej
            I.state = {}
            return None

        return [("I", init), ("R", der_resp), ("I", der_init)]
