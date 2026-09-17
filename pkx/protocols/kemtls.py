import hashlib

from .base import Method
from .. import primitives as P
from ..meter import METER

TAG = 16


class Transcript:
    def __init__(self):
        self.h = hashlib.sha256()

    def add(self, data):
        METER.add("sym_hash", 1, len(data))
        self.h.update(data)

    def digest(self):
        return self.h.copy().digest()


def expand(secret, label, context=b""):
    return P.hkdf_expand_label_sha256(secret, label, context)


def aead_key(secret):
    return expand(secret, b"key")


class KEMTLSMutual(Method):
    name = "KEMTLS-mutual"
    setting = "XX"
    reference = "ssw2020kemtls"
    flows = 6

    def steps(self, I, R):
        kem = self.kem
        zero = bytes(32)

        def client_hello(_):
            pk_e, sk_e = kem.keygen()
            ch = b"CH" + P.rand(32) + pk_e
            tr = Transcript()
            tr.add(ch)
            ES = P.hkdf_extract_sha256(zero, zero)
            dES = expand(ES, b"derived")
            I.tr = tr
            I.state = {"sk_e": sk_e, "dES": dES, "tr": b"\x00" * 104}
            return ch

        def server_hello(msg):
            pk_e = msg[34:]
            tr = Transcript()
            tr.add(msg)
            ES = P.hkdf_extract_sha256(zero, zero)
            dES = expand(ES, b"derived")
            ss_e, ct_e = kem.encaps(pk_e)
            sh = b"SH" + P.rand(32) + ct_e
            tr.add(sh)
            HS = P.hkdf_extract_sha256(dES, ss_e)
            th = tr.digest()
            CHTS = expand(HS, b"c hs traffic", th)
            SHTS = expand(HS, b"s hs traffic", th)
            dHS = expand(HS, b"derived")
            cert = P.AEAD(aead_key(SHTS)).enc(0, pk_e[:0] + R.static["ek"], b"")
            tr.add(cert)
            R.tr = tr
            R.state = {"CHTS": CHTS, "SHTS": SHTS, "dHS": dHS, "tr": b"\x00" * 104}
            return sh + cert

        def client_kem(msg):
            tr = I.tr
            sh = msg[: 34 + kem.ct_len]
            cert = msg[34 + kem.ct_len:]
            tr.add(sh)
            ss_e = kem.decaps(I.state["sk_e"], sh[34:])
            HS = P.hkdf_extract_sha256(I.state["dES"], ss_e)
            th = tr.digest()
            CHTS = expand(HS, b"c hs traffic", th)
            SHTS = expand(HS, b"s hs traffic", th)
            dHS = expand(HS, b"derived")
            pk_S = P.AEAD(aead_key(SHTS)).dec(0, cert, b"")
            tr.add(cert)
            ss_S, ct_S = kem.encaps(pk_S)
            ckc = P.AEAD(aead_key(CHTS)).enc(0, ct_S, b"")
            tr.add(ckc)
            AHS = P.hkdf_extract_sha256(dHS, ss_S)
            th = tr.digest()
            CAHTS = expand(AHS, b"c ahs traffic", th)
            SAHTS = expand(AHS, b"s ahs traffic", th)
            dAHS = expand(AHS, b"derived")
            ccert = P.AEAD(aead_key(CAHTS)).enc(0, I.static["ek"], b"")
            tr.add(ccert)
            I.state = {"CAHTS": CAHTS, "SAHTS": SAHTS, "dAHS": dAHS, "tr": b"\x00" * 104}
            return ckc + ccert

        def server_kem(msg):
            tr = R.tr
            ckc = msg[: kem.ct_len + TAG]
            ccert = msg[kem.ct_len + TAG:]
            ct_S = P.AEAD(aead_key(R.state["CHTS"])).dec(0, ckc, b"")
            tr.add(ckc)
            ss_S = kem.decaps(R.static["dk"], ct_S)
            AHS = P.hkdf_extract_sha256(R.state["dHS"], ss_S)
            th = tr.digest()
            CAHTS = expand(AHS, b"c ahs traffic", th)
            SAHTS = expand(AHS, b"s ahs traffic", th)
            dAHS = expand(AHS, b"derived")
            pk_C = P.AEAD(aead_key(CAHTS)).dec(0, ccert, b"")
            tr.add(ccert)
            ss_C, ct_C = kem.encaps(pk_C)
            skc = P.AEAD(aead_key(SAHTS)).enc(0, ct_C, b"")
            tr.add(skc)
            MS = P.hkdf_extract_sha256(dAHS, ss_C)
            R.state = {"CAHTS": CAHTS, "SAHTS": SAHTS, "MS": MS, "tr": b"\x00" * 104}
            return skc

        def client_finished(msg):
            tr = I.tr
            ct_C = P.AEAD(aead_key(I.state["SAHTS"])).dec(0, msg, b"")
            tr.add(msg)
            ss_C = kem.decaps(I.static["dk"], ct_C)
            MS = P.hkdf_extract_sha256(I.state["dAHS"], ss_C)
            fk_c = expand(MS, b"c finished")
            cf_mac = P.hmac_sha256(fk_c, tr.digest())
            cf = P.AEAD(aead_key(I.state["CAHTS"])).enc(1, cf_mac, b"")
            tr.add(cf)
            CATS = expand(MS, b"c ap traffic", tr.digest())
            I.state = {"MS": MS, "SAHTS": I.state["SAHTS"], "CATS": CATS, "tr": b"\x00" * 104}
            return cf

        def server_finished(msg):
            tr = R.tr
            fk_c = expand(R.state["MS"], b"c finished")
            cf_mac = P.AEAD(aead_key(R.state["CAHTS"])).dec(1, msg, b"")
            if cf_mac != P.hmac_sha256(fk_c, tr.digest()):
                raise ValueError("finished")
            tr.add(msg)
            CATS = expand(R.state["MS"], b"c ap traffic", tr.digest())
            fk_s = expand(R.state["MS"], b"s finished")
            sf = P.AEAD(aead_key(R.state["SAHTS"])).enc(1, P.hmac_sha256(fk_s, tr.digest()), b"")
            tr.add(sf)
            SATS = expand(R.state["MS"], b"s ap traffic", tr.digest())
            R.key = CATS + SATS
            R.state = {}
            del R.tr
            return sf

        def client_done(msg):
            tr = I.tr
            fk_s = expand(I.state["MS"], b"s finished")
            sf_mac = P.AEAD(aead_key(I.state["SAHTS"])).dec(1, msg, b"")
            if sf_mac != P.hmac_sha256(fk_s, tr.digest()):
                raise ValueError("finished")
            tr.add(msg)
            SATS = expand(I.state["MS"], b"s ap traffic", tr.digest())
            I.key = I.state["CATS"] + SATS
            I.state = {}
            del I.tr
            return None

        return [("I", client_hello), ("R", server_hello), ("I", client_kem), ("R", server_kem), ("I", client_finished), ("R", server_finished), ("I", client_done)]
