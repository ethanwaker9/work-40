import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

from pkx.mlkem import MLKEM, byte_decode, byte_encode, compress, decompress, Q
import numpy as np

REFERENCE = {512: ML_KEM_512, 768: ML_KEM_768, 1024: ML_KEM_1024}


def check_level(level, trials):
    ref = REFERENCE[level]
    ours = MLKEM(level)
    for _ in range(trials):
        d = os.urandom(32)
        z = os.urandom(32)
        m = os.urandom(32)
        ek_r, dk_r = ref._keygen_internal(d, z)
        ek_o, dk_o = ours.keygen_internal(d, z)
        assert ek_r == ek_o
        assert dk_r == dk_o
        K_r, c_r = ref._encaps_internal(ek_r, m)
        K_o, c_o = ours.encaps_internal(ek_o, m)
        assert K_r == K_o
        assert c_r == c_o
        assert ours.decaps(dk_o, c_o) == ref._decaps_internal(dk_r, c_r) == K_o
        bad = bytearray(c_o)
        bad[os.urandom(1)[0] % len(bad)] ^= 1 << (os.urandom(1)[0] % 8)
        bad = bytes(bad)
        assert ours.decaps(dk_o, bad) == ref._decaps_internal(dk_r, bad)
        dk_pke = dk_o[: ours.dk_pke_len]
        assert ours.kpke_decrypt(dk_pke, c_o) == ref._k_pke_decrypt(dk_pke, c_o)
        ek_e, dk_e, h_e = ours.eph_keygen(d)
        assert ek_e == ek_o
        assert dk_e == dk_pke
        assert h_e == dk_o[768 * ours.k + 32: 768 * ours.k + 64]
        assert ours.decaps_light(dk_e, h_e, c_o) == K_o


def check_codecs():
    rng = np.random.default_rng(7)
    for d in range(1, 12):
        x = rng.integers(0, 1 << d, size=(3, 256))
        assert np.array_equal(byte_decode(byte_encode(x, d), d, 3), x)
    x = rng.integers(0, Q, size=(2, 256))
    assert np.array_equal(byte_decode(byte_encode(x, 12), 12, 2), x)
    for d in (1, 4, 5, 10, 11):
        x = np.arange(Q)
        err = (decompress(compress(x, d), d) - x) % Q
        err = np.minimum(err, Q - err)
        assert err.max() <= (Q + (1 << d)) // (1 << (d + 1))


def main():
    check_codecs()
    for level in (512, 768, 1024):
        check_level(level, 25)
    print("ML-KEM backend matches the reference implementation for ML-KEM-512, ML-KEM-768 and ML-KEM-1024")


if __name__ == "__main__":
    main()
