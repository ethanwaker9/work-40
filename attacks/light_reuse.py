import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from pkx.mlkem import MLKEM

BIND = b"PKX-ML/bind"


def maul(c):
    bad = bytearray(c)
    bad[-1] ^= 0x01
    return bytes(bad)


def bind(k, c):
    return hashlib.sha3_256(BIND + k + c).digest()


def main(trials=2000):
    for level in (512, 768, 1024):
        kem = MLKEM(level)
        ek, dk_pke, h = kem.eph_keygen(os.urandom(32))
        ek_full, dk_full = kem.keygen()
        same_raw = 0
        same_bound = 0
        same_full = 0
        for _ in range(trials):
            K, c = kem.encaps(ek)
            cm = maul(c)
            if kem.decaps_light(dk_pke, h, cm) == K:
                same_raw += 1
            if bind(kem.decaps_light(dk_pke, h, cm), cm) == bind(K, c):
                same_bound += 1
            Kf, cf = kem.encaps(ek_full)
            if kem.decaps(dk_full, maul(cf)) == Kf:
                same_full += 1
        print(f"ML-KEM-{level}: a mauled ephemeral ciphertext yields the sender shared secret under raw light decapsulation in {same_raw / trials:.4f} of trials, under the bound light decapsulation in {same_bound / trials:.4f} of trials, and under full decapsulation in {same_full / trials:.4f} of trials")


if __name__ == "__main__":
    main()
