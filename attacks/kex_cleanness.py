import hashlib
import os
import sys
from functools import lru_cache

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

from pkx.mlkem import MLKEM

CORRUPT = "corrupt"


def bracket_values(literals, ops):
    @lru_cache(maxsize=None)
    def rec(i, j):
        if i == j:
            return frozenset([literals[i]])
        out = set()
        for m in range(i, j):
            for a in rec(i, m):
                for b in rec(m + 1, j):
                    out.add((a or b) if ops[m] == "OR" else (a and b))
        return frozenset(out)

    return rec(0, len(literals) - 1)


def catalan_count(n):
    @lru_cache(maxsize=None)
    def c(k):
        if k <= 1:
            return 1
        return sum(c(i) * c(k - 1 - i) for i in range(k))

    return c(n - 1)


def adjacent_or(literals, ops):
    false_positions = [p for p, v in enumerate(literals) if not v]
    if len(false_positions) != 1:
        return None
    f = false_positions[0]
    left = ops[f - 1] if f > 0 else None
    right = ops[f] if f < len(ops) else None
    return left == "OR" or right == "OR"


DH_KEYS = {
    "I": {1: ("eph_i", "static_j"), 2: ("eph_i", "eph_j"), 3: ("static_i", "eph_j"), 4: ("static_i", "static_j")},
    "R": {1: ("eph_j", "static_i"), 2: ("eph_j", "eph_i"), 3: ("static_j", "eph_i"), 4: ("static_j", "static_i")},
}
KEM_KEYS = {
    "I": {1: ("static_j", "coins_i"), 2: ("eph_i", "coins_j"), 3: ("static_i", "coins_j")},
    "R": {1: ("static_i", "coins_j"), 2: ("eph_j", "coins_i"), 3: ("static_j", "coins_i")},
}

DEFINITIONS = [
    ("Definition 2", "Theorem 1", "DH.TTEE", "I", [["LSK_i"], ["RAND_i"], ["LSK_j"], ["RAND_j"], [], [], [], []], ["OR", "AND", "OR", "AND", "OR", "OR", "OR"], (1, 2, 3, 4), "R", 1),
    ("Definition 4", "Theorem 2", "KEM.TTE", "I", [["LSK_i", "RAND_j"], ["RAND_i", "LSK_j"], ["RAND_i", "RAND_j"], [], [], []], ["OR", "OR", "AND", "OR", "OR"], (1, 2, 3), "R", 1),
    ("Definition 9", "Theorem 6", "DH.TTEX", "I", [["LSK_i"], ["RAND_i"], ["LSK_j"], [], []], ["OR", "AND", "AND", "OR"], (1, 4), "I", 4),
    ("Definition 10", "Theorem 7", "DH.TXEE", "I", [["LSK_i"], ["RAND_i"], ["RAND_j"], [], []], ["OR", "AND", "AND", "OR"], (2, 3), "I", 3),
    ("Definition 11", "none", "DH.XTEE", "I", [["RAND_i"], ["LSK_j"], ["RAND_j"], [], []], ["AND", "OR", "OR", "OR"], (1, 2), "R", 1),
    ("Definition 12", "Theorem 8", "KEM.TTX", "I", [["LSK_i", "RAND_j"], ["RAND_i", "LSK_j"], [], []], ["OR", "AND", "OR"], (1, 3), "R", 1),
    ("Definition 13", "none", "KEM.KKX", "I", [["LSK_i", "RAND_j"], ["RAND_i", "LSK_j"], [], []], ["OR", "AND", "OR"], (1, 3), "R", 1),
    ("Definition 14", "Theorem 9", "KEM.XTE", "I", [["RAND_i", "LSK_j"], ["RAND_i", "RAND_j"], [], []], ["OR", "AND", "OR"], (1, 2), "R", 1),
    ("Definition 16", "Theorem 10", "KEM.TXE", "R", [["LSK_i", "RAND_j", "NA"], ["RAND_i", "RAND_j"], [], []], ["OR", "AND", "OR"], (2, 3), "I", 3),
]


def symbolic_check():
    rows = []
    for name, theorem, pattern, role, atoms, ops, keys, corrupted, tested in DEFINITIONS:
        atom = "LSK_i" if corrupted == role else "LSK_j"
        literals = tuple(atom not in group and "NA" not in group for group in atoms)
        values = bracket_values(literals, tuple(ops))
        table = (DH_KEYS if pattern.startswith("DH") else KEM_KEYS)[role]
        leaked = "static_i" if corrupted == role else "static_j"
        computable = tested in keys and leaked in table[tested]
        rows.append((name, theorem, pattern, role, corrupted, tested, catalan_count(len(literals)), values == frozenset([True]), literals.count(False), adjacent_or(literals, ops), computable))
    return rows


class KEXExperiment:
    def __init__(self):
        self.PK = {}
        self.LSK = {}
        self.RAND = {}
        self.OUT = {}
        self.IN = {}
        self.KEY = {}
        self.revealed = set()
        self.role = {}

    def open_session(self, party, sess, role):
        self.role[(party, sess)] = role
        self.OUT[(party, sess)] = [None, None]
        self.IN[(party, sess)] = [None, None]
        self.KEY[(party, sess)] = {}

    def sessions(self):
        return list(self.role.keys())

    def not_revealed(self, party, sess, ell):
        return (party, sess, ell) not in self.revealed


def reveal_guard(exp, i, s, ell, match):
    if not exp.not_revealed(i, s, ell):
        return False
    for (j, t) in exp.sessions():
        if (j, t) != (i, s) and match(j, t) and not exp.not_revealed(j, t, ell):
            return False
    return True


def kem_tte_trial(kem):
    exp = KEXExperiment()
    I, R = 0, 1
    ek = {}
    dk = {}
    for p in (I, R):
        ek[p], dk[p] = kem.keygen()
        exp.PK[p] = ek[p]
    exp.LSK[R] = CORRUPT
    leaked_dk_R = dk[R]
    s, t = 0, 0
    exp.open_session(I, s, "I")
    exp.open_session(R, t, "R")
    epk, esk = kem.keygen()
    exp.OUT[(I, s)][0] = epk
    exp.IN[(R, t)][0] = epk
    k2, ctxt_i = kem.encaps(epk)
    exp.OUT[(R, t)][0] = ctxt_i
    exp.OUT[(R, t)][1] = ek[R]
    exp.IN[(I, s)][0] = ctxt_i
    exp.IN[(I, s)][1] = ek[R]
    k1, ctxt_r = kem.encaps(ek[R])
    k2_i = kem.decaps(esk, ctxt_i)
    exp.OUT[(I, s)][1] = ek[I]
    exp.IN[(R, t)][1] = ek[I]
    k3, ctxt_i3 = kem.encaps(ek[I])
    k1_r = kem.decaps(dk[R], ctxt_r)
    k3_i = kem.decaps(dk[I], ctxt_i3)
    exp.KEY[(I, s)] = {1: k1, 2: k2_i, 3: k3_i}
    exp.KEY[(R, t)] = {1: k1_r, 2: k2, 3: k3}
    b = os.urandom(1)[0] & 1
    real = exp.KEY[(I, s)][1]
    challenge = real if b == 0 else os.urandom(32)
    guess = 0 if kem.decaps(leaked_dk_R, ctxt_r) == challenge else 1
    c1 = exp.LSK.get(I) != CORRUPT and any(
        exp.PK[I] == exp.IN[(j, u)][1] and exp.IN[(I, s)][1] == exp.OUT[(j, u)][1] and exp.RAND.get((j, u)) != CORRUPT
        for (j, u) in exp.sessions() if j != I)
    c2 = exp.RAND.get((I, s)) != CORRUPT and any(
        exp.IN[(I, s)][1] == exp.PK[j] and exp.OUT[(I, s)][1] == exp.IN[(j, u)][1] and exp.LSK.get(j) != CORRUPT
        for (j, u) in exp.sessions() if j != I)
    c3 = exp.RAND.get((I, s)) != CORRUPT and any(
        exp.OUT[(I, s)][0] == exp.IN[(j, u)][0] and exp.IN[(I, s)][0] == exp.OUT[(j, u)][0] and exp.RAND.get((j, u)) != CORRUPT
        for (j, u) in exp.sessions() if j != I)
    c4 = reveal_guard(exp, I, s, 1, lambda j, u: exp.IN[(I, s)][1] == exp.PK.get(j) and exp.OUT[(I, s)][1] == exp.IN[(j, u)][1])
    c5 = reveal_guard(exp, I, s, 2, lambda j, u: exp.OUT[(I, s)][0] == exp.IN[(j, u)][0] and exp.IN[(I, s)][0] == exp.OUT[(j, u)][0])
    c6 = reveal_guard(exp, I, s, 3, lambda j, u: exp.OUT[(I, s)][1] == exp.IN[(j, u)][1] and exp.IN[(I, s)][1] == exp.OUT[(j, u)][1])
    literals = (c1, c2, c3, c4, c5, c6)
    values = bracket_values(literals, ("OR", "OR", "AND", "OR", "OR"))
    return guess == b, values, literals


def x25519_pub(sk):
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ro(x):
    return hashlib.sha3_256(b"KEX-RO" + x).digest()


def dh_ttee_trial():
    exp = KEXExperiment()
    I, R = 0, 1
    a = X25519PrivateKey.generate()
    bkey = X25519PrivateKey.generate()
    exp.PK[I] = x25519_pub(a)
    exp.PK[R] = x25519_pub(bkey)
    exp.LSK[R] = CORRUPT
    leaked_b = bkey
    s, t = 0, 0
    exp.open_session(I, s, "I")
    exp.open_session(R, t, "R")
    x = X25519PrivateKey.generate()
    y = X25519PrivateKey.generate()
    gx, gy = x25519_pub(x), x25519_pub(y)
    exp.OUT[(I, s)][0] = gx
    exp.IN[(R, t)][0] = gx
    exp.OUT[(R, t)][0] = gy
    exp.OUT[(R, t)][1] = exp.PK[R]
    exp.IN[(I, s)][0] = gy
    exp.IN[(I, s)][1] = exp.PK[R]
    exp.OUT[(I, s)][1] = exp.PK[I]
    exp.IN[(R, t)][1] = exp.PK[I]
    pub = X25519PublicKey.from_public_bytes
    k1 = ro(x.exchange(pub(exp.PK[R])))
    k2 = ro(x.exchange(pub(gy)))
    k3 = ro(a.exchange(pub(gy)))
    k4 = ro(a.exchange(pub(exp.PK[R])))
    exp.KEY[(I, s)] = {1: k1, 2: k2, 3: k3, 4: k4}
    b = os.urandom(1)[0] & 1
    challenge = k1 if b == 0 else os.urandom(32)
    guess = 0 if ro(leaked_b.exchange(pub(gx))) == challenge else 1
    c1 = exp.LSK.get(I) != CORRUPT
    c2 = exp.RAND.get((I, s)) != CORRUPT
    c3 = any(exp.IN[(I, s)][1] == exp.PK[j] and exp.LSK.get(j) != CORRUPT for j in exp.PK if j != I)
    c4 = any(exp.IN[(I, s)][0] == exp.OUT[(j, u)][0] and exp.RAND.get((j, u)) != CORRUPT for (j, u) in exp.sessions() if j != I)
    c5 = reveal_guard(exp, I, s, 1, lambda j, u: exp.IN[(I, s)][1] == exp.PK.get(j) and exp.OUT[(I, s)][0] == exp.IN[(j, u)][0])
    c6 = reveal_guard(exp, I, s, 2, lambda j, u: exp.OUT[(I, s)][0] == exp.IN[(j, u)][0] and exp.IN[(I, s)][0] == exp.OUT[(j, u)][0])
    c7 = reveal_guard(exp, I, s, 3, lambda j, u: exp.OUT[(I, s)][1] == exp.IN[(j, u)][1] and exp.IN[(I, s)][0] == exp.OUT[(j, u)][0])
    c8 = reveal_guard(exp, I, s, 4, lambda j, u: exp.OUT[(I, s)][1] == exp.IN[(j, u)][1] and exp.IN[(I, s)][1] == exp.PK.get(j))
    literals = (c1, c2, c3, c4, c5, c6, c7, c8)
    values = bracket_values(literals, ("OR", "AND", "OR", "AND", "OR", "OR", "OR"))
    return guess == b, values, literals


def xxe_predicate_gap():
    exp = KEXExperiment()
    I, R = 0, 1
    s, t = 0, 0
    exp.open_session(I, s, "I")
    exp.open_session(R, t, "R")
    epk = os.urandom(32)
    reply = os.urandom(32)
    injected = os.urandom(32)
    exp.OUT[(I, s)][0] = epk
    exp.IN[(R, t)][0] = epk
    exp.OUT[(R, t)][0] = reply
    exp.IN[(I, s)][0] = injected
    rand_r = exp.RAND.get((R, t)) != CORRUPT
    guard = reveal_guard(exp, R, t, 2, lambda j, u: exp.IN[(R, t)][0] == exp.OUT[(j, u)][0] and exp.OUT[(R, t)][0] == exp.IN[(j, u)][0])
    dh_partner = any(exp.IN[(R, t)][0] == exp.OUT[(j, u)][0] and exp.RAND.get((j, u)) != CORRUPT for (j, u) in exp.sessions() if j != R)
    kem_partner = any(exp.OUT[(R, t)][0] == exp.IN[(j, u)][0] and exp.IN[(R, t)][0] == exp.OUT[(j, u)][0] and exp.RAND.get((j, u)) != CORRUPT for (j, u) in exp.sessions() if j != R)
    return rand_r and dh_partner and guard, rand_r and kem_partner and guard


def main(trials=200):
    for name, theorem, pattern, role, corrupted, tested, count, clean_all, false_count, adj, computable in symbolic_check():
        print(f"{name} ({pattern}, {theorem}): test session of {role}, OCorrupt on {corrupted}, OTest on key {tested}; clean under all {count} parenthesizations: {clean_all}; false literals: {false_count}, one of them next to OR: {adj}; tested key computable from the corrupted secret: {computable}")
    kem = MLKEM(768)
    wins = 0
    always_clean = True
    for _ in range(trials):
        ok, values, literals = kem_tte_trial(kem)
        wins += ok
        always_clean &= values == frozenset([True])
    print(f"KEM.TTE executed with ML-KEM-768: clean under all {catalan_count(6)} parenthesizations: {always_clean}; literals {literals}; adversary advantage {2 * wins / trials - 1:.3f}")
    wins = 0
    always_clean = True
    for _ in range(trials):
        ok, values, literals = dh_ttee_trial()
        wins += ok
        always_clean &= values == frozenset([True])
    print(f"DH.TTEE executed with X25519: clean under all {catalan_count(8)} parenthesizations: {always_clean}; literals {literals}; adversary advantage {2 * wins / trials - 1:.3f}")
    dh_clean, kem_clean = xxe_predicate_gap()
    print(f"responder test session whose initiator receives a replaced reply: clean for DH.XXEE: {dh_clean}; clean for KEM.XXE: {kem_clean}")


if __name__ == "__main__":
    main()
