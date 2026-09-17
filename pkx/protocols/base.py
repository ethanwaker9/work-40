import time

from ..mlkem import MLKEM
from .. import primitives as P


def state_size(state):
    total = 0
    for value in state.values():
        if isinstance(value, (bytes, bytearray)):
            total += len(value)
        elif isinstance(value, int):
            total += 8
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, (bytes, bytearray)):
                    total += len(item)
                elif isinstance(item, int):
                    total += 8
    return total


class Party:
    def __init__(self, role, ident, static):
        self.role = role
        self.id = ident
        self.static = static
        self.state = {}
        self.key = None


class Method:
    name = "method"
    setting = "KK"
    reference = ""
    flows = 2

    def __init__(self, level=768):
        self.level = level
        self.kem = MLKEM(level)
        self.cache = {}

    def static_keys(self):
        ek, dk = self.kem.keygen()
        return {"ek": ek, "dk": dk, "h": self.kem.h_of(dk)}

    def static_secret_size(self, static):
        return self.kem.dk_pke_len + 32

    def new_parties(self):
        I = Party("I", P.rand(16), self.static_keys())
        R = Party("R", P.rand(16), self.static_keys())
        return I, R

    def steps(self, I, R):
        raise NotImplementedError

    def run(self, I, R, timed=False):
        I.state = {}
        R.state = {}
        I.key = None
        R.key = None
        msg = None
        messages = []
        states = {"I": [], "R": []}
        times = {"I": 0.0, "R": 0.0}
        for role, fn in self.steps(I, R):
            party = I if role == "I" else R
            if timed:
                t0 = time.perf_counter()
                msg = fn(msg)
                times[role] += time.perf_counter() - t0
            else:
                msg = fn(msg)
            if msg is not None:
                messages.append((role, len(msg)))
            states[role].append(state_size(party.state))
        return {"messages": messages, "states": states, "times": times}
