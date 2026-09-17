import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from pkx.protocols import ALL_METHODS


def main():
    for level in (512, 768, 1024):
        for cls in ALL_METHODS:
            method = cls(level)
            I, R = method.new_parties()
            for _ in range(3):
                out = method.run(I, R)
                assert I.key is not None and I.key == R.key, (cls.name, level)
            total = sum(n for _, n in out["messages"])
            flows = len(out["messages"])
            assert flows == method.flows, (cls.name, flows, method.flows)
            print(f"{level:5d} {method.setting} {method.name:22s} flows={flows} bytes={total:6d} stateI={max(out['states']['I'])} stateR={max(out['states']['R'])} static={method.static_secret_size(I.static)}")
    print("all constructions derive matching session keys")


if __name__ == "__main__":
    main()
