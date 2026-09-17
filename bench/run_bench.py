import argparse
import gc
import json
import os
import platform
import random
import statistics
import sys
import time
import tracemalloc

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from pkx.meter import METER
from pkx.protocols import KK_METHODS, XX_METHODS


def key_of(cls):
    return cls.name + "|" + cls.setting


def time_methods(classes, level, rounds):
    instances = []
    for cls in classes:
        m = cls(level)
        I, R = m.new_parties()
        for _ in range(5):
            m.run(I, R)
        instances.append((key_of(cls), m, I, R))
    samples = {key: [] for key, _, _, _ in instances}
    gc.collect()
    gc.disable()
    try:
        for r in range(rounds):
            order = list(instances)
            random.shuffle(order)
            for key, m, I, R in order:
                t0 = time.perf_counter()
                m.run(I, R)
                samples[key].append(time.perf_counter() - t0)
            if r % 250 == 249:
                gc.enable()
                gc.collect()
                gc.disable()
    finally:
        gc.enable()
    result = {}
    for key, m, _, _ in instances:
        s = sorted(samples[key])
        n = len(s)
        result[key] = {
            "name": m.name,
            "setting": m.setting,
            "reference": m.reference,
            "median_us": 1e6 * statistics.median(s),
            "p10_us": 1e6 * s[n // 10],
            "p25_us": 1e6 * s[n // 4],
            "p75_us": 1e6 * s[(3 * n) // 4],
            "p90_us": 1e6 * s[(9 * n) // 10],
            "min_us": 1e6 * s[0],
            "mean_us": 1e6 * statistics.fmean(s),
        }
    return result


def step_counts(m, I, R):
    I.state = {}
    R.state = {}
    msg = None
    per_step = []
    METER.enabled = True
    for role, fn in m.steps(I, R):
        METER.reset()
        msg = fn(msg)
        calls, nbytes = METER.snapshot()
        per_step.append({"role": role, "calls": calls, "nbytes": nbytes, "out": 0 if msg is None else len(msg)})
    METER.enabled = False
    return per_step


def retained_memory(m, I, R, reps=15):
    best_total = None
    best_steps = None
    for _ in range(reps):
        I.state = {}
        R.state = {}
        I.key = None
        R.key = None
        gc.collect()
        base = tracemalloc.get_traced_memory()[0]
        msg = None
        steps = []
        for role, fn in m.steps(I, R):
            msg = fn(msg)
            steps.append(tracemalloc.get_traced_memory()[0] - base)
        worst = max(steps)
        if best_total is None or worst < best_total:
            best_total = worst
        best_steps = steps if best_steps is None else [min(a, b) for a, b in zip(best_steps, steps)]
    return best_total, best_steps


def profile_method(cls, level):
    m = cls(level)
    I, R = m.new_parties()
    m.run(I, R)
    per_step = step_counts(m, I, R)
    tracemalloc.start()
    m.run(I, R)
    retained, retained_steps = retained_memory(m, I, R)
    tracemalloc.stop()
    METER.reset()
    METER.enabled = True
    out = m.run(I, R)
    METER.enabled = False
    calls, nbytes = METER.snapshot()
    tracemalloc.start()
    peaks = []
    for _ in range(7):
        tracemalloc.reset_peak()
        base = tracemalloc.get_traced_memory()[0]
        m.run(I, R)
        peaks.append(tracemalloc.get_traced_memory()[1] - base)
    tracemalloc.stop()
    return {
        "flows": len(out["messages"]),
        "bytes": sum(n for _, n in out["messages"]),
        "messages": out["messages"],
        "state_I": max(out["states"]["I"]),
        "state_R": max(out["states"]["R"]),
        "static_secret": m.static_secret_size(I.static),
        "peak_mem": min(peaks),
        "retained_mem": retained,
        "retained_steps": retained_steps,
        "calls": calls,
        "nbytes": nbytes,
        "steps": per_step,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=4000)
    ap.add_argument("--levels", type=str, default="512,768,1024")
    ap.add_argument("--out", type=str, default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "bench.json"))
    args = ap.parse_args()
    levels = [int(x) for x in args.levels.split(",")]
    report = {"platform": platform.platform(), "machine": platform.machine(), "python": platform.python_version(), "rounds": args.rounds, "levels": {}}
    for level in levels:
        entry = {"timing": {}, "profile": {}}
        for group in (KK_METHODS, XX_METHODS):
            entry["timing"].update(time_methods(group, level, args.rounds))
        for cls in KK_METHODS + XX_METHODS:
            entry["profile"][key_of(cls)] = profile_method(cls, level)
        report["levels"][str(level)] = entry
        print("level", level, "done", flush=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=1)
    for level in levels:
        e = report["levels"][str(level)]
        for key, t in sorted(e["timing"].items(), key=lambda kv: (kv[1]["setting"], kv[1]["median_us"])):
            p = e["profile"][key]
            print(f"{level:5d} {t['setting']} {t['name']:16s} median={t['median_us']:8.1f} p25={t['p25_us']:8.1f} p75={t['p75_us']:8.1f} bytes={p['bytes']:5d} flows={p['flows']} stI={p['state_I']:5d} stR={p['state_R']:4d} static={p['static_secret']:5d} retained={p['retained_mem']:6d} peak={p['peak_mem']:7d}")


if __name__ == "__main__":
    main()
