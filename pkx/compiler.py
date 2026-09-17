from itertools import product

FUNDAMENTAL_DH = {
    "KKXX": [],
    "TTXX": [("I", ["s"]), ("R", ["s"])],
    "XXEE": [("I", ["e"]), ("R", ["e"])],
    "XTEX": [("I", ["e"]), ("R", ["s"])],
    "TXXE": [("I", ["s"]), ("R", ["e"])],
    "TXEE": [("I", ["e"]), ("R", ["e"]), ("I", ["s"])],
    "TXEE'": [("I", ["e", "s"]), ("R", ["e"])],
    "XTEE": [("I", ["e"]), ("R", ["e", "s"])],
    "TTEX": [("I", ["e"]), ("R", ["s"]), ("I", ["s"])],
    "TTEX'": [("I", ["e", "s"]), ("R", ["s"])],
    "TTXE": [("I", []), ("R", ["e", "s"]), ("I", ["s"])],
    "TTXE'": [("I", ["s"]), ("R", ["e", "s"])],
    "TTEE": [("I", ["e"]), ("R", ["e", "s"]), ("I", ["s"])],
    "TTEE'": [("I", ["e", "s"]), ("R", ["e", "s"])],
    "KKEE": [("I", ["e"]), ("R", ["e"])],
}

TARGET_KEM_FLOWS = {
    "KKXX": None,
    "TTXX": 3,
    "XXEE": 2,
    "XTEX": 3,
    "TXXE": 2,
    "TXEE": 4,
    "TXEE'": 2,
    "XTEE": 3,
    "TTEX": 4,
    "TTEX'": 3,
    "TTXE": 4,
    "TTXE'": 3,
    "TTEE": 4,
    "TTEE'": 3,
    "KKEE": 2,
}

OTHER = {"I": "R", "R": "I"}


def keys_of(name):
    return {"I": {"s": name[0] in "KT", "e": name[2] == "E"}, "R": {"s": name[1] in "KT", "e": name[3] == "E"}}


def dh_components(name):
    k = keys_of(name)
    comps = []
    for u in ("s", "e"):
        for v in ("s", "e"):
            if k["I"][u] and k["R"][v]:
                comps.append((u, v))
    return comps


def known_at(name, flows, party, kind):
    if kind == "s" and name[0 if party == "I" else 1] == "K":
        return 0
    for idx, (sender, toks) in enumerate(flows, start=1):
        if sender == party and kind in toks:
            return idx
    return None


def next_flow(sender, after):
    idx = after + 1
    if (idx % 2 == 1) != (sender == "I"):
        idx += 1
    return idx


def compile_pattern(name):
    flows = FUNDAMENTAL_DH[name]
    k = keys_of(name)
    comps = dh_components(name)
    reqs = []
    for (u, v) in comps:
        if v == "s":
            reqs.append(("I", "s", k["I"]["s"]))
        if u == "s":
            reqs.append(("R", "s", k["R"]["s"]))
    placed = []
    for sender, target, hardened in dict.fromkeys(reqs):
        receiver = OTHER[sender]
        t = known_at(name, flows, receiver, "s")
        placed.append((next_flow(sender, t), sender, "c(s_%s)" % receiver, hardened))
    if ("e", "e") in comps:
        tI = known_at(name, flows, "I", "e")
        tR = known_at(name, flows, "R", "e")
        opt_I = (next_flow("R", tI), "R", "c(e_I)", False, tI)
        opt_R = (next_flow("I", tR), "I", "c(e_R)", False, tR)
        best = min(opt_I, opt_R, key=lambda o: o[0])
        placed.append(best[:4])
        eph_owner = "I" if best is opt_I else "R"
    else:
        eph_owner = None
    nflows = max([len(flows)] + [p[0] for p in placed] + [2])
    out = []
    for idx in range(1, nflows + 1):
        sender = "I" if idx % 2 == 1 else "R"
        toks = []
        if idx <= len(flows):
            for tok in flows[idx - 1][1]:
                if tok == "s":
                    toks.append("s")
                elif tok == "e" and sender == eph_owner:
                    toks.append("e")
        for p in placed:
            if p[0] == idx:
                toks.append(p[2] + ("*" if p[3] else ""))
        out.append((sender, toks))
    return out


def lower_bound(name):
    flows = FUNDAMENTAL_DH[name]
    comps = dh_components(name)
    bound = 2 if ("e", "e") in comps else 0
    for idx, (_, toks) in enumerate(flows, start=1):
        if "s" in toks:
            bound = max(bound, idx)
    for (u, v) in comps:
        if v == "s":
            bound = max(bound, next_flow("I", known_at(name, flows, "R", "s")))
        if u == "s":
            bound = max(bound, next_flow("R", known_at(name, flows, "I", "s")))
    return bound


def dh_predicate(comp, role, env, two_sided):
    u, v = comp
    sec = {("I", "s"): not env["cI"], ("I", "e"): not env["rI"], ("R", "s"): not env["cR"], ("R", "e"): not env["rR"]}
    hidden = sec[("I", u)] and sec[("R", v)]
    authI = env[("authI", comp)]
    authR = env[("authR", comp)]
    if comp == ("e", "e") and two_sided:
        return hidden and authI and authR
    return hidden and (authR if role == "I" else authI)


def kem_components(comp, keys):
    u, v = comp
    if comp == ("s", "s"):
        return [("I", "s", keys["I"]["s"], "authR", "ctI"), ("R", "s", keys["R"]["s"], "authI", "ctR")]
    if v == "s":
        return [("I", "s", keys["I"]["s"], "authR", "authI")]
    if u == "s":
        return [("R", "s", keys["R"]["s"], "authI", "authR")]
    return [("R", "e", False, "authI", "authR")]


def kem_predicate(kc, comp, role, env, mode):
    sender, target, hardened, tk_name, ct_name = kc
    receiver = OTHER[sender]
    corrupt = {"I": env["cI"], "R": env["cR"]}
    revealed = {"I": env["rI"], "R": env["rR"]}
    tk = env[(tk_name, comp)]
    ct = env[(ct_name, comp)] if ct_name in ("authI", "authR") else env[(ct_name, comp)]
    coins = (not revealed[sender]) or (hardened and not corrupt[sender])
    if target == "s":
        target_hidden = not corrupt[receiver]
        if role == sender:
            return target_hidden and coins and tk
        return target_hidden and coins and ct
    target_hidden = not revealed[receiver]
    if mode == "full":
        return target_hidden and coins and (tk if role == sender else ct)
    return target_hidden and coins and tk and ct


def check_inclusion(name, mode):
    comps = dh_components(name)
    keys = keys_of(name)
    names = ["cI", "cR", "rI", "rR"]
    extra = []
    for comp in comps:
        extra += [("authI", comp), ("authR", comp), ("ctI", comp), ("ctR", comp)]
    count = 0
    for role in ("I", "R"):
        for bits in product((False, True), repeat=len(names) + len(extra)):
            env = dict(zip(names + extra, bits))
            for comp in comps:
                if keys["I"]["s"] and name[0] == "K":
                    env[("authR" if comp[1] == "s" else "authI", comp)] = env[("authR" if comp[1] == "s" else "authI", comp)]
            dh = any(dh_predicate(c, role, env, mode == "compact") for c in comps)
            kem = any(kem_predicate(kc, c, role, env, mode) for c in comps for kc in kem_components(c, keys))
            if dh and not kem:
                return False, count
            count += 1
    return True, count


def table():
    rows = []
    for name in FUNDAMENTAL_DH:
        compiled = compile_pattern(name)
        ok_full, n_full = check_inclusion(name, "full")
        ok_compact, _ = check_inclusion(name, "compact")
        rows.append({
            "dh": name,
            "dh_flows": len(FUNDAMENTAL_DH[name]),
            "components": ["".join(c) for c in dh_components(name)],
            "kem_flows": len(compiled),
            "lower_bound": lower_bound(name),
            "target_flows": TARGET_KEM_FLOWS[name],
            "compiled": compiled,
            "full_inclusion": ok_full,
            "compact_inclusion": ok_compact,
            "assignments": n_full,
        })
    return rows
