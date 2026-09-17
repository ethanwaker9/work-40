import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "..", "results")

KK_ORDER = ["KEX-KKE", "PQNoise-KK", "PQ-WireGuard", "Kyber.AKE", "FO-AKE", "PWZ-AKE", "PKX-ML (ours)"]
XX_ORDER = ["KEX-TTE", "PQNoise-XX", "KEMTLS-mutual", "PKX-ML (ours)"]
CITE = {
    "KEX-KKE": "dowling2026kex",
    "KEX-TTE": "dowling2026kex",
    "PQNoise-KK": "angel2022pqnoise",
    "PQNoise-XX": "angel2022pqnoise",
    "PQ-WireGuard": "hulsing2021pqwg",
    "Kyber.AKE": "bos2018kyber",
    "FO-AKE": "hksu2020",
    "PWZ-AKE": "pwz2023tighter",
    "KEMTLS-mutual": "ssw2020kemtls",
}
OURS = "PKX-ML (ours)"
LEVELS = ("512", "768", "1024")


def load():
    with open(os.path.join(RESULTS, "bench.json")) as fh:
        return json.load(fh)


def t(data, level, name, setting):
    return data["levels"][level]["timing"][name + "|" + setting]


def p(data, level, name, setting):
    return data["levels"][level]["profile"][name + "|" + setting]


def disp(name):
    if name == OURS:
        return r"\textbf{PKX-ML}"
    return name + r"~\cite{" + CITE[name] + "}"


def fmt_best(value, best, spec):
    s = spec.format(value)
    return r"\textbf{" + s + "}" if abs(value - best) < 1e-9 else s


def table_measure(data):
    lines = []
    for setting, order in (("KK", KK_ORDER), ("XX", XX_ORDER)):
        if setting != "KK":
            lines.append(r"\multicolumn{9}{@{}l}{\emph{transmitted static keys (XX)}}\\")
        best_t = {lv: min(t(data, lv, n, setting)["median_us"] for n in order) for lv in LEVELS}
        best = {f: min(p(data, "768", n, setting)[f] for n in order) for f in ("bytes", "state_I", "static_secret", "retained_mem")}
        for n in order:
            pr = p(data, "768", n, setting)
            row = [disp(n)]
            row += [fmt_best(t(data, lv, n, setting)["median_us"] / 1e3, best_t[lv] / 1e3, "{:.3f}") for lv in LEVELS]
            row.append(str(pr["flows"]))
            row.append(fmt_best(pr["bytes"], best["bytes"], "{:d}"))
            row.append(fmt_best(pr["state_I"], best["state_I"], "{:d}"))
            row.append(fmt_best(pr["static_secret"], best["static_secret"], "{:d}"))
            row.append(fmt_best(pr["retained_mem"], best["retained_mem"], "{:d}"))
            lines.append(" & ".join(row) + r" \\")
        if setting == "KK":
            lines.append(r"\midrule")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}%")
    return "\n".join(lines)


def table_levels(data):
    lines = []
    for level in LEVELS:
        for setting, order in (("KK", KK_ORDER), ("XX", XX_ORDER)):
            best_med = min(t(data, level, n, setting)["median_us"] for n in order)
            best = {f: min(p(data, level, n, setting)[f] for n in order) for f in ("bytes", "state_I", "retained_mem")}
            for n in order:
                tm = t(data, level, n, setting)
                pr = p(data, level, n, setting)
                row = ["ML-KEM-" + level if (n == order[0] and setting == "KK") else "", setting if n == order[0] else "", r"\textbf{PKX-ML}" if n == OURS else n]
                row.append(fmt_best(tm["median_us"] / 1e3, best_med / 1e3, "{:.3f}"))
                row.append("{:.3f}".format(tm["p25_us"] / 1e3))
                row.append("{:.3f}".format(tm["p75_us"] / 1e3))
                row.append(fmt_best(pr["bytes"], best["bytes"], "{:d}"))
                row.append(fmt_best(pr["state_I"], best["state_I"], "{:d}"))
                row.append(str(pr["state_R"]))
                row.append(fmt_best(pr["retained_mem"], best["retained_mem"], "{:d}"))
                lines.append(" & ".join(row) + r" \\")
        if level != LEVELS[-1]:
            lines.append(r"\midrule")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}%")
    return "\n".join(lines)


def table_ops(data):
    lines = []
    for setting, order in (("KK", KK_ORDER), ("XX", XX_ORDER)):
        for n in order:
            pr = p(data, "768", n, setting)
            c = pr["calls"]
            nb = pr["nbytes"]
            hashed = sum(nb.get(k, 0) for k in ("H", "J", "G", "sym_hash", "hmac", "mac"))
            ciphered = sum(nb.get(k, 0) for k in ("aead", "prp", "otp"))
            row = [r"\textbf{PKX-ML}" if n == OURS else n, str(len(pr["steps"])), str(c.get("pke_keygen", 0)), str(c.get("pke_enc", 0)), str(c.get("pke_dec", 0)), str(c.get("matrix", 0)), str(hashed), str(ciphered)]
            lines.append(" & ".join(row) + r" \\")
        if setting == "KK":
            lines.append(r"\midrule")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}%")
    return "\n".join(lines)


def main():
    data = load()
    out_dir = os.path.join(RESULTS, "tables")
    os.makedirs(out_dir, exist_ok=True)
    for name, fn in (("tab_measure.tex", table_measure), ("tab_levels.tex", table_levels), ("tab_ops.tex", table_ops)):
        with open(os.path.join(out_dir, name), "w") as fh:
            fh.write(fn(data) + "\n")
        print(os.path.join(out_dir, name))


if __name__ == "__main__":
    main()
