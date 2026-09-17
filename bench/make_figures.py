import json
import os
import subprocess

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "..", "results")

KK_ORDER = ["KEX-KKE", "PQNoise-KK", "PQ-WireGuard", "Kyber.AKE", "FO-AKE", "PWZ-AKE", "PKX-ML (ours)"]
XX_ORDER = ["KEX-TTE", "PQNoise-XX", "KEMTLS-mutual", "PKX-ML (ours)"]
LEVELS = ["512", "768", "1024"]
LEVEL_COLORS = {"512": "#9ecae1", "768": "#4292c6", "1024": "#08306b"}
OURS = "PKX-ML (ours)"
HASHED = ("H", "J", "G", "sym_hash", "hmac", "mac")
CIPHERED = ("aead", "prp", "otp")
SHORT = {
    "KEX-KKE": "KEX-KKE",
    "PQNoise-KK": "PQNoise-KK",
    "PQ-WireGuard": "PQ-WG",
    "Kyber.AKE": "Kyber.AKE",
    "FO-AKE": "FO-AKE",
    "PWZ-AKE": "PWZ-AKE",
    "KEX-TTE": "KEX-TTE",
    "PQNoise-XX": "PQNoise-XX",
    "KEMTLS-mutual": "KEMTLS",
    OURS: "PKX-ML",
}
STYLE = {
    "KEX-KKE": ("#1f77b4", "o", "-"),
    "PQNoise-KK": ("#ff7f0e", "s", "--"),
    "PQ-WireGuard": ("#2ca02c", "^", "-."),
    "Kyber.AKE": ("#9467bd", "v", ":"),
    "FO-AKE": ("#8c564b", "D", "--"),
    "PWZ-AKE": ("#7f7f7f", "P", "-."),
    "KEX-TTE": ("#1f77b4", "o", "-"),
    "PQNoise-XX": ("#ff7f0e", "s", "--"),
    "KEMTLS-mutual": ("#17becf", "X", "-."),
    OURS: ("#b2182b", "*", "-"),
}

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 8,
    "axes.labelsize": 8,
    "axes.titlesize": 8.5,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "legend.fontsize": 6.8,
    "axes.linewidth": 0.6,
    "ps.fonttype": 42,
})


def load():
    with open(os.path.join(RESULTS, "bench.json")) as fh:
        return json.load(fh)


def entry(data, level, name, setting, field):
    key = name + "|" + setting
    if field.endswith("_us"):
        return data["levels"][level]["timing"][key][field]
    return data["levels"][level]["profile"][key][field]


def save(fig, stem):
    eps = os.path.join(RESULTS, stem + ".eps")
    fig.savefig(eps, format="eps", bbox_inches="tight", pad_inches=0.04)
    plt.close(fig)
    subprocess.run(["epstopdf", eps], check=True)
    return eps


def group_labels(ax, top):
    ax.axvline(len(KK_ORDER) - 0.5, color="gray", linewidth=0.5, linestyle="--")
    ax.text((len(KK_ORDER) - 1) / 2, top, "KK", ha="center", va="center", fontsize=7)
    ax.text(len(KK_ORDER) + (len(XX_ORDER) - 1) / 2, top, "XX", ha="center", va="center", fontsize=7)


def fig_time(data):
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.5), gridspec_kw={"width_ratios": [len(KK_ORDER), len(XX_ORDER) + 0.8]})
    for ax, order, setting, title in ((axes[0], KK_ORDER, "KK", "(a) preshared static keys (KK)"), (axes[1], XX_ORDER, "XX", "(b) transmitted static keys (XX)")):
        x = np.arange(len(order))
        width = 0.26
        for i, level in enumerate(LEVELS):
            med = np.array([entry(data, level, n, setting, "median_us") for n in order]) / 1e3
            lo = med - np.array([entry(data, level, n, setting, "p25_us") for n in order]) / 1e3
            hi = np.array([entry(data, level, n, setting, "p75_us") for n in order]) / 1e3 - med
            bars = ax.bar(x + (i - 1) * width, med, width, color=LEVEL_COLORS[level], edgecolor="black", linewidth=0.3, label="ML-KEM-" + level)
            ax.errorbar(x + (i - 1) * width, med, yerr=[lo, hi], fmt="none", ecolor="black", elinewidth=0.5, capsize=1.2)
            for j, n in enumerate(order):
                if n == OURS:
                    bars[j].set_hatch("////")
        ax.set_xticks(x)
        ax.set_xticklabels([SHORT[n] for n in order], rotation=30, ha="right")
        ax.set_ylabel("handshake time (ms)")
        ax.set_title(title)
        ax.grid(axis="y", linewidth=0.3, alpha=0.6)
        ax.set_axisbelow(True)
        top = max(entry(data, "1024", n, setting, "p75_us") for n in order) / 1e3
        ax.set_ylim(0, top * 1.22)
    axes[0].legend(loc="upper left", ncol=3, frameon=False)
    fig.tight_layout(w_pad=1.2)
    return save(fig, "fig_time")


def fig_space(data):
    level = "768"
    names = [(n, "KK") for n in KK_ORDER] + [(n, "XX") for n in XX_ORDER]
    xt = [SHORT[n] for n, _ in names]
    colors = ["#b2182b" if n == OURS else ("#fdbf6f" if s == "KK" else "#a6cee3") for n, s in names]
    fig, axes = plt.subplots(1, 3, figsize=(7.0, 2.45))
    metrics = (("bytes", "(a) bytes on the wire", 1.0, "bytes"), ("state_I", "(b) initiator state", 1.0, "bytes"), ("retained_mem", "(c) retained session memory", 1.0 / 1024, "KiB"))
    for ax, (field, title, scale, unit) in zip(axes, metrics):
        vals = [entry(data, level, n, s, field) * scale for n, s in names]
        x = np.arange(len(names))
        ax.bar(x, vals, color=colors, edgecolor="black", linewidth=0.3)
        ax.set_xticks(x)
        ax.set_xticklabels(xt, rotation=60, ha="right")
        ax.set_ylabel(unit)
        ax.set_title(title)
        ax.grid(axis="y", linewidth=0.3, alpha=0.6)
        ax.set_axisbelow(True)
        ax.set_ylim(0, max(vals) * 1.2)
        group_labels(ax, ax.get_ylim()[1] * 0.93)
    fig.tight_layout(w_pad=0.9)
    return save(fig, "fig_space")


def fig_memsteps(data):
    level = "768"
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.75))
    for ax, order, setting, title in ((axes[0], KK_ORDER, "KK", "(a) preshared static keys (KK)"), (axes[1], XX_ORDER, "XX", "(b) transmitted static keys (XX)")):
        longest = 0
        peak = 0
        for n in order:
            steps = entry(data, level, n, setting, "retained_steps")
            longest = max(longest, len(steps))
            peak = max(peak, max(steps))
            color, marker, ls = STYLE[n]
            lw = 1.5 if n == OURS else 0.9
            ms = 6 if n == OURS else 3.5
            ax.plot(np.arange(1, len(steps) + 1), np.array(steps) / 1024, linestyle=ls, marker=marker, markersize=ms, linewidth=lw, color=color, label=SHORT[n])
        ax.set_xticks(np.arange(1, longest + 1))
        ax.set_xlabel("protocol step")
        ax.set_ylabel("retained memory (KiB)")
        ax.set_title(title)
        ax.grid(linewidth=0.3, alpha=0.6)
        ax.set_ylim(0, peak / 1024 * 1.12)
        ax.legend(frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(0.5, -0.24), columnspacing=1.0, handlelength=2.2)
    fig.tight_layout(w_pad=1.0)
    return save(fig, "fig_memsteps")


def fig_ops(data):
    level = "768"
    names = [(n, "KK") for n in KK_ORDER] + [(n, "XX") for n in XX_ORDER]
    x = np.arange(len(names))
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.45), gridspec_kw={"width_ratios": [1.3, 1]})
    ax = axes[0]
    kinds = (("pke_keygen", "key generation"), ("pke_enc", "encryption"), ("pke_dec", "decryption"))
    palette = ["#4d4d4d", "#2166ac", "#f4a582"]
    width = 0.26
    for i, ((kind, lab), col) in enumerate(zip(kinds, palette)):
        vals = [entry(data, level, n, s, "calls").get(kind, 0) for n, s in names]
        ax.bar(x + (i - 1) * width, vals, width, color=col, edgecolor="black", linewidth=0.3, label=lab)
    ax.set_xticks(x)
    ax.set_xticklabels([SHORT[n] for n, _ in names], rotation=60, ha="right")
    ax.set_ylabel("operations")
    ax.set_title("(a) lattice operations per handshake")
    ax.set_ylim(0, 9.4)
    ax.set_yticks(range(0, 8))
    ax.grid(axis="y", linewidth=0.3, alpha=0.6)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.0))
    group_labels(ax, 7.1)
    ax = axes[1]
    hashed = np.array([sum(entry(data, level, n, s, "nbytes").get(k, 0) for k in HASHED) for n, s in names]) / 1024
    ciphered = np.array([sum(entry(data, level, n, s, "nbytes").get(k, 0) for k in CIPHERED) for n, s in names]) / 1024
    colors = ["#b2182b" if n == OURS else ("#fdbf6f" if s == "KK" else "#a6cee3") for n, s in names]
    ax.bar(x, hashed, color=colors, edgecolor="black", linewidth=0.3, label="hashed")
    ax.bar(x, ciphered, bottom=hashed, color="white", edgecolor="black", linewidth=0.3, hatch="////", label="encrypted")
    ax.set_xticks(x)
    ax.set_xticklabels([SHORT[n] for n, _ in names], rotation=60, ha="right")
    ax.set_ylabel("KiB")
    ax.set_title("(b) symmetric input per handshake")
    top = max(hashed + ciphered)
    ax.set_ylim(0, top * 1.45)
    ax.grid(axis="y", linewidth=0.3, alpha=0.6)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, ncol=2, loc="upper center", bbox_to_anchor=(0.5, 1.0))
    group_labels(ax, top * 1.12)
    fig.tight_layout(w_pad=1.0)
    return save(fig, "fig_ops")


def main():
    data = load()
    for fn in (fig_time, fig_space, fig_memsteps, fig_ops):
        print(fn(data))


if __name__ == "__main__":
    main()
