# Formally Sound and Compact Post-Quantum Key Exchange Patterns

This repository contains our implementation, the attack scripts, the compiler,
and the measurement harness for our research *Sound and Compact Post-Quantum Key Exchange
Patterns*. It implements the PKX framework and its instantiation PKX-ML, reproduces the
soundness attack on the unified KEX framework, verifies the predicate-preserving compiler,
and benchmarks PKX-ML against nine alternative techniques.

## Requirements

- Python 3.10 or newer
- `numpy`
- `cryptography`
- `matplotlib` (figures only)
- `kyber-py` (tests only, used as an independent reference for the ML-KEM backend)


Install the Python dependencies with:
```
pip install numpy cryptography matplotlib kyber-py
```

## Files and Contents

```
pkx/
  mlkem.py            vectorized ML-KEM (FIPS 203), with the light decapsulation
  primitives.py       hashes, HKDF, AEAD, one-time pad, all metered
  meter.py            global operation and byte counter
  compiler.py         DH to KEM pattern compiler and predicate checker
  protocols/
    base.py           common party and method interface
    pkx.py            PKX-ML, the KK and XX patterns, compact and full modes
    kex.py            the two KEX patterns of the target framework
    pqnoise.py        post-quantum Noise KK and XX
    pqwg.py           post-quantum WireGuard
    kyberake.py       the Kyber authenticated exchange
    hksu.py           the generic Fujisaki-Okamoto authenticated exchange
    pwz.py            the tighter generic exchange
    kemtls.py         mutual KEMTLS
attacks/
  kex_cleanness.py    the soundness attack of Proposition 2 and Corollary 3
  light_reuse.py      the malleability check behind Theorem 3
bench/
  run_bench.py        timing and space profiling
  make_figures.py     
  make_tables.py      
tests/
  test_mlkem.py       byte equality of the ML-KEM backend against kyber-py
  test_protocols.py   all constructions agree on the session key
  test_compiler.py    predicate preservation and the flow lower bound
results/              generated benchmark data, figures, and tables
```

## Running the Experiments

### Correctness of the ML-KEM backend

```
python tests/test_mlkem.py
```
Confirms that the encapsulation and decapsulation outputs of `pkx/mlkem.py` agree byte for
byte with `kyber-py` at ML-KEM-512, ML-KEM-768, and ML-KEM-1024, including the light
decapsulation.

### Constructions agreement on the key

```
python tests/test_protocols.py
```

Runs each of the ten constructions and confirms that the initiator and the responder derive
the same session key, and prints the flow count and the space figures.

### The soundness attack 
```
python attacks/kex_cleanness.py
```
For the nine flagged cleanness definitions of the target framework, this prints the corruption
that keeps the tested session clean under all parenthesizations while the tested key is
computable from the corrupted secret. It then plays the attack against ML-KEM-768 and against
X25519 with a random oracle, and prints the measured advantage, which is `1.000`.

### The light decapsulation malleability 
```
python attacks/light_reuse.py
```
Shows that a mauled ephemeral ciphertext yields the same shared secret under the raw light
decapsulation, that the binding of PKX-ML resolves this, and that the full decapsulation
rejects the mauled input.

### The compiler 
```
python tests/test_compiler.py
```
Compiles the fifteen fundamental patterns, prints their flows and lower bound, and verifies
predicate preservation by enumerating all corruption assignments for both roles and both modes,
which is `6351360` assignments.

### The benchmark 
```
python bench/run_bench.py
python bench/make_tables.py
python bench/make_figures.py
```
`run_bench.py` writes `results/bench.json` and `results/bench_log.txt` with the timing,
the flows, the bytes on the wire, the state, and the retained session memory.

## Notes
- The operation meter counts key generation, encryption, and decryption at the encryption scheme
  level for every construction through the same interface, so that no construction is credited for
  skipping a step its proof needs. A full decapsulation is counted with its re-encryption, and the
  light decapsulation only where a construction is entitled to it.
- The retained session memory is the smallest current allocation held after a protocol step over
  repeated runs, which removes the transient arrays of the mechanism that are common to all
  constructions and isolates the state a construction must keep between steps.
