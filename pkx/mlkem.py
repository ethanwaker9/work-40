import hashlib
import os
import numpy as np

from .meter import METER

Q = 3329
NINV = 3303


def _bitrev7(i):
    return int("{:07b}".format(i)[::-1], 2)


ZETAS = np.array([pow(17, _bitrev7(i), Q) for i in range(128)], dtype=np.int64)
GAMMAS = np.array([pow(17, 2 * _bitrev7(i) + 1, Q) for i in range(128)], dtype=np.int64)
ZETA_LAYERS = {}
ZETA_LAYERS_INV = {}
for _l in (128, 64, 32, 16, 8, 4, 2):
    _b = 128 // _l
    ZETA_LAYERS[_l] = ZETAS[_b:2 * _b][:, None].copy()
    ZETA_LAYERS_INV[_l] = ZETAS[_b:2 * _b][::-1][:, None].copy()
BIT_WEIGHTS = {d: (1 << np.arange(d, dtype=np.int64)) for d in range(1, 13)}

PARAMS = {
    512: dict(k=2, eta1=3, eta2=2, du=10, dv=4),
    768: dict(k=3, eta1=2, eta2=2, du=10, dv=4),
    1024: dict(k=4, eta1=2, eta2=2, du=11, dv=5),
}


def ntt(f):
    a = np.array(f, dtype=np.int64, copy=True)
    shape = a.shape[:-1]
    length = 128
    while length >= 2:
        blocks = 128 // length
        a = a.reshape(shape + (blocks, 2 * length))
        lo = a[..., :length]
        t = (ZETA_LAYERS[length] * a[..., length:]) % Q
        a = np.concatenate(((lo + t) % Q, (lo - t) % Q), axis=-1)
        length //= 2
    return a.reshape(shape + (256,))


def intt(f):
    a = np.array(f, dtype=np.int64, copy=True)
    shape = a.shape[:-1]
    length = 2
    while length <= 128:
        blocks = 128 // length
        a = a.reshape(shape + (blocks, 2 * length))
        lo = a[..., :length]
        hi = a[..., length:]
        a = np.concatenate(((lo + hi) % Q, (ZETA_LAYERS_INV[length] * (hi - lo)) % Q), axis=-1)
        length *= 2
    return (a.reshape(shape + (256,)) * NINV) % Q


def mul_ntt(f, g):
    f0 = f[..., 0::2]
    f1 = f[..., 1::2]
    g0 = g[..., 0::2]
    g1 = g[..., 1::2]
    out = np.empty(np.broadcast_shapes(f.shape, g.shape), dtype=np.int64)
    out[..., 0::2] = (f0 * g0 + ((f1 * g1) % Q) * GAMMAS) % Q
    out[..., 1::2] = (f0 * g1 + f1 * g0) % Q
    return out


def byte_encode(a, d):
    flat = np.asarray(a, dtype=np.int64).reshape(-1, 256)
    bits = ((flat[..., None] >> np.arange(d, dtype=np.int64)) & 1).astype(np.uint8)
    return np.packbits(bits.reshape(-1), bitorder="little").tobytes()


def byte_decode(b, d, count):
    bits = np.unpackbits(np.frombuffer(b, dtype=np.uint8), bitorder="little").astype(np.int64)
    vals = bits.reshape(count, 256, d) @ BIT_WEIGHTS[d]
    if d == 12:
        vals = vals % Q
    return vals


def compress(x, d):
    return (((x << d) + Q // 2) // Q) & ((1 << d) - 1)


def decompress(y, d):
    return (y * Q + (1 << (d - 1))) >> d


def cbd(b, eta):
    bits = np.unpackbits(np.frombuffer(b, dtype=np.uint8), bitorder="little").astype(np.int64)
    bits = bits.reshape(256, 2 * eta)
    return (bits[:, :eta].sum(axis=1) - bits[:, eta:].sum(axis=1)) % Q


def sample_ntt(seed):
    METER.add("xof", 1, len(seed))
    n = 840
    while True:
        buf = np.frombuffer(hashlib.shake_128(seed).digest(n), dtype=np.uint8).astype(np.int64)
        c = buf[: 3 * (n // 3)].reshape(-1, 3)
        d1 = c[:, 0] + 256 * (c[:, 1] & 15)
        d2 = (c[:, 1] >> 4) + 16 * c[:, 2]
        d = np.stack((d1, d2), axis=1).reshape(-1)
        d = d[d < Q]
        if d.shape[0] >= 256:
            return d[:256]
        n += 504


def H(s):
    METER.add("H", 1, len(s))
    return hashlib.sha3_256(s).digest()


def J(s):
    METER.add("J", 1, len(s))
    return hashlib.shake_256(s).digest(32)


def G(s):
    METER.add("G", 1, len(s))
    h = hashlib.sha3_512(s).digest()
    return h[:32], h[32:]


def PRF(eta, s, n):
    METER.add("PRF", 1, 33)
    return hashlib.shake_256(s + bytes([n])).digest(64 * eta)


class MLKEM:
    def __init__(self, level=768):
        p = PARAMS[level]
        self.level = level
        self.k = p["k"]
        self.eta1 = p["eta1"]
        self.eta2 = p["eta2"]
        self.du = p["du"]
        self.dv = p["dv"]
        self.ek_len = 384 * self.k + 32
        self.dk_len = 768 * self.k + 96
        self.dk_pke_len = 384 * self.k
        self.ct_len = 32 * (self.du * self.k + self.dv)
        self.ss_len = 32

    def _matrix(self, rho):
        METER.add("matrix", 1, 0)
        k = self.k
        A = np.empty((k, k, 256), dtype=np.int64)
        for i in range(k):
            for j in range(k):
                A[i, j] = sample_ntt(rho + bytes([j, i]))
        return A

    def _noise_vec(self, seed, eta, start):
        return np.stack([cbd(PRF(eta, seed, start + i), eta) for i in range(self.k)])

    def check_ek(self, ek):
        if len(ek) != self.ek_len:
            raise ValueError("type check")
        t_bytes = ek[: 384 * self.k]
        if byte_encode(byte_decode(t_bytes, 12, self.k), 12) != t_bytes:
            raise ValueError("modulus check")

    def kpke_keygen(self, d):
        METER.add("pke_keygen", 1, 0)
        rho, sigma = G(d + bytes([self.k]))
        A = self._matrix(rho)
        s = self._noise_vec(sigma, self.eta1, 0)
        e = self._noise_vec(sigma, self.eta1, self.k)
        s_hat = ntt(s)
        e_hat = ntt(e)
        t_hat = (mul_ntt(A, s_hat[None, :, :]).sum(axis=1) + e_hat) % Q
        return byte_encode(t_hat, 12) + rho, byte_encode(s_hat, 12)

    def kpke_encrypt(self, ek, m, r, check=False):
        METER.add("pke_enc", 1, 0)
        k = self.k
        t_bytes = ek[: 384 * k]
        rho = ek[384 * k:]
        t_hat = byte_decode(t_bytes, 12, k)
        if check and (len(ek) != self.ek_len or byte_encode(t_hat, 12) != t_bytes):
            raise ValueError("modulus check")
        A = self._matrix(rho)
        y = self._noise_vec(r, self.eta1, 0)
        e1 = self._noise_vec(r, self.eta2, k)
        e2 = cbd(PRF(self.eta2, r, 2 * k), self.eta2)
        y_hat = ntt(y)
        u = (intt(mul_ntt(A.transpose(1, 0, 2), y_hat[None, :, :]).sum(axis=1) % Q) + e1) % Q
        mu = decompress(byte_decode(m, 1, 1)[0], 1)
        v = (intt(mul_ntt(t_hat, y_hat).sum(axis=0) % Q) + e2 + mu) % Q
        return byte_encode(compress(u, self.du), self.du) + byte_encode(compress(v, self.dv), self.dv)

    def kpke_decrypt(self, dk_pke, c):
        METER.add("pke_dec", 1, 0)
        k = self.k
        n1 = 32 * self.du * k
        u = decompress(byte_decode(c[:n1], self.du, k), self.du)
        v = decompress(byte_decode(c[n1:], self.dv, 1)[0], self.dv)
        s_hat = byte_decode(dk_pke, 12, k)
        w = (v - intt(mul_ntt(s_hat, ntt(u)).sum(axis=0) % Q)) % Q
        return byte_encode(compress(w, 1), 1)

    def keygen_internal(self, d, z):
        METER.add("keygen", 1, 0)
        ek, dk_pke = self.kpke_keygen(d)
        return ek, dk_pke + ek + H(ek) + z

    def keygen(self):
        return self.keygen_internal(os.urandom(32), os.urandom(32))

    def encaps_internal(self, ek, m, h=None, check=True):
        METER.add("encaps", 1, 0)
        K, r = G(m + (H(ek) if h is None else h))
        return K, self.kpke_encrypt(ek, m, r, check)

    def encaps(self, ek, h=None, check=True):
        return self.encaps_internal(ek, os.urandom(32), h, check)

    def decaps(self, dk, c):
        METER.add("decaps_full", 1, 0)
        k = self.k
        if len(c) != self.ct_len or len(dk) != self.dk_len:
            raise ValueError("length check")
        dk_pke = dk[: 384 * k]
        ek = dk[384 * k: 768 * k + 32]
        h = dk[768 * k + 32: 768 * k + 64]
        z = dk[768 * k + 64:]
        m = self.kpke_decrypt(dk_pke, c)
        K, r = G(m + h)
        K_bar = J(z + c)
        if self.kpke_encrypt(ek, m, r) != c:
            return K_bar
        return K

    def eph_keygen(self, d):
        METER.add("keygen_eph", 1, 0)
        ek, dk_pke = self.kpke_keygen(d)
        return ek, dk_pke, H(ek)

    def decaps_light(self, dk_pke, h, c):
        METER.add("decaps_light", 1, 0)
        if len(c) != self.ct_len:
            raise ValueError("length check")
        return G(self.kpke_decrypt(dk_pke, c) + h)[0]

    def z_of(self, dk):
        return dk[768 * self.k + 64:]

    def h_of(self, dk):
        return dk[768 * self.k + 32: 768 * self.k + 64]
