import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .meter import METER


def rand(n):
    METER.add("rng", 1, n)
    return os.urandom(n)


def sha3_256(data):
    METER.add("sym_hash", 1, len(data))
    return hashlib.sha3_256(data).digest()


def shake256(data, n):
    METER.add("sym_hash", 1, len(data))
    return hashlib.shake_256(data).digest(n)


def sha256(data):
    METER.add("sym_hash", 1, len(data))
    return hashlib.sha256(data).digest()


def blake2s(data):
    METER.add("sym_hash", 1, len(data))
    return hashlib.blake2s(data).digest()


def blake2s_mac(key, data):
    METER.add("mac", 1, len(data))
    return hashlib.blake2s(data, key=key, digest_size=16).digest()


def hmac_sha256(key, data):
    METER.add("hmac", 1, len(data))
    return hmac.new(key, data, hashlib.sha256).digest()


def hmac_blake2s(key, data):
    METER.add("hmac", 1, len(data))
    return hmac.new(key, data, hashlib.blake2s).digest()


def hkdf_extract_sha256(salt, ikm):
    return hmac_sha256(salt if salt else bytes(32), ikm)


def hkdf_expand_label_sha256(secret, label, context, length=32):
    info = length.to_bytes(2, "big") + bytes([6 + len(label)]) + b"tls13 " + label + bytes([len(context)]) + context
    return hmac_sha256(secret, info + b"\x01")[:length]


def noise_hkdf(hmac_fn, chaining_key, ikm, n):
    tmp = hmac_fn(chaining_key, ikm)
    out = []
    last = b""
    for i in range(1, n + 1):
        last = hmac_fn(tmp, last + bytes([i]))
        out.append(last)
    return out


class AEAD:
    def __init__(self, key):
        self._aead = ChaCha20Poly1305(key)

    def enc(self, nonce, data, ad):
        METER.add("aead", 1, len(data))
        return self._aead.encrypt(nonce.to_bytes(12, "little"), data, ad)

    def dec(self, nonce, data, ad):
        METER.add("aead", 1, len(data))
        return self._aead.decrypt(nonce.to_bytes(12, "little"), data, ad)


def aes256_prp(key, block):
    METER.add("prp", 1, len(block))
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def xor_stream(key_material, data, label):
    METER.add("otp", 1, len(data))
    n = len(data)
    stream = hashlib.shake_256(label + key_material).digest(n)
    return (int.from_bytes(data, "little") ^ int.from_bytes(stream, "little")).to_bytes(n, "little")
