from __future__ import absolute_import, division, print_function


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC


def p_hash(hash_algorithm, secret, seed, output_length):
    result = b""
    i = 1
    while len(result) < output_length:
        h = HMAC(hash_algorithm, secret, default_backend())
        h.update(a(hash_algorithm, i, secret, seed))
        h.update(seed)
        result += h.finalize()
        i += 1
    return result[:output_length]


def a(hash_algorithm, n, secret, seed):
    if n == 0:
        return seed
    else:
        h = HMAC(hash_algorithm, secret)
        h.update(a(hash_algorithm, n - 1, secret, seed))
        return h.finalize()


def prf(secret, label, seed, hash_algorithm, output_length):
    return p_hash(hash_algorithm, secret, seed + label, output_length)
