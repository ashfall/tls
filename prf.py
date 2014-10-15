def P_hash(hash_algorithm, secret, seed, output_length):
    result = b""
    i = 1
    while len(result) < output_length:
        h = HMAC(hash_algorithm, secret)
        h.update(A(hash_algorithm, i, secret, seed))
        h.update(seed)
        result += h.finalize()
        i += 1
    return result[:output_length]


def A(hash_algorithm, n, secret, seed):
    if n == 0:
        return seed
    else:
        h = HMAC(hash_algorithm, secret)
        h.update(A(hash_algorithm, n - 1, secret, seed))
        return h.finalize()
