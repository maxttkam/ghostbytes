"""
benchmark.py

This module provides benchmarking utilities for the cryptographic features
implemented throughout this Ghostbytes.

The benchmarks measure encryption, decryption, hashing, random-data generation,
and key-generation times using a high-resolution performance counter.
Results are returned as formatted tuple containing the algorithm name and elapsed time
"""

from hashlib import md5
import re


from os import name as _os_name
from time import perf_counter_ns
from random import randbytes

from Crypto.PublicKey import RSA as _rsa
from ghostbytes.crypto import primitives
from ghostbytes.crypto.config import AVAIL_ALG, AVAIL_HASH, \
    AVAIL_HASH_STR, AVAIL_RANDOM_STR, CryptoConfig
from ghostbytes.crypto.kyber import genkey, kyber_decrypt, kyber_encrypt
from ghostbytes.crypto.oaep_extension import oaep_extended_decrypt, oaep_extended_encrypt
from ghostbytes.error import algorithm_not_supported, hash_not_supported
from ghostbytes.tools import rand


def benchmark(algorithm, length, rsa_keysize):
    """
    Benchmark a supported cryptographic, hashing, or random-data algorithm.

    Args:
        algorithm: Name of the algorithm to benchmark
        length: Number of bytes to use as benchmark input
        rsa_keysize: RSA key size, in bits, used by RSA-based algorithms.

        Returns:
            tuple: benchmark results.
                hash, random algorithms: ``(algorithm, elapsed_time)``
                cryptographic algorithms: ``(encryption_result, decryption_result), keygen_result``

        Raises:
            algorithm_not_supported: if ``algorithm`` is not configured as an available algorithm
    """
    if algorithm in AVAIL_HASH_STR:
        benchmark_data = randbytes(length)
        return _benchmark_hash(algorithm, benchmark_data)
    if algorithm in AVAIL_RANDOM_STR:
        return _benchmark_random(algorithm, length)
    if algorithm in AVAIL_ALG:
        benchmark_data = randbytes(length)
        return (
            _benchmark_crypto(algorithm, benchmark_data, rsa_keysize),
            _benchmark_keygen(algorithm, rsa_keysize)
        )
    raise algorithm_not_supported()


def benchmark_all(length, rsa_keysize):
    """
    Benchmark every configured hash, cryptographic, and random algorithms.

    Results are turned in the order defined by the configured algorithm lists.
    Sections labels are inserted before each category of algorithm.

    Args:
        length: Number of bytes to use as benchmark input
        rsa_keysize: RSA key size, in bits, used by RSA-based algorithms

    Returns:
        List of tuples. ``(algorithm_name, algorithm_time_or_error)``
    """

    all_algorithms = AVAIL_HASH_STR + AVAIL_ALG + AVAIL_RANDOM_STR

    results = []
    for algorithm in all_algorithms:
        if algorithm in AVAIL_HASH_STR and AVAIL_HASH_STR.index(
                algorithm) == 0:
            results.append("========== HASH ALGORITHMS ==========")
        if algorithm in AVAIL_ALG and AVAIL_ALG.index(algorithm) == 0:
            results.append("\n========== CRYPTO ALGORITHMS ==========")
        if algorithm in AVAIL_RANDOM_STR and AVAIL_RANDOM_STR.index(
                algorithm) == 0:
            results.append("\n========== RANDOM ALGORITHMS ==========")
        result = benchmark(algorithm, length, rsa_keysize)
        if algorithm in AVAIL_ALG:
            results.append(result[0][0])
            results.append(result[0][1])
            results.append(result[1])
        else:
            results.append(result)

    return results


def _benchmark_hash(algorithm, data):
    try:
        index = AVAIL_HASH_STR.index(algorithm)
    except ValueError as e:
        raise hash_not_supported() from e

    alg = AVAIL_HASH[index]
    start = perf_counter_ns()
    if alg != md5:
        alg.new(data=data).digest()
    else:
        md5(data).digest()
    consumed = perf_counter_ns() - start

    return (algorithm, _format_time(consumed))


def _benchmark_random(algorithm, length):
    if _os_name != 'posix' and '(*nux only)' in algorithm:
        return (algorithm, '-')

    start = perf_counter_ns()

    if "dd" in algorithm:
        is_secure = "/dev/urandom" in algorithm
        bs = min(length, 4 * 1024 * 1024)
        count = (length + bs - 1) // bs
        rand.dd_random_to_file(is_secure, "/dev/null", bs, count)
    else:
        rand.random(algorithm, length)

    consumed = perf_counter_ns() - start

    return (algorithm, _format_time(consumed))


def _benchmark_crypto(algorithm, data, rsa_keysize=None):
    plaintext = bytes()
    encrypt_consumed = 0
    decrypt_consumed = 0
    if algorithm == 'aes':
        key = randbytes(16)

        start_encrypt = perf_counter_ns()
        ciphertext = primitives.aes_encrypt(CryptoConfig(), key, data)
        encrypt_consumed = perf_counter_ns() - start_encrypt

        start_decrypt = perf_counter_ns()
        plaintext = primitives.aes_decrypt(CryptoConfig(), key, ciphertext)
        decrypt_consumed = perf_counter_ns() - start_decrypt
    elif algorithm == "rsa-oaep":
        priv_key = _rsa.generate(rsa_keysize)
        pub_key = priv_key.public_key()

        start_encrypt = perf_counter_ns()
        ciphertext = primitives.rsa_oaep_encrypt(CryptoConfig(), pub_key, data)
        encrypt_consumed = perf_counter_ns() - start_encrypt

        start_decrypt = perf_counter_ns()
        plaintext = primitives.rsa_oaep_decrypt(
            CryptoConfig(), priv_key, ciphertext)
        decrypt_consumed = perf_counter_ns() - start_decrypt
    elif algorithm == "extended_oaep":
        priv_key = _rsa.generate(rsa_keysize)
        pub_key = priv_key.public_key()

        start_encrypt = perf_counter_ns()
        ciphertext = oaep_extended_encrypt(CryptoConfig(), pub_key, data)
        encrypt_consumed = perf_counter_ns() - start_encrypt

        start_decrypt = perf_counter_ns()
        plaintext = oaep_extended_decrypt(CryptoConfig(), priv_key, ciphertext)
        decrypt_consumed = perf_counter_ns() - start_decrypt
    elif re.search(r"^ML-KEM-(768|1024)$", algorithm):
        pubkey, privkey = genkey(algorithm, "PEM")

        start_encrypt = perf_counter_ns()
        ciphertext = kyber_encrypt(CryptoConfig(), pubkey, data)
        encrypt_consumed = perf_counter_ns() - start_encrypt

        start_decrypt = perf_counter_ns()
        plaintext = kyber_decrypt(CryptoConfig(), privkey, ciphertext)
        decrypt_consumed = perf_counter_ns() - start_decrypt

    if plaintext != data:
        return (
            (f'{algorithm}-encrypt', _format_time(encrypt_consumed)),
            (f'{algorithm}-decrypt', 'failed')
        )
    return (
        (f'{algorithm}-encrypt', _format_time(encrypt_consumed)),
        (f'{algorithm}-decrypt', _format_time(decrypt_consumed))
    )


def _benchmark_keygen(algorithm, rsa_keysize):
    start = perf_counter_ns()
    if algorithm == "aes":
        randbytes(32)
        label = "aes-keygen"
    elif algorithm in ("rsa-oaep", "extended_oaep"):
        primitives.genrsa(rsa_keysize, 65537, None)
        label = f"{algorithm}-keygen"
    elif re.search(r"^ML-KEM-(768|1024)$", algorithm):
        genkey(algorithm, "PEM")
        label = f"{algorithm}-keygen"
    else:
        raise algorithm_not_supported()
    consumed = perf_counter_ns() - start
    return label, _format_time(consumed)


def _format_time(ns):
    if ns < 1_000_000:
        return f"{ns} ns"
    if ns < 1_000_000_000:
        return f"{ns / 1_000_000:.3f} ms"
    if ns < 60_000_000_000:
        return f"{ns / 1_000_000_000:.3f} s"
    return f"{ns / 60_000_000_000:.3f} m"
