"""
Thin bridge between the GUI layer and the ``ghostbytes.crypto`` / ``ghostbytes.tools``
backends.

Every function in this module is plain Python: it takes simple arguments
(paths, strings, bytes, numbers) and either returns a result or raises one of
the exceptions defined in :mod:`ghostbytes.error` (``CryptoError`` /
``GeneralError``). None of it touches Tkinter/CustomTkinter, which means the
GUI can safely call any of these from a background thread and only has to
know how to handle two exception types.
"""
from __future__ import annotations

import os
import re

from Crypto.PublicKey import RSA as _rsa

from ghostbytes.crypto import crypto as _crypto
from ghostbytes.crypto import kyber as _kyber
from ghostbytes.crypto import primitives as _primitives
from ghostbytes.crypto.config import (
    AVAIL_ALG,
    AVAIL_HASH,
    AVAIL_HASH_STR,
    AVAIL_RANDOM_STR,
    ENCRYPTED_SUFFIX,
    RSA_KEY_OUT_FORMAT,
    CryptoConfig,
)
from ghostbytes.error import (
    file_not_found,
    invalid_argument,
    invalid_configuration_type,
    invalid_keyfile,
    invalid_mode,
    not_a_file,
    parameter_not_exist,
    unsupported_mlkem_key,
)
from ghostbytes.tools import benchmark as _benchmark
from ghostbytes.tools import rand as _random
from ghostbytes.tools import shred as _shred

# This module is a compatibility bridge with intentionally broad public
# signatures used by both the GUI and CLI layers.
# pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals,import-outside-toplevel,line-too-long,missing-function-docstring,unused-variable

# --------------------------------------------------------------------------- #
# Configuration — every field of CryptoConfig is settable from here
# --------------------------------------------------------------------------- #


def build_config(
    algorithm=CryptoConfig.algorithm,
    store_iv=CryptoConfig.store_iv,
    mac_len=CryptoConfig.mac_len,
    kdf_salt=CryptoConfig.kdf_salt,
    kdf_time_cost=CryptoConfig.kdf_time_cost,
    kdf_memory_cost=CryptoConfig.kdf_memory_cost,
    kdf_parallelism=CryptoConfig.kdf_parallelism,
    hash_func_str=CryptoConfig.hash_func,
    rand_func=CryptoConfig.rand_func,
):
    """Build a :class:`CryptoConfig` from the values the "Advanced" section of
    the GUI exposes. Every field of ``CryptoConfig`` is represented here,
    including ``kdf_salt`` — note that it must stay identical for every user
    of a given encrypted file, so changing it from the default is only safe
    when you control both ends.
    """
    if algorithm not in AVAIL_ALG:
        raise invalid_argument("algorithm", "is unsupported")
    if store_iv not in ("append", "prepend"):
        raise invalid_argument("store_iv", "must be `append` or `prepend`")
    if not isinstance(mac_len, int) or not 4 <= mac_len <= 16:
        raise invalid_argument(
            "mac_len", "must be an integer between 4 and 16")
    if isinstance(kdf_salt, str):
        kdf_salt = kdf_salt.encode("utf-8")
    if not isinstance(kdf_salt, bytes) or not kdf_salt:
        raise invalid_argument("kdf_salt", "must be non-empty bytes")
    if any(
        not isinstance(
            value,
            int) or value < 1 for value in (
            kdf_time_cost,
            kdf_memory_cost,
            kdf_parallelism)):
        raise invalid_argument("KDF settings", "must be positive integers")
    if hash_func_str not in AVAIL_HASH_STR:
        raise invalid_argument("hash_func", "is unsupported")
    if rand_func not in AVAIL_RANDOM_STR:
        raise invalid_argument("rand_func", "is unsupported")

    cfg = CryptoConfig()
    cfg.algorithm = algorithm
    cfg.store_iv = store_iv
    cfg.mac_len = mac_len
    cfg.kdf_salt = kdf_salt
    cfg.kdf_time_cost = kdf_time_cost
    cfg.kdf_memory_cost = kdf_memory_cost
    cfg.kdf_parallelism = kdf_parallelism
    cfg.hash_func = AVAIL_HASH[AVAIL_HASH_STR.index(hash_func_str)] if isinstance(
        hash_func_str, str) else hash_func_str
    cfg.rand_func = rand_func
    return cfg


# --------------------------------------------------------------------------- #
# File I/O helpers
# --------------------------------------------------------------------------- #

def _read_file(path):
    if not os.path.exists(path):
        raise file_not_found()
    if not os.path.isfile(path):
        raise not_a_file()
    with open(path, "rb") as f:
        return f.read()


def _write_file(path, data):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


# --------------------------------------------------------------------------- #
# Encrypt / Decrypt
# --------------------------------------------------------------------------- #

def encrypt_file(in_path, out_path, config, key, rsa_passphrase=None):
    _require_config(config)
    plaintext = _read_file(in_path)
    ciphertext = _crypto.encrypt(config, key, plaintext, rsa_passphrase)
    _write_file(out_path, ciphertext)
    return out_path


def decrypt_file(in_path, out_path, config, key, rsa_passphrase=None):
    _require_config(config)
    ciphertext = _read_file(in_path)
    plaintext = _crypto.decrypt(config, key, ciphertext, rsa_passphrase)
    _write_file(out_path, plaintext)
    return out_path


def encrypt_paths(paths, output_path, config, key, rsa_passphrase=None):
    """Encrypt one or many paths, returning the written output paths."""
    _require_config(config)
    paths = list(paths)
    if len(paths) == 1:
        return [
            encrypt_file(
                paths[0],
                output_path,
                config,
                key,
                rsa_passphrase)]
    extension = os.path.splitext(output_path)[
        1] if output_path else ENCRYPTED_SUFFIX
    extension = extension or ENCRYPTED_SUFFIX
    return [
        encrypt_file(path, path + extension, config, key, rsa_passphrase)
        for path in paths
    ]


def decrypt_paths(paths, output_path, config, key, rsa_passphrase=None):
    """Decrypt one or many paths, returning the written output paths."""
    _require_config(config)
    paths = list(paths)
    if len(paths) == 1:
        return [
            decrypt_file(
                paths[0],
                output_path,
                config,
                key,
                rsa_passphrase)]
    extension = os.path.splitext(output_path)[1] if output_path else ""
    return [
        decrypt_file(
            path,
            remove_encrypted_suffix(path) + extension,
            config, key, rsa_passphrase,
        )
        for path in paths
    ]


def remove_encrypted_suffix(path):
    """Remove one configured terminal encrypted-file suffix."""
    return re.sub(f"{re.escape(ENCRYPTED_SUFFIX)}$", "",
                  path, count=1, flags=re.IGNORECASE)


def detect_mlkem_algorithm(key_data, passphrase=None):
    """Return the ML-KEM algorithm name encoded by a public/private key."""
    from cryptography.hazmat.primitives import serialization

    if not isinstance(key_data, bytes):
        raise invalid_keyfile()
    key_format = _primitives.detect_key_format(key_data)
    password = passphrase.encode("utf-8") if passphrase else None
    try:
        loader = serialization.load_pem_private_key if key_format == "PEM" else serialization.load_der_private_key
        key = loader(key_data, password=password)
    except (ValueError, TypeError):
        try:
            loader = serialization.load_pem_public_key if key_format == "PEM" else serialization.load_der_public_key
            key = loader(key_data)
        except (ValueError, TypeError) as exc:
            raise invalid_keyfile() from exc
    key_name = type(key).__name__
    if "MLKEM768" in key_name:
        return "ML-KEM-768"
    if "MLKEM1024" in key_name:
        return "ML-KEM-1024"
    raise unsupported_mlkem_key()


def batch_process(
        mode,
        in_dir,
        out_dir,
        config,
        key,
        rsa_passphrase=None,
        progress_cb=None):
    """Recursively encrypt/decrypt every file under ``in_dir`` into ``out_dir``,
    preserving the folder structure. ``mode`` is ``"encrypt"`` or
    ``"decrypt"``. ``progress_cb(done, total, current_path)`` is invoked
    after each file, if provided. Returns the number of files processed.
    """
    _require_config(config)
    if mode not in ("encrypt", "decrypt"):
        raise invalid_mode(mode)
    if not os.path.isdir(in_dir):
        raise not_a_file()

    files = []
    for root, _dirs, filenames in os.walk(in_dir):
        for name in filenames:
            files.append(os.path.join(root, name))

    total = len(files)
    func = encrypt_file if mode == "encrypt" else decrypt_file

    for i, src in enumerate(files):
        rel = os.path.relpath(src, in_dir)
        if mode == "encrypt":
            rel = rel + ENCRYPTED_SUFFIX
        elif rel.endswith(ENCRYPTED_SUFFIX):
            rel = rel[: -len(ENCRYPTED_SUFFIX)]
        dst = os.path.join(out_dir, rel)
        func(src, dst, config, key, rsa_passphrase)
        if progress_cb:
            progress_cb(i + 1, total, src)

    return total


def _require_config(config):
    if not isinstance(config, CryptoConfig):
        raise invalid_configuration_type()


# --------------------------------------------------------------------------- #
# RSA key management
# --------------------------------------------------------------------------- #

def generate_rsa_keypair(
        key_len,
        exponent,
        passphrase,
        out_format=RSA_KEY_OUT_FORMAT[0]):
    return _primitives.genrsa(
        key_len,
        exponent,
        passphrase or None,
        out_format)


def verify_rsa_keypair(public_key, private_key, passphrase):
    return _primitives.verify_rsa(public_key, private_key, passphrase or None)


def generate_mlkem_keypair(algorithm, out_format, passphrase=None):
    return _kyber.genkey(
        algorithm,
        out_format,
        passphrase.encode("utf-8") if passphrase else None)


def verify_keypair(public_key, private_key, passphrase=None):
    if _primitives.keytype(public_key) == "ML-KEM":
        return _kyber.verify_key(
            public_key,
            private_key,
            passphrase.encode("utf-8") if passphrase else None)
    return verify_rsa_keypair(public_key, private_key, passphrase)


def rsa_key_info(key_data, passphrase=None):
    key = _rsa.import_key(key_data, passphrase or None)
    exponent_prime = _is_prime(key.e)
    return {
        "Key size": f"{key.size_in_bits()} bits",
        "Has private key": "Yes" if key.has_private() else "No",
        "Can encrypt": "Yes" if key.can_encrypt() else "No",
        "Public exponent (e)": str(key.e),
        "e is prime": "Yes" if exponent_prime else "No",
        "Cryptographically usable": "Yes" if key.can_encrypt() and exponent_prime else "No",
        "Modulus bit length": str(key.n.bit_length()),
    }


def key_info(key_data, passphrase=None):
    key_type = _primitives.keytype(
        key_data, passphrase.encode("utf-8") if passphrase else None)
    if key_type == "RSA":
        return {"Key type": "RSA", **rsa_key_info(key_data, passphrase)}
    key_format = _primitives.detect_key_format(key_data)
    from cryptography.hazmat.primitives import serialization
    password = passphrase.encode("utf-8") if passphrase else None
    try:
        loader = serialization.load_pem_private_key if key_format == "PEM" else serialization.load_der_private_key
        key = loader(key_data, password=password)
    except (ValueError, TypeError):
        loader = serialization.load_pem_public_key if key_format == "PEM" else serialization.load_der_public_key
        key = loader(key_data)
    algorithm = type(key).__name__.replace(
        "PublicKey", "").replace(
        "PrivateKey", "")
    return {
        "Key type": "ML-KEM",
        "Algorithm": algorithm,
        "Has private key": "Yes" if hasattr(
            key,
            "decapsulate") else "No",
        "Key usability": "True" if hasattr(
            key,
            "encapsulate") or hasattr(
                key,
                "decapsulate") else "Unsupported key object",
    }


def _is_prime(value):
    if value < 2:
        return False
    if value % 2 == 0:
        return value == 2
    divisor = 3
    while divisor * divisor <= value:
        if value % divisor == 0:
            return False
        divisor += 2
    return True


def rsa_key_bits(key_data, passphrase=None):
    """Bit length of an RSA key, used by the GUI to decide whether to show
    the "this will be slow in pure Python" warning before an operation."""
    return _rsa.import_key(key_data, passphrase or None).size_in_bits()


# --------------------------------------------------------------------------- #
# Hashing — single files, multi-file batches, and whole folders
# --------------------------------------------------------------------------- #

def hash_file(path, algorithm_str):
    data = _read_file(path)
    alg = AVAIL_HASH[AVAIL_HASH_STR.index(algorithm_str)]
    # `data=` (keyword) is required here: BLAKE2b/BLAKE2s only accept it as
    # a keyword argument, unlike the SHA-family modules.
    if algorithm_str == "md5":
        return alg(data).hexdigest()
    return alg.new(data=data).hexdigest()


def collect_folder_files(folder):
    """Return [(relative_path, absolute_path), ...] for every file under
    ``folder``, recursively."""
    if not os.path.isdir(folder):
        raise not_a_file()
    items = []
    for root, _dirs, filenames in os.walk(folder):
        for name in filenames:
            full = os.path.join(root, name)
            items.append((os.path.relpath(full, folder), full))
    return items


def hash_paths(entries, algorithm_str, progress_cb=None):
    """``entries``: an iterable of ``(label, filepath)`` pairs — ``label`` is
    what gets shown/written (a relative path for a folder batch, or a bare
    filename for a manual file selection). Returns ``[(label, digest), ...]``
    in the same order. ``progress_cb(done, total, label)`` fires per file.
    """
    entries = list(entries)
    total = len(entries)
    results = []
    for i, (label, path) in enumerate(entries):
        results.append((label, hash_file(path, algorithm_str)))
        if progress_cb:
            progress_cb(i + 1, total, label)
    return results


def checksum_suffix(algorithm_str):
    """Return the conventional checksum filename suffix."""
    return f"{algorithm_str}sum"


def checksum_root(paths):
    """Return the closest common directory containing all selected paths."""
    paths = [os.path.abspath(path) for path in paths]
    if not paths:
        return os.getcwd()
    directories = [path if os.path.isdir(
        path) else os.path.dirname(path) for path in paths]
    return os.path.commonpath(directories)


def checksum_entries_for_output(entries, output_path):
    """Return checksum entries labelled relative to the output file directory."""
    output_directory = os.path.dirname(
        os.path.abspath(output_path)) or os.getcwd()
    normalized = []
    for label, path in entries:
        try:
            checksum_label = os.path.relpath(path, output_directory)
        except ValueError:
            checksum_label = os.path.abspath(path)
        normalized.append((checksum_label, path))
    return normalized


def write_checksum_file(path, entries):
    """``entries``: ``[(label, digest), ...]``. Writes one
    ``<digest>  <label>`` line per entry (the conventional `*sum` format)."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for label, digest in entries:
            f.write(f"{digest}  {label}\n")


# --------------------------------------------------------------------------- #
# Random data / passwords
# --------------------------------------------------------------------------- #

def random_bytes(algorithm_str, length):
    return _random.random(algorithm_str, length)


_PASSWORD_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?"


def generate_password(
    length=16,
    use_upper=True,
    use_lower=True,
    use_digits=True,
    use_symbols=True,
    random_source=AVAIL_RANDOM_STR[0],
):
    """Generate a password using the *selected* random source (any of
    ``AVAIL_RANDOM_STR``) rather than always relying on ``secrets``. Uses
    rejection sampling against the charset size to avoid modulo bias.
    """
    charset = ""
    if use_lower:
        charset += "abcdefghijklmnopqrstuvwxyz"
    if use_upper:
        charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if use_digits:
        charset += "0123456789"
    if use_symbols:
        charset += _PASSWORD_SYMBOLS
    if not charset:
        raise parameter_not_exist("charset")

    if not isinstance(length, int) or length < 1:
        raise invalid_argument("length", "must be a positive integer")
    n = len(charset)
    limit = 256 - (256 % n)  # bytes >= limit are rejected to avoid modulo bias

    chars = []
    while len(chars) < length:
        pool = random_bytes(random_source, max((length - len(chars)) * 2, 16))
        for b in pool:
            if b < limit:
                chars.append(charset[b % n])
                if len(chars) == length:
                    break
    return "".join(chars)


# --------------------------------------------------------------------------- #
# Benchmark
# --------------------------------------------------------------------------- #

def run_benchmark(algorithm, length, rsa_keysize):
    return _benchmark.benchmark(algorithm, length, rsa_keysize)


# --------------------------------------------------------------------------- #
# Secure delete / free space wipe
# --------------------------------------------------------------------------- #

def secure_delete_file(
        path,
        method,
        zeroise,
        delete,
        chunksize,
        random_func=AVAIL_RANDOM_STR[0],
        repeat=1):
    _shred.shred_file(
        path,
        method,
        zeroise,
        delete,
        chunksize *
        1024,
        random_func,
        repeat)


def secure_delete_paths(
        paths,
        method,
        zeroise,
        delete,
        chunksize,
        random_func=AVAIL_RANDOM_STR[0],
        repeat=1):
    for path in paths:
        secure_delete_file(
            path,
            method,
            zeroise,
            delete,
            chunksize,
            random_func,
            repeat)
    return list(paths)


def wipe_free_space(
        device,
        chunksize,
        zeroise,
        random_func=AVAIL_RANDOM_STR[0]):
    _shred.wipe_free_space(device, chunksize * 1024, zeroise, random_func)


def list_partitions():
    from psutil import disk_partitions
    return disk_partitions(True)
