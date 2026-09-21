"""Smoke-test the public functionality used by the Ghostbytes GUI/CLI.

Run with ``python tools/test.py``.  The runner intentionally does not call
``wipe_free_space`` because that operation writes across free disk space.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import tempfile
from pathlib import Path

from colorama import Fore, Style, init

from ghostbytes.crypto.config import AVAIL_HASH_STR, CryptoConfig
from ghostbytes.crypto import crypto as crypto_backend
from ghostbytes.gui import wrappers as cli


init(autoreset=True)

_VERBOSE = False


def _step(message, reason=None):
    if _VERBOSE:
        print(Fore.BLUE + f"  STEP  {message}")
        print(
            Fore.WHITE +
            f"        WHY   {
                reason or 'This checks that the operation behaves as expected.'}")


def _output(label, value):
    """Display function results in an educational, terminal-friendly form."""
    if not _VERBOSE:
        return
    if isinstance(value, bytes):
        hex_value = value.hex()
        if len(hex_value) > 128:
            hex_value = f"{hex_value[:128]}... ({len(value)} bytes total)"
        print(Fore.YELLOW + f"        OUT   {label}: 0x{hex_value}")
    elif isinstance(value, str):
        print(Fore.YELLOW +
              f"        OUT   {label}: {value!r} (utf-8 hex: 0x{value.encode().hex()})")
    else:
        print(Fore.YELLOW + f"        OUT   {label}: {value!r}")


def _config(algorithm="aes", hash_func="sha3_512"):
    """Return a fast configuration suitable for a smoke test."""
    return cli.build_config(
        algorithm=algorithm,
        kdf_salt=b"test-salt",
        kdf_time_cost=1,
        kdf_memory_cost=1024,
        kdf_parallelism=1,
        hash_func_str=hash_func,
    )


def _check(condition, message):
    if not condition:
        raise AssertionError(message)


def _test_config_and_crypto(root):
    _step("export and import AES configuration")
    plaintext = b"Ghostbytes integration test payload"
    source = root / "plain.txt"
    source.write_bytes(plaintext)

    config = _config()
    config_path = root / "crypto.conf"
    config.export_file(config_path)
    restored = CryptoConfig.import_file(config_path)
    _output("restored algorithm", restored.algorithm)
    _output("restored salt", restored.kdf_salt)
    _check(restored.algorithm == "aes",
           "configuration algorithm was not restored")
    _check(restored.kdf_salt == config.kdf_salt,
           "configuration salt was not restored")

    encrypted = root / "plain.fvlt"
    decrypted = root / "decrypted.txt"
    _step("AES file encrypt/decrypt")
    cli.encrypt_file(source, encrypted, config, b"test-password")
    cli.decrypt_file(encrypted, decrypted, restored, b"test-password")
    _output("decrypted plaintext", decrypted.read_bytes())
    _check(decrypted.read_bytes() == plaintext, "AES round trip failed")

    for store_iv in ("append", "prepend"):
        _step(f"AES encrypt/decrypt with {store_iv} IV storage")
        iv_config = _config()
        iv_config.store_iv = store_iv
        ciphertext = crypto_backend.encrypt(
            iv_config, b"test-password", plaintext)
        _output(f"AES {store_iv} ciphertext", ciphertext)
        _check(
            crypto_backend.decrypt(
                iv_config,
                b"test-password",
                ciphertext) == plaintext,
            f"AES {store_iv} round trip failed")


def _test_rsa(_):
    _step("generate, inspect, and verify RSA-1024 key pair")
    plaintext = b"RSA"
    public_key, private_key = cli.generate_rsa_keypair(1024, 65537, "secret")
    _output("RSA public key", public_key)
    _output("RSA private key", private_key)
    _check(
        cli.verify_rsa_keypair(
            public_key,
            private_key,
            "secret"),
        "RSA keys do not match")
    info = cli.key_info(private_key, "secret")
    _output("RSA key information", info)
    _check(info["Key type"] == "RSA", "RSA key type was not detected")
    _check(cli.rsa_key_bits(private_key, "secret")
           == 1024, "RSA key size was not detected")

    for algorithm in ("rsa-oaep", "extended_oaep"):
        _step(f"{algorithm} encrypt/decrypt")
        config = _config(algorithm, "sha256")
        ciphertext = crypto_backend.encrypt(config, public_key, plaintext)
        _output(f"{algorithm} ciphertext", ciphertext)
        recovered = crypto_backend.decrypt(
            config, private_key, ciphertext, "secret")
        _check(recovered == plaintext, f"{algorithm} round trip failed")


def _test_mlkem(_):
    plaintext = b"ML-KEM integration test"
    for algorithm in ("ML-KEM-768", "ML-KEM-1024"):
        _step(f"{algorithm} generate, inspect, verify, encrypt, and decrypt")
        public_key, private_key = cli.generate_mlkem_keypair(
            algorithm, "PEM", "secret")
        _output(f"{algorithm} public key", public_key)
        _output(f"{algorithm} private key", private_key)
        _check(cli.verify_keypair(public_key, private_key, "secret"),
               f"{algorithm} keys do not match")
        _check(cli.detect_mlkem_algorithm(public_key) == algorithm,
               f"{algorithm} key type was not detected")
        _check(cli.key_info(private_key, "secret")["Key type"] == "ML-KEM",
               f"{algorithm} key info failed")
        config = _config(algorithm)
        ciphertext = crypto_backend.encrypt(config, public_key, plaintext)
        _output(f"{algorithm} ciphertext", ciphertext)
        _check(
            crypto_backend.decrypt(
                config,
                private_key,
                ciphertext,
                "secret") == plaintext,
            f"{algorithm} round trip failed")


def _test_files_hashes_and_batches(root):
    _step("collect folder files and report hash progress")
    source = root / "files"
    nested = source / "nested"
    nested.mkdir(parents=True)
    (source / "one.txt").write_bytes(b"one")
    (nested / "two.txt").write_bytes(b"two")

    entries = cli.collect_folder_files(source)
    progress = []
    hashes = cli.hash_paths(
        entries,
        "sha256",
        lambda done,
        total,
        label: progress.append(done))
    _output("SHA-256 folder hashes", hashes)
    _check(len(hashes) == 2 and progress == [1, 2], "folder hashing failed")
    _check(
        cli.hash_file(
            source / "one.txt",
            "sha256") == hashlib.sha256(b"one").hexdigest(),
        "single-file hash failed")
    for algorithm in AVAIL_HASH_STR:
        _step(f"{algorithm} single-file hash")
        digest = cli.hash_file(source / "one.txt", algorithm)
        _output(f"{algorithm} digest", digest)
        _check(len(digest) > 0,
               f"{algorithm} hash failed")
    _check(cli.checksum_suffix("sha256") ==
           "sha256sum", "checksum suffix failed")

    encrypted_dir = root / "encrypted"
    decrypted_dir = root / "decrypted"
    config = _config()
    _step("batch AES encryption")
    count = cli.batch_process(
        "encrypt",
        source,
        encrypted_dir,
        config,
        b"password")
    _output("encrypted file count", count)
    _step("batch AES decryption")
    _check(count == 2, "batch encryption count failed")
    count = cli.batch_process(
        "decrypt",
        encrypted_dir,
        decrypted_dir,
        config,
        b"password")
    _output("decrypted file count", count)
    _check(
        count == 2 and (
            decrypted_dir /
            "nested" /
            "two.txt").read_bytes() == b"two",
        "batch decryption failed")

    checksum_path = root / "checksums.txt"
    _step("write checksum file")
    checksum_entries = cli.checksum_entries_for_output(hashes, checksum_path)
    cli.write_checksum_file(checksum_path, checksum_entries)
    _check(len(checksum_path.read_text(encoding="utf-8").splitlines()) == 2,
           "checksum file writing failed")


def _test_random_password_benchmark_and_delete(root):
    for source in (
        "os.urandom",
        "cryptodome_random",
        "secrets_random",
            "random lib (python)"):
        _step(f"random bytes from {source}")
        random_data = cli.random_bytes(source, 16)
        _output(source, random_data)
        _check(len(random_data) == 16, f"random source failed: {source}")
    _step("generate password")
    password = cli.generate_password(24)
    _output("generated password", password)
    _step("run SHA-256 benchmark")
    _check(len(password) == 24, "password generation failed")
    benchmark_result = cli.run_benchmark("sha256", 32, 1024)
    _output("benchmark result", benchmark_result)
    _check(benchmark_result[0] == "sha256", "benchmark failed")
    partitions = cli.list_partitions()
    _output("partitions", partitions)
    _check(partitions, "partition listing failed")

    for method in ("random", "zero", "one", "gutmann"):
        _step(f"secure overwrite using {method}")
        target = root / f"{method}.bin"
        target.write_bytes(b"sensitive test data")
        cli.secure_delete_file(target, method, False, False, 1, repeat=1)
        _check(target.exists() and target.stat().st_size == len(
            b"sensitive test data"), f"secure overwrite failed: {method}")

    deleted = root / "delete-me.bin"
    _step("secure overwrite and delete file")
    deleted.write_bytes(b"delete me")
    cli.secure_delete_file(deleted, "zero", True, True, 1)
    _check(not deleted.exists(), "secure delete failed")


def test_cli(verbose=False):
    """Run all non-interactive public CLI/backend functionality.

    Args:
            verbose: Print every individual test step when ``True``.

    Returns ``True`` when every test passes and ``False`` otherwise.
    """
    global _VERBOSE  # pylint: disable=global-statement
    _VERBOSE = verbose
    tests = (
        ("configuration and AES",
         _test_config_and_crypto),
        ("RSA key management and encryption",
         _test_rsa),
        ("ML-KEM key management and encryption",
         _test_mlkem),
        ("files, hashes, checksums, and batches",
         _test_files_hashes_and_batches),
        ("random, passwords, benchmark, and secure delete",
         _test_random_password_benchmark_and_delete),
    )
    failures = 0
    print(Fore.CYAN + "Ghostbytes functional test suite")
    with tempfile.TemporaryDirectory(prefix="ghostbytes-test-") as directory:
        root = Path(directory)
        for name, test in tests:
            try:
                test(root)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                failures += 1
                print(Fore.RED + f"FAIL  {name}: {exc}")
            else:
                print(Fore.GREEN + f"PASS  {name}")

    if failures:
        print(Fore.RED + Style.BRIGHT + f"{failures} test group(s) failed")
        return False
    print(Fore.GREEN + Style.BRIGHT + "All functional tests passed")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run Ghostbytes functional tests")
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="print every test step and algorithm",
    )
    args = parser.parse_args()
    sys.exit(0 if test_cli(args.verbose) else 1)
