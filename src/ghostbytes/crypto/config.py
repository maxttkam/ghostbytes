"""
config.py

Defines encryption configuration used by Ghostbytes:
which cipher, hash function, KDF parameters, and random source to use,
plus helper functions (import, export, and generate configuration)
to save / load configurations to / from a config file.

See docs/confguration.md
"""
import base64
import configparser
from hashlib import md5
from Crypto.Hash import SHA3_512, SHA3_256, SHA512, SHA256, BLAKE2b, BLAKE2s
from ghostbytes.error import invalid_configuration

AVAIL_HASH = [SHA3_512, SHA3_256, SHA512, SHA256, BLAKE2b, BLAKE2s, md5]
AVAIL_HASH_STR = [
    "sha3_512",
    "sha3_256",
    "sha512",
    "sha256",
    "blake2b",
    "blake2s",
    "md5"]
AVAIL_ALG = ["aes", "rsa-oaep", "extended_oaep", "ML-KEM-768", "ML-KEM-1024"]
AVAIL_SIGN_ALG = ["RSA-PSS", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
AVAIL_RANDOM_STR = [
    "os.urandom",
    "cryptodome_random",
    "random lib (python)",
    "secrets_random",
    "/dev/urandom (*nux only)",
    "/dev/random (*nux only)",
    "/dev/urandom (dd, out file only) (*nux only)",
    "/dev/random (dd, out file only) (*nux only)",
]
ENCRYPTED_SUFFIX = ".enc"
RSA_KEY_OUT_FORMAT = ["PEM", "DER", "OpenSSH"]
COMMON_RSA_SIZE = [2048, 4096, 8192]
RSA_SIZE_WARNING_THRESHOLD = 4096

OVERWRITE_OPTIONS = [
    'random',
    'zero',
    'one',
    'gutmann'
]

RANDOM_SALT_SIZE = 64


class CryptoConfig:
    """
    Holds cryptographic parameters used to encrypt / decrypt a file.

    An instance can be created via `CryptoConfig()`, randomised via
    `CryptoConfig.generate_random_salt()`, or restored from disk via
    `CryptoConfig.import_file(path)`. Use `export_file(path)` to persist it.

    Fields such as `algorithm`, `store_iv`, `mac_len`, and all kdf parameters must
    remain the identical between encryptor and decryptor to allow ciphertext
    to be successfully decrypted.

    It is also recommended to use a DIFFERERNT SALT per encryption pair to prevent
    rainbow table attacks. Use `export_file` and `import_file` to ensure the
    cryptographic configurations are the same.
    """
    algorithm = AVAIL_ALG[0]

    store_iv = "append"  # or "prepend"
    mac_len = 16
    kdf_salt = b"CHANGE_ME_F1L3_3NCRYP710N_53CR37_54L7_70_3N5UR3_R4ND0MN355"
    kdf_time_cost = 16
    kdf_memory_cost = 128 * 1024  # 128 MB, times 1024 to get KB
    kdf_parallelism = 8

    hash_func = AVAIL_HASH[0]
    rand_func = AVAIL_RANDOM_STR[0]

    def generate_random_salt(self, length=64):
        """Generate and store a new KDF salt using this config's random source."""

        # Imports random within the function prevents cross-import error
        from ghostbytes.tools.rand import random

        self.kdf_salt = random(self.rand_func, length)
        return self.kdf_salt

    def export_file(self, path):
        """Exports the current `CryptoConfig` state to a `.conf` file"""
        parser = configparser.ConfigParser()
        parser["CryptoConfig"] = {
            "algorithm": self.algorithm,
            "store_iv": self.store_iv,
            "mac_len": str(self.mac_len),
            "kdf_salt": base64.b64encode(self.kdf_salt).decode("ascii"),
            "kdf_time_cost": str(self.kdf_time_cost),
            "kdf_memory_cost": str(self.kdf_memory_cost),
            "kdf_parallelism": str(self.kdf_parallelism),
            "hash_func": AVAIL_HASH_STR[AVAIL_HASH.index(self.hash_func)],
            "rand_func": self.rand_func,
        }
        with open(path, "w", encoding="utf-8") as file:
            parser.write(file)

    @classmethod
    def import_file(cls, path):
        """Imports the previous `CryptoConfig` state through a `.conf` file"""
        parser = configparser.ConfigParser()
        try:
            if not parser.read(
                    path,
                    encoding="utf-8") or "CryptoConfig" not in parser:
                raise invalid_configuration("missing CryptoConfig section")
        except (OSError, UnicodeDecodeError, configparser.Error) as exc:
            raise invalid_configuration("file could not be read") from exc

        values = parser["CryptoConfig"]
        try:
            algorithm = values["algorithm"]
            store_iv = values["store_iv"]
            mac_len = values.getint("mac_len")
            kdf_salt = base64.b64decode(values["kdf_salt"], validate=True)
            kdf_time_cost = values.getint("kdf_time_cost")
            kdf_memory_cost = values.getint("kdf_memory_cost")
            kdf_parallelism = values.getint("kdf_parallelism")
            hash_name = values["hash_func"]
            rand_func = values["rand_func"]
        except (KeyError, ValueError) as e:
            raise invalid_configuration(
                "one or more values are malformed") from e

        if algorithm not in AVAIL_ALG:
            raise invalid_configuration("unsupported algorithm")
        if store_iv not in ("append", "prepend"):
            raise invalid_configuration("invalid IV storage mode")
        if not 4 <= mac_len <= 16:
            raise invalid_configuration(
                "MAC length must be between 4 and 16 bytes")
        if not kdf_salt or kdf_time_cost < 1 or kdf_memory_cost < 1 or kdf_parallelism < 1:
            raise invalid_configuration("invalid KDF settings")
        if hash_name not in AVAIL_HASH_STR or rand_func not in AVAIL_RANDOM_STR:
            raise invalid_configuration("unsupported hash or random function")

        config = cls()
        config.algorithm = algorithm
        config.store_iv = store_iv
        config.mac_len = mac_len
        config.kdf_salt = kdf_salt
        config.kdf_time_cost = kdf_time_cost
        config.kdf_memory_cost = kdf_memory_cost
        config.kdf_parallelism = kdf_parallelism
        config.hash_func = AVAIL_HASH[AVAIL_HASH_STR.index(hash_name)]
        config.rand_func = rand_func
        return config
