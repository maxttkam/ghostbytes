from typing import Literal, TypeAlias

from Crypto.PublicKey.RSA import RsaKey

from ghostbytes.crypto.config import (
    AVAIL_ALG,
    AVAIL_HASH,
    AVAIL_HASH_STR,
    AVAIL_RANDOM_STR,
    AVAIL_SIGN_ALG,
    COMMON_RSA_SIZE,
    ENCRYPTED_SUFFIX,
    OVERWRITE_OPTIONS,
    RANDOM_SALT_SIZE,
    RSA_KEY_OUT_FORMAT,
    RSA_SIZE_WARNING_THRESHOLD,
    CryptoConfig,
)


# Public configuration values
Algorithm: TypeAlias = Literal[
    "aes",
    "rsa-oaep",
    "extended_oaep",
    "ML-KEM-768",
    "ML-KEM-1024",
]
HashName: TypeAlias = Literal[
    "sha3_512",
    "sha3_256",
    "sha512",
    "sha256",
    "blake2b",
    "blake2s",
    "md5",
]
KeyEncoding: TypeAlias = Literal["PEM", "DER", "OpenSSH"]
MLKEMEncoding: TypeAlias = Literal["PEM", "DER"]
MLDSAEncoding: TypeAlias = Literal["PEM", "DER"]
SignAlgorithm: TypeAlias = Literal[
    "RSA-PSS",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
]


# crypto.py
def encrypt(
    config: CryptoConfig,
    key: bytes,
    plaintext: bytes,
    rsa_passphrase: str | bytes | None = None,
) -> bytes: ...


def decrypt(
    config: CryptoConfig,
    key: bytes,
    ciphertext: bytes,
    rsa_passphrase: str | bytes | None = None,
) -> bytes: ...


# primitives.py
def aes_encrypt(config: CryptoConfig, key: bytes, plaintext: bytes) -> bytes: ...


def aes_decrypt(config: CryptoConfig, key: bytes, ciphertext: bytes) -> bytes: ...


def derive_key(config: CryptoConfig, secret: bytes) -> bytes: ...


def rsa_sign(config: CryptoConfig, key: RsaKey, message: bytes) -> bytes: ...


def rsa_verify(
    config: CryptoConfig,
    key: RsaKey,
    message: bytes,
    signature: bytes,
) -> bool: ...


def rsa_oaep_encrypt(
    config: CryptoConfig,
    key: RsaKey,
    plaintext: bytes,
) -> bytes: ...


def rsa_oaep_decrypt(
    config: CryptoConfig,
    key: RsaKey,
    ciphertext: bytes,
) -> bytes: ...


def genrsa(
    length: int,
    exp: int,
    passphrase: str | bytes | None,
    out_format: KeyEncoding = "PEM",
) -> tuple[bytes, bytes]: ...


def verify_rsa(
    public_key: bytes,
    private_key: bytes,
    passphrase: str | bytes | None = None,
) -> bool: ...


def detect_key_format(key_bytes: bytes) -> Literal["PEM", "DER"]: ...


def keytype(
    key_bytes: bytes,
    passphrase: str | bytes | None = None,
) -> Literal["RSA", "ML-KEM", "ML-DSA"]: ...


# oaep_extension.py
def oaep_extended_encrypt(
    config: CryptoConfig,
    rsa: RsaKey,
    plaintext: bytes,
) -> bytes: ...


def oaep_extended_decrypt(
    config: CryptoConfig,
    rsa: RsaKey,
    ciphertext: bytes,
) -> bytes: ...


# kyber.py
def genkey(
    alg: Literal["ML-KEM-768", "ML-KEM-1024"],
    encoding: MLKEMEncoding,
    passphrase: bytes | None = None,
) -> tuple[bytes, bytes]: ...


def verify_key(
    pubkey: bytes,
    privkey: bytes,
    passphrase: str | bytes | None = None,
) -> bool: ...


def kyber_encrypt(
    config: CryptoConfig,
    pubkey: bytes,
    plaintext: bytes,
    passphrase: str | bytes | None = None,
) -> bytes: ...


def kyber_decrypt(
    config: CryptoConfig,
    privkey: bytes,
    ciphertext: bytes,
    passphrase: str | bytes | None = None,
) -> bytes: ...


# dilithium.py
def genkey(
    alg: Literal["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
    encoding: MLDSAEncoding,
    passphrase: bytes | None = None,
) -> tuple[bytes, bytes]: ...


def verify_key(
    pubkey: bytes,
    privkey: bytes,
    passphrase: bytes | None = None,
) -> bool: ...


def sign(
    privkey: bytes,
    message: bytes,
    passphrase: bytes | None = None,
    context: bytes | None = None,
) -> bytes: ...


def verify(
    pubkey: bytes,
    message: bytes,
    signature: bytes,
    context: bytes | None = None,
) -> bool: ...
