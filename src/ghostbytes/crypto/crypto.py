"""
crypto.py

This is the main module provides a unified interface for encryption and decryption
using symmetric, asymmetric, and post-quantum cryptographic algorithms.

Supported algorithms are defined in `./config.py`
"""


import re
from Crypto.PublicKey import RSA as _rsa
from ghostbytes.crypto.kyber import kyber_decrypt, kyber_encrypt
from ghostbytes.crypto.oaep_extension import oaep_extended_decrypt, oaep_extended_encrypt
from ghostbytes.crypto.config import CryptoConfig
from ghostbytes.error import algorithm_not_supported, parameter_not_exist, \
    keyfile_cannot_crypt, keyfile_passphrase_incorrect, invalid_keyfile, \
    invalid_configuration_type
from ghostbytes.crypto.primitives import derive_key, \
    aes_decrypt, aes_encrypt, rsa_oaep_decrypt, rsa_oaep_encrypt


def encrypt(
    config,
    key,
    plaintext,
    rsa_passphrase=None
):
    """
    Encrypts plaintext using the specified algorithm in `CryptoConfig`

    Args:
        config: Cryptographic configuration for the operation, includes the algorithm,
            KDF parameters, and all necessary configuration to complete the operation.
        key: Encryption key or key material. The expected format depends on the algorithm.
            For symmetric encryption, key is typically a password or other secret key material.
        plaintext:  ata to encrypt. Must be provided as bytes.
        rsa_passphrase: Optional passphrase used to decrypt a password-protected RSA keyfile
                        Must be provided as bytes.

    Returns:
        bytes: The encrypted ciphertext

    Raises:
        TypeError: If config args is not an instance of CryptoConfig.
        CryptoError: Cryptographic errors likely raised due to invalid keys, malformed
            ciphertext, invalid cryptographic parameters, or failures during
            the underlying encryption/decryption operation.
        GeneralError: Incorrect Usage of the function that are not cryptography-related.
    """
    _must_be_valid("config", config)
    _must_be_valid("key", key)
    _must_be_valid("plaintext", plaintext)

    if not isinstance(config, CryptoConfig):
        raise invalid_configuration_type()

    algorithm = config.algorithm
    if algorithm == "aes":
        raw_key = derive_key(config, key)
        return aes_encrypt(config, raw_key, plaintext)

    if algorithm == "extended_oaep":
        try:
            rsa_key = _rsa.import_key(key, rsa_passphrase)
        except (ValueError, TypeError, IndexError) as e:
            if rsa_passphrase is not None:
                raise keyfile_passphrase_incorrect() from e
            raise invalid_keyfile() from e
        if not rsa_key.can_encrypt():
            raise keyfile_cannot_crypt("encrypt")

        return oaep_extended_encrypt(config, rsa_key, plaintext)

    if algorithm == "rsa-oaep":
        try:
            rsa_key = _rsa.import_key(key, rsa_passphrase)
        except (ValueError, TypeError, IndexError) as e:
            if rsa_passphrase is not None:
                raise keyfile_passphrase_incorrect() from e
            raise invalid_keyfile() from e
        if not rsa_key.can_encrypt():
            raise keyfile_cannot_crypt("encrypt")

        return rsa_oaep_encrypt(config, rsa_key, plaintext)
    if re.search(r"^ML-KEM-(768|1024)$", algorithm):
        return kyber_encrypt(config, key, plaintext, rsa_passphrase)
    raise algorithm_not_supported()


def decrypt(
    config,
    key,
    ciphertext,
    rsa_passphrase=None
):
    """
    Decrypts ciphertext using the specified algorithm in `CryptoConfig`

    Args:
        config: Cryptographic configuration for the operation, includes the algorithm,
            KDF parameters, and all necessary configuration to complete the operation.
        key: Encryption key or key material. The expected format depends on the algorithm.
            For symmetric encryption, key is typically a password or other secret key material.
        ciphertext: Encrypted data to decrypt. Must be provided as bytes.
        rsa_passphrase: Optional passphrase used to decrypt a password-protected RSA keyfile
                        Must be provided as bytes.

    Returns:
        bytes: The encrypted ciphertext

    Raises:
        TypeError: If config args is not an instance of CryptoConfig.
        CryptoError: Cryptographic errors likely raised due to invalid keys, malformed
            ciphertext, invalid cryptographic parameters, or failures during
            the underlying encryption/decryption operation.
        GeneralError: Incorrect Usage of the function that are not cryptography-related.
    """

    if not isinstance(config, CryptoConfig):
        raise invalid_configuration_type()

    _must_be_valid("config", config)
    _must_be_valid("key", key)
    _must_be_valid("ciphertext", ciphertext)

    algorithm = config.algorithm
    if algorithm == "aes":
        raw_key = derive_key(config, key)
        return aes_decrypt(config, raw_key, ciphertext)

    if algorithm == "extended_oaep":
        try:
            rsa_key = _rsa.import_key(key, rsa_passphrase)
        except (ValueError, TypeError, IndexError) as e:
            if rsa_passphrase is not None:
                raise keyfile_passphrase_incorrect() from e
            raise invalid_keyfile() from e
        if not rsa_key.has_private():
            raise keyfile_cannot_crypt("decrypt")

        return oaep_extended_decrypt(config, rsa_key, ciphertext)

    if algorithm == "rsa-oaep":
        try:
            rsa_key = _rsa.import_key(key, rsa_passphrase)
        except (ValueError, TypeError, IndexError) as e:
            if rsa_passphrase is not None:
                raise keyfile_passphrase_incorrect() from e
            raise invalid_keyfile() from e
        if not rsa_key.has_private():
            raise keyfile_cannot_crypt("decrypt")

        return rsa_oaep_decrypt(config, rsa_key, ciphertext)
    if re.search(r"^ML-KEM-(768|1024)$", algorithm):
        return kyber_decrypt(config, key, ciphertext, rsa_passphrase)
    raise algorithm_not_supported()


def _must_be_valid(name, param):
    if param is None:
        raise parameter_not_exist(name)
