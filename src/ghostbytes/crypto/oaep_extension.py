"""
oaep_extension.py

This module extends RSA-OAEP by generating a random AES-256 key for each message.
The plaintext is encrypted with AES, while the AES key is encrypted with RSA-OAEP.

The resulting envelope contains the AES ciphertext and the RSA-encrypted AES key.
The RSA-encrypted key is stored with the AES ciphertext.
"""

from Crypto.Cipher import PKCS1_OAEP as _oaep
from ghostbytes.crypto.primitives import aes_encrypt, aes_decrypt
from ghostbytes.crypto.config import AVAIL_HASH, CryptoConfig
from ghostbytes.tools.rand import random
from ghostbytes.error import decryption_key_incorrect, envelope_too_small, \
    hash_not_supported, invalid_configuration_type, keyfile_cannot_crypt, store_iv_choice_mismatch


def oaep_extended_encrypt(config, rsa, plaintext):
    """
    Encrypt plaintext using AES and wrap the AES key with RSA-OAEP

    A random 256-bit AES key is generated using the configured random
    function. The plaintext is encrypted with AES, and the AES key is
    encrypted with RSA-OAEP. The encrypted AES key is then joined to
    the AES ciphertext.

    Args:
        config: Cryptographic configuration for the operation, includes the algorithm,
            KDF parameters, and all necessary configuration to complete the operation.
        rsa: An RSA public Key used to encrypt the AES Key
        plaintext: the data to encrypt in bytes.

    Returns:
        The combined RSA-OAEP and AES ciphertext as bytes

    Raises:
        invalid_configuration_types: if ``config`` is not ``CryptoConfig`` instance.
        hash_not_supported: if the configured hash function is unsupported.
        keyfile_cannot_crypt: If the RSA key cannot encrypt
        store_iv_choice_mismatch: if ``config.store_iv`` is invalid
    """
    if not isinstance(config, CryptoConfig):
        raise invalid_configuration_type()
    if config.hash_func not in AVAIL_HASH:
        raise hash_not_supported()

    oaep = _oaep.new(
        key=rsa,
        hashAlgo=config.hash_func
    )
    if not oaep.can_encrypt():
        raise keyfile_cannot_crypt("encrypt")

    key = random(config.rand_func, 32)  # AES-256 32 bytes key length

    ciphertext = aes_encrypt(config, key, plaintext)

    key = oaep.encrypt(key)

    if config.store_iv == 'append':
        ciphertext += key
    elif config.store_iv == 'prepend':
        ciphertext = key + ciphertext
    else:
        raise store_iv_choice_mismatch()

    return ciphertext


def oaep_extended_decrypt(config, rsa, ciphertext):
    """
    Decrypt an RSA-OAEP and AES encrypted envelop.

    The function extracts the RSA-encrypted AES key from the ciphertext. It then decrypts
    the AES key with RSA-OAEP and uses that key to decrypt the remaining AES ciphertext.

    Args:
        config: Cryptographic configuration for the operation, includes the algorithm,
            KDF parameters, and all necessary configuration to complete the operation.
        rsa: An RSA private Key used to derypt the AES Key
        ciphertext: the data to decrypt in bytes.

    Returns:
        The decrypted plaintext as bytes

    Raises:
        invalid_configuration_types: if ``config`` is not ``CryptoConfig`` instance.
        hash_not_supported: if the configured hash function is unsupported.
        keyfile_cannot_crypt: If the RSA key cannot encrypt
        envelop_too_small: if the size of the envelop is too small to contain a
            complete ML-KEM ciphertext
        decryption_key_incorrect: if RSA-OAEP decryption fails
        store_iv_choice_mismatch: if ``config.store_iv`` is invalid
    """
    if not isinstance(config, CryptoConfig):
        raise invalid_configuration_type()
    oaep = _oaep.new(
        key=rsa,
        hashAlgo=config.hash_func
    )
    if not rsa.has_private():
        raise keyfile_cannot_crypt("decrypt")

    rsa_size = rsa.size_in_bytes()
    if len(ciphertext) - rsa_size <= 0:
        raise envelope_too_small()

    if config.store_iv == 'append':
        encrypted_key = ciphertext[len(ciphertext) - rsa_size:]
        ciphertext = ciphertext[:len(ciphertext) - rsa_size]
    elif config.store_iv == 'prepend':
        encrypted_key = ciphertext[:rsa_size]
        ciphertext = ciphertext[rsa_size:]
    else:
        raise store_iv_choice_mismatch()

    try:
        decrypted_key = oaep.decrypt(encrypted_key)
    except ValueError as e:
        raise decryption_key_incorrect() from e

    plaintext = aes_decrypt(config, decrypted_key, ciphertext)

    return plaintext
