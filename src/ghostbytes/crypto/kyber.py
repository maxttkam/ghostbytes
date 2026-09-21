"""
kyber.py

Implementation of ML-KEM (CRYSTALS-Kyber, Module-Lattice-Based Key-Encapsulation Mechanism Standard)
according to FIPS 203. ML-KEM is one of the 7 finalists selected in the third round of the NIST
Post-Quantum Cryptography (PQC) standardisation process.

2 of 3 Standard Parameter sets are implemented here, ML-KEM-768 and ML-KEM-1024.
ML-KEM-768 is classified in NIST Security Category 3 (AES-192 Equivalent)
ML-KEM-1024 is classified in NIST Security Category 5 (AES-256 Equivalent)

More about ML-KEM here: https://en.wikipedia.org/wiki/ML-KEM

This module uses ML-KEM to derive a symmetric key,
which is then used for AES encryption of the plaintext.
"""

import re
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mlkem
from ghostbytes.crypto.primitives import detect_key_format
from ghostbytes.error import CryptoError, \
    algorithm_not_supported, envelope_too_small, invalid_keyfile, key_encoding_not_found, \
    invalid_configuration_type, keyfile_passphrase_incorrect, store_iv_choice_mismatch, \
    text_not_in_bytes, keyfile_cannot_crypt
from ghostbytes.crypto.config import CryptoConfig
from ghostbytes.crypto.primitives import aes_decrypt, aes_encrypt, derive_key


def genkey(alg, encoding, passphrase=None):
    """
    Generate and serialise an ML-KEM key pair

    Args:
        alg: ML-KEM algorithm name. Supported values are ``"ML-KEM-768"`` and ``"ML-KEM-1024"``
        encoding: Key encoding. Supported values are ``"PEM"`` and ``"DER"``
        passphrase: Optional passphrase used to encrypt the serialised private key

    Return:
        A tuple containing ``(publickey, privatekey)`` as serialised bytes

    Raises:
        algorithm_not_supported: if ``alg`` is not supported
        key_encoding_not_found: if ``encoding`` is not supported
    """
    _, kem = _alg_to_class(alg)
    privkey = kem.generate()
    pubkey = privkey.public_key()

    privkey = privkey.private_bytes(
        encoding=_get_encoding(encoding),
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
        if passphrase else serialization.NoEncryption()
    )
    pubkey = pubkey.public_bytes(
        encoding=_get_encoding(encoding),
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return (pubkey, privkey)


def verify_key(pubkey, privkey, passphrase=None):
    """
    Verify that a public and private ML-KEM key belong together

    The function encapsulates a shared secret with the public key and
    decapsulates it with the private key. The two resulting secrets
    are then compared.

    Args:
        pubkey: Serialised ML-KEM public key.
        privkey: Serialised ML-KEM private key.
        passphrase: Optional passphrase for decrypting the private key.

    Returns:
        ``True`` if both keys produce the same shared secret, otherwise ``False``

    Raises:
        invalid_keyfile: if either key is invalid.
        keyfile_passphrase_incorrect: if the privatekey passphrase is incorrect.
    """
    pubkeytype = detect_key_format(pubkey)
    privkeytype = detect_key_format(privkey)
    pubkey = _import_public_key(pubkeytype, pubkey)
    privkey = _import_private_key(privkeytype, privkey, passphrase)

    shared_secret_sender, ciphertext = pubkey.encapsulate()
    shared_secret_receiver = privkey.decapsulate(ciphertext)

    return secrets.compare_digest(shared_secret_sender, shared_secret_receiver)


def kyber_encrypt(config, pubkey, plaintext, passphrase=None):
    """
    Encrypt plaintext using ML-KEM key encapsulation and AES.

    The function encapsulates a share secret using the public key,
    derives a symmetric key from that secret, and encrypts the
    plaintext with AES. The ML-KEM ciphertext is stored with the
    ciphertext and returns as bytes.

    Args:
        config: encryption configuration passed to ``derive_key``
            (KDF parameters)
        pubkey: serialised ML-KEM public key
        plaintext: Data to encrypt. Must be a ``bytes`` object
        passphrase: optional passphrase for decrypting ``pubkey``
            when it is a private key

    Returns:
        The combined ML-KEM and AES ciphertext as bytes

    Raises:
        invalid_configuration_type: when config is not a ``CryptoConfig`` instance
        text_not_in_bytes: if ``plaintext`` is not bytes
        store_iv_choice_mismatch: if ``config.store_iv`` is invalid
        invalid_keyfile: if the supplied key is invalid
    """
    if not isinstance(config, CryptoConfig):
        raise invalid_configuration_type()
    if not isinstance(plaintext, bytes):
        raise text_not_in_bytes()
    keytype = detect_key_format(pubkey)
    try:
        pubkeyclass = _import_public_key(keytype, pubkey)
    except CryptoError:
        pubkeyclass = _import_private_key(
            keytype, pubkey, passphrase).public_key()
    shared_secret, kemciphertext = pubkeyclass.encapsulate()
    masterkey = derive_key(config, shared_secret)

    ciphertext = aes_encrypt(config, masterkey, plaintext)

    if config.store_iv == "append":
        ciphertext += kemciphertext
    elif config.store_iv == "prepend":
        ciphertext = kemciphertext + ciphertext
    else:
        raise store_iv_choice_mismatch()

    return ciphertext


def kyber_decrypt(config, privkey, ciphertext, passphrase=None):
    """
    Decrypt ciphertext using ML-KEM key decapsulation and AES.

    The function extracts the ML-KEM ciphertext from the envelop,
    decapsulate it with the private key, derives the symmetric AES
    key, and decrypts the remaining ciphertext.

    Args:
        config: encryption configuration passed to ``derive_key``
            (KDF parameters)
        privkey: serialised ML-KEM private key
        plaintext: Data to encrypt. Must be a ``bytes`` object
        passphrase: optional passphrase for decrypting ``privkey``

    Returns:
        The decrypted plaintext as bytes

    Raises:
        invalid_configuration_type: when config is not a ``CryptoConfig`` instance
        text_not_in_bytes: if ``plaintext`` is not bytes
        envelop_too_small: if the size of the envelop is too small
            to contain a complete ML-KEM ciphertext
        keyfile_cannot_crypt: If a public key is supplied instead
            of a private key
        store_iv_choice_mismatch: if ``config.store_iv`` is invalid
        invalid_keyfile: if the supplied key is invalid
    """
    if not isinstance(config, CryptoConfig):
        raise invalid_configuration_type()
    if not isinstance(ciphertext, bytes):
        raise text_not_in_bytes()
    keytype = detect_key_format(privkey)
    kem = _import_private_key(keytype, privkey, passphrase)
    if isinstance(kem, mlkem.MLKEM768PrivateKey):
        kem_len = 1088
    elif isinstance(kem, mlkem.MLKEM1024PrivateKey):
        kem_len = 1568
    elif isinstance(kem, (mlkem.MLKEM1024PublicKey, mlkem.MLKEM768PublicKey)):
        raise keyfile_cannot_crypt("decrypt")
    else:
        raise invalid_keyfile()
    if len(ciphertext) < kem_len:
        raise envelope_too_small()
    if config.store_iv == "append":
        kem_ciphertext = ciphertext[-kem_len:]
        ciphertext = ciphertext[:-kem_len]
    elif config.store_iv == "prepend":
        kem_ciphertext = ciphertext[:kem_len]
        ciphertext = ciphertext[kem_len:]
    else:
        raise store_iv_choice_mismatch()

    shared_secret = kem.decapsulate(kem_ciphertext)

    masterkey = derive_key(config, shared_secret)

    plaintext = aes_decrypt(config, masterkey, ciphertext)

    return plaintext


def _alg_to_class(alg):
    match = re.search(r"^ML-KEM-(768|1024)$", alg)
    if match:
        if match.group(1) == "768":
            return (mlkem.MLKEM768PublicKey, mlkem.MLKEM768PrivateKey)
        return (mlkem.MLKEM1024PublicKey, mlkem.MLKEM1024PrivateKey)
    raise algorithm_not_supported()


def _get_encoding(encoding):
    match encoding:
        case "PEM":
            return serialization.Encoding.PEM
        case "DER":
            return serialization.Encoding.DER
    raise key_encoding_not_found()


def _import_private_key(keytype, privkey, passphrase=None):
    if isinstance(passphrase, str):
        passphrase = passphrase.encode('utf-8')
    try:
        match keytype:
            case "PEM":
                return serialization.load_pem_private_key(
                    privkey, password=passphrase)
            case "DER":
                return serialization.load_der_private_key(
                    privkey, password=passphrase)
            case _:
                raise key_encoding_not_found()
    except (ValueError, TypeError) as e:
        if passphrase is None:
            raise invalid_keyfile() from e
        raise keyfile_passphrase_incorrect() from e


def _import_public_key(keytype, pubkey):
    try:
        match keytype:
            case "PEM":
                return serialization.load_pem_public_key(pubkey)
            case "DER":
                return serialization.load_der_public_key(pubkey)
            case _:
                raise key_encoding_not_found()
    except (ValueError, TypeError) as e:
        raise invalid_keyfile() from e
