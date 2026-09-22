"""
primitives.py

This modules provides helpers for:

* AES-GCM encryption / decryption
* RSA-OAEP encryption / decryption
* Argon2id KDF
* RSA key generation / verification
* Key-format, key-type detection (for non-pycryptodome)

The ``ML-KEM`` implementations / functions are located in kyber.py
The ``extended_oaep`` implementations / functions are located in oaep_extension.py
"""

from Crypto.Cipher import AES as _aes
from Crypto.Cipher import PKCS1_OAEP as _oaep
from Crypto.PublicKey import RSA as _rsa
from Crypto.Signature import pss as _pss

from argon2.low_level import hash_secret_raw, Type

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem, rsa

from ghostbytes.crypto.config import RSA_KEY_OUT_FORMAT, CryptoConfig
from ghostbytes.error import aes_envelope_extraction_failed, data_integrity_check_failed, \
    decryption_key_incorrect, envelope_too_small, invalid_argument, invalid_configuration_type, \
    invalid_keyfile, keyfile_cannot_crypt, keyfile_passphrase_incorrect, rsa_message_too_big, \
    rsa_public_exponent_not_prime, store_iv_choice_mismatch, unsupported_keyfile


def aes_encrypt(config, key, plaintext):
    """
    Encrypts plaintext using AES-GCM

    Args:
        config: encryption configuration in ``CryptoConfig``
        key: AES key as bytes, must be 16, 24, or 32 bytes
        plaintext: data to encrypt as bytes

    Returns:
        AES envelop of ciphertext and authentication tag as bytes.

    Raises:
        invalid_configuration_type: when config is not a ``CryptoConfig`` instance
        invalid_argument: if ``plaintext`` or ``key`` is not bytes, or if key has an
            invalid length
        store_iv_choice_mismatch: if ``config.store_iv`` is invalid.
    """
    _require_config(config)
    if not isinstance(plaintext, bytes) or not isinstance(key, bytes):
        raise invalid_argument("AES plaintext and key", "must be bytes")
    if len(key) not in (16, 24, 32):
        raise invalid_argument("AES key", "must be 16, 24, or 32 bytes")
    encryptor = _aes.new(
        key=key,
        mode=_aes.MODE_GCM,
        mac_len=config.mac_len,
        use_aesni=True,
    )

    ciphertext, digest = encryptor.encrypt_and_digest(plaintext)

    if config.store_iv == 'append':
        ciphertext += encryptor.nonce + digest
    elif config.store_iv == 'prepend':
        ciphertext = encryptor.nonce + digest + ciphertext
    else:
        raise store_iv_choice_mismatch()

    return ciphertext


def aes_decrypt(config, key, ciphertext):
    """
    Decrypt and authenticate an AES-GCM envelop

    The function extracts the AES-GCM nonce and authenticate tag from the
    ciphertext and verifies it with the decrypted plaintext.

    Args:
        config: encryption configuration in ``CryptoConfig``
        key: AES key as bytes, must be 16, 24, or 32 bytes
        ciphertext: data to decrypt as bytes

    Returns:
        The decrypted text as plaintext

    Raises:
        invalid_configuration_type: when config is not a ``CryptoConfig`` instance
        invalid_argument: if ``plaintext`` or ``key`` is not bytes, or if key has an
            invalid length
        envelop_too_small: if the size of the envelop is too small to contain a
            complete ML-KEM ciphertext
        aes_envelope_extraction_failed: if the authentication tag cannot be
            extracted correctly.
        decrypt_key_incorrect: if decryption fails
        data_integrity_check_failed: if authentication fails
        store_iv_choice_mismatch: if ``config.store_iv`` is invalid.
    """
    _require_config(config)
    envelop_len = 16 + config.mac_len  # 16 bytes for nonce length
    if not isinstance(ciphertext, bytes) or not isinstance(key, bytes):
        raise invalid_argument("AES ciphertext and key", "must be bytes")
    if len(key) not in (16, 24, 32):
        raise invalid_argument("AES key", "must be 16, 24, or 32 bytes")
    if len(ciphertext) < envelop_len:
        raise envelope_too_small()

    if config.store_iv == 'append':
        nonce = ciphertext[len(ciphertext) -
                           envelop_len:len(ciphertext) -
                           envelop_len +
                           16]
        mac = ciphertext[len(ciphertext) - envelop_len + 16:]
        ciphertext = ciphertext[:len(ciphertext) - envelop_len]
    elif config.store_iv == 'prepend':
        nonce = ciphertext[:16]
        mac = ciphertext[16:16 + config.mac_len]
        ciphertext = ciphertext[16 + config.mac_len:]
    else:
        raise store_iv_choice_mismatch()

    if len(mac) != config.mac_len:
        raise aes_envelope_extraction_failed()

    decryptor = _aes.new(
        key=key,
        mode=_aes.MODE_GCM,
        mac_len=config.mac_len,
        use_aesni=True,
        nonce=nonce
    )

    try:
        plaintext = decryptor.decrypt(ciphertext)
    except ValueError as e:
        raise decryption_key_incorrect() from e

    try:
        decryptor.verify(mac)
    except ValueError as e:
        raise data_integrity_check_failed() from e

    return plaintext


def rsa_oaep_encrypt(config, key, plaintext):
    """
    Encrypt a message using RSA-OAEP.

    Args:
        config: encryption configuration in ``CryptoConfig``
        key: RSA public key.
        plaintext: data to encrypt as bytes

    Returns:
        The RSA-OAEP ciphertext as bytes

    Raises:
        invalid_configuration_types: if ``config`` is invalid
        keyfile_cannot_crypt: if ``key`` cannot encrypt
        rsa_message_too_big: if the plaintext is too large for RSA-OAEP
    """
    _require_config(config)
    if not key.can_encrypt():
        raise keyfile_cannot_crypt("encrypt")

    oaep = _oaep.new(
        key,
        config.hash_func
    )

    try:
        return oaep.encrypt(plaintext)
    except ValueError as e:
        raise rsa_message_too_big() from e


def rsa_oaep_decrypt(config, key, ciphertext):
    """
    Decrypt a message using RSA-OAEP

    Args:
        config: encryption configuration in ``CryptoConfig``
        ciphertext: data to decrypt as bytes
        key: RSA private key.

    Returns:
        The decrypted plaintext as bytes

    Raises:
        invalid_configuration_types: if ``config`` is invalid
        keyfile_cannot_crypt: if ``key`` cannot decrypt (``key`` is not private key)
        decryption_key_incorrect: if RSA-OAEP decryption fails
    """
    _require_config(config)
    if not key.has_private():
        raise keyfile_cannot_crypt("decrypt")

    oaep = _oaep.new(
        key,
        config.hash_func
    )

    try:
        return oaep.decrypt(ciphertext)
    except ValueError as e:
        raise decryption_key_incorrect() from e


def rsa_sign(config, key, message):
    """Sign a message with RSA-PSS using the configured hash function."""
    _require_config(config)
    if not isinstance(message, bytes):
        raise invalid_argument("RSA message", "must be bytes")
    if not key.has_private():
        raise keyfile_cannot_crypt("sign")
    try:
        return _pss.new(key).sign(config.hash_func.new(message))
    except (ValueError, TypeError) as e:
        raise invalid_argument("RSA signing key", "is invalid") from e


def rsa_verify(config, key, message, signature):
    """Verify an RSA-PSS signature and return whether it is valid."""
    _require_config(config)
    if not isinstance(message, bytes) or not isinstance(signature, bytes):
        raise invalid_argument("RSA message and signature", "must be bytes")
    try:
        _pss.new(key).verify(config.hash_func.new(message), signature)
    except (ValueError, TypeError):
        return False
    return True


def derive_key(config, secret):
    """
    Derive a 256-bit key from a secret using Argon2id memory-hard
    key derivation function (KDF)

    Args:
        config: key derivation configuration in ``CryptoConfig``
        secret: Non-empty secret material as bytes

    Returns:
        A 32-bytes derived key.

    Raises:
        invalid_configuration_type: if ``config`` is invalid
        invalid_argument: if ``key`` is not non-empty bytes
    """
    _require_config(config)
    if not isinstance(secret, bytes) or not secret:
        raise invalid_argument("KDF secret", "must be non-empty bytes")
    return hash_secret_raw(
        secret=secret,
        salt=config.kdf_salt,
        time_cost=config.kdf_time_cost,
        memory_cost=config.kdf_memory_cost,
        parallelism=config.kdf_parallelism,
        hash_len=32,
        type=Type.ID
    )


def genrsa(length, exp, passphrase, out_format=RSA_KEY_OUT_FORMAT[0]):
    """
    Generate and serialize an RSA key pair.

    Args:
        key_size: RSA modulus size in bits. Must be at least 1024
        exponent: RSA public exponent. Must be an odd prime greater than 2
        passphrase: Passphrase used to encrypt the private key
        out_format: Output format supported by PyCryptodome, such as ``"PEM"``

    Returns:
        A tuple ``(public_key, private_key)``.
        Each key is encoded into bytes.

    Raises:
        invalid_argument: if a parameter is invalid (rsa key size < 1024 bits? RSA exponent
            too small? RSA key encoding not supported?)
        rsa_public_exponent_not_prime: if ``exponent`` is not prime.
    """
    if not isinstance(length, int) or length < 1024:
        raise invalid_argument("RSA key size",
                               "must be an integer of at least 1024 bits")
    if not isinstance(exp, int) or exp < 3:
        raise invalid_argument(
            "RSA public exponent",
            "must be an integer greater than 2")
    if out_format not in RSA_KEY_OUT_FORMAT:
        raise invalid_argument("RSA key encoding", "is not supported")
    for i in range(2, int(exp**0.5) + 1):
        if exp % i == 0:
            raise rsa_public_exponent_not_prime()

    key = _rsa.generate(length, None, exp)
    public = key.public_key()

    public_key = public.export_key(out_format)
    private_key = key.export_key(out_format, passphrase)

    return public_key, private_key


def verify_rsa(public_key, private_key, passphrase):
    """
    Verifies that an RSA public key matches a private key

    Args:
        public_key: Serialised RSA public key
        private_key: Serialised RSA private key
        passphrase: passphrase for the private key

    Returns:
        ``True`` if the keys contain the same RSA modulus; otherwise ``False``

    Raises:
        keyfile_passphrase_incorrect: if the passphrase is invalid
        invalid_keyfile: if either key cannot be imported.
    """
    try:
        priv = _rsa.import_key(private_key, passphrase)
    except (ValueError, TypeError, IndexError) as e:
        if passphrase is not None:
            raise keyfile_passphrase_incorrect() from e
        raise invalid_keyfile() from e
    if not priv.has_private():
        return False
    try:
        pub = _rsa.import_key(public_key, passphrase)
    except (ValueError, TypeError, IndexError) as e:
        if passphrase is not None:
            raise keyfile_passphrase_incorrect() from e
        raise invalid_keyfile() from e
    return priv.n == pub.n


def detect_key_format(key_bytes: bytes) -> str:
    """Detect if the serialised key data is PEM or DER encoded through inspecting the headers"""
    if key_bytes.startswith(b"-----BEGIN"):
        return "PEM"

    if key_bytes[0] == 0x30:
        if len(key_bytes) > 1 and (key_bytes[1] & 0x80 or key_bytes[1] < 128):
            return "DER"

    raise invalid_keyfile()


def keytype(key_bytes, passphrase=None):
    """Determine whether serialised key data contains an RSA or ML-KEM key"""
    try:
        if detect_key_format(key_bytes) == "PEM":
            if b"PRIVATE KEY" in key_bytes:
                key_obj = serialization.load_pem_private_key(
                    key_bytes, password=passphrase)
            else:
                key_obj = serialization.load_pem_public_key(key_bytes)
        else:
            try:
                key_obj = serialization.load_der_private_key(
                    key_bytes, password=passphrase)
            except Exception:
                key_obj = serialization.load_der_public_key(key_bytes)
    except Exception as e:
        raise invalid_keyfile() from e

    if isinstance(key_obj, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return "RSA"
    if isinstance(
        key_obj,
        (mlkem.MLKEM768PrivateKey,
         mlkem.MLKEM768PublicKey,
         mlkem.MLKEM1024PrivateKey,
         mlkem.MLKEM1024PublicKey)):
        return "ML-KEM"
    if isinstance(
        key_obj,
        (mldsa.MLDSA44PrivateKey,
         mldsa.MLDSA44PublicKey,
         mldsa.MLDSA65PrivateKey,
         mldsa.MLDSA65PublicKey,
         mldsa.MLDSA87PrivateKey,
         mldsa.MLDSA87PublicKey)):
        return "ML-DSA"
    raise unsupported_keyfile()


def _require_config(config):
    if not isinstance(config, CryptoConfig):
        raise invalid_configuration_type()
