"""
dilithium.py

Implementation of ML-DSA (CRYSTALS-Dilithium, Module-Lattice-Based Digital
Signature Algorithm) according to FIPS 204.

The supported parameter sets are ML-DSA-44, ML-DSA-65, and ML-DSA-87.
"""

import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

from ghostbytes.crypto.primitives import detect_key_format
from ghostbytes.error import (
    algorithm_not_supported,
    invalid_argument,
    invalid_keyfile,
    key_encoding_not_found,
    keyfile_cannot_crypt,
    keyfile_passphrase_incorrect,
    text_not_in_bytes,
)


def genkey(alg, encoding, passphrase=None):
    """Generate and serialize an ML-DSA key pair."""
    _, dsa = _alg_to_class(alg)
    private_key = dsa.generate()
    public_key = private_key.public_key()

    private_key = private_key.private_bytes(
        encoding=_get_encoding(encoding),
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
        if passphrase else serialization.NoEncryption(),
    )
    public_key = public_key.public_bytes(
        encoding=_get_encoding(encoding),
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return public_key, private_key


def verify_key(pubkey, privkey, passphrase=None):
    """Verify that an ML-DSA public and private key belong together."""
    public_key = _import_public_key(detect_key_format(pubkey), pubkey)
    private_key = _import_private_key(
        detect_key_format(privkey), privkey, passphrase)
    message = b"ghostbytes ML-DSA key verification"
    signature = private_key.sign(message)
    return verify(public_key, message, signature)


def sign(privkey, message, passphrase=None, context=None):
    """Sign bytes with an ML-DSA private key."""
    if not isinstance(message, bytes):
        raise text_not_in_bytes()
    private_key = _import_private_key(
        detect_key_format(privkey), privkey, passphrase)
    if not hasattr(private_key, "sign"):
        raise keyfile_cannot_crypt("sign")
    try:
        return private_key.sign(message, context=context)
    except (TypeError, ValueError) as e:
        raise invalid_argument("ML-DSA signing context", "is invalid") from e


def verify(pubkey, message, signature, context=None):
    """Verify an ML-DSA signature and return whether it is valid."""
    if not isinstance(message, bytes) or not isinstance(signature, bytes):
        raise text_not_in_bytes()
    public_key = pubkey if hasattr(pubkey, "verify") else _import_public_key(
        detect_key_format(pubkey), pubkey)
    try:
        public_key.verify(signature, message, context=context)
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def _alg_to_class(alg):
    match = re.fullmatch(r"ML-DSA-(44|65|87)", alg)
    if not match:
        raise algorithm_not_supported()
    classes = {
        "44": (mldsa.MLDSA44PublicKey, mldsa.MLDSA44PrivateKey),
        "65": (mldsa.MLDSA65PublicKey, mldsa.MLDSA65PrivateKey),
        "87": (mldsa.MLDSA87PublicKey, mldsa.MLDSA87PrivateKey),
    }
    return classes[match.group(1)]


def _get_encoding(encoding):
    if encoding == "PEM":
        return serialization.Encoding.PEM
    if encoding == "DER":
        return serialization.Encoding.DER
    raise key_encoding_not_found()


def _import_private_key(keytype, privkey, passphrase=None):
    try:
        loader = (serialization.load_pem_private_key
                  if keytype == "PEM" else serialization.load_der_private_key)
        return loader(privkey, password=passphrase)
    except (ValueError, TypeError) as e:
        if passphrase is None:
            raise invalid_keyfile() from e
        raise keyfile_passphrase_incorrect() from e


def _import_public_key(keytype, pubkey):
    try:
        loader = (serialization.load_pem_public_key
                  if keytype == "PEM" else serialization.load_der_public_key)
        return loader(pubkey)
    except (ValueError, TypeError) as e:
        raise invalid_keyfile() from e
