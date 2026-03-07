import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password using PBKDF2 (SHA-256)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,  # Increased for better security
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_private_key(private_key: bytes, password: str) -> bytes:
    """Encrypt a 32-byte private key with a password.

    The returned value consists of
        salt (16 bytes) || nonce (12 bytes) || ciphertext

    This format is intentionally simple and encoded as raw bytes so that
    callers can hexlify it for storage.
    """
    if not isinstance(private_key, (bytes, bytearray)):
        raise TypeError("private_key must be bytes")

    # 128-bit salt for key derivation
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    # 96-bit nonce for AES-GCM
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, private_key, associated_data=None)

    # prefix with a version byte so we can upgrade format later
    # currently version 1; format: [1] || salt || nonce || ciphertext
    return b"\x01" + salt + nonce + ciphertext

def decrypt_private_key(encrypted: bytes, password: str) -> bytes:
    """Decrypt data produced by :func:`encrypt_private_key`.

    Raises ``cryptography.exceptions.InvalidTag`` if the password is
    incorrect or the ciphertext was tampered with.
    """
    if not isinstance(encrypted, (bytes, bytearray)):
        raise TypeError("encrypted data must be bytes")
    if len(encrypted) < 1 + 16 + 12:
        raise ValueError("encrypted data is too short")

    version = encrypted[0]
    if version == 1:
        # format introduced above
        salt = encrypted[1:17]
        nonce = encrypted[17:29]
        ciphertext = encrypted[29:]
    else:
        # fall back to old format (no version byte)
        # this branch retains backward-compatibility with existing wallets
        salt = encrypted[:16]
        nonce = encrypted[16:28]
        ciphertext = encrypted[28:]

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
