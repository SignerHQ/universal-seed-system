# Copyright (c) 2026 Signer — MIT License

"""Hybrid X25519 + ML-KEM-768 key encapsulation mechanism.

Both shared secrets are combined via HKDF with ciphertext binding.
Security holds as long as *either* X25519 or ML-KEM-768 remains unbroken.

X25519 provides classical (pre-quantum) security (~128-bit).
ML-KEM-768 provides post-quantum security (NIST Level 3, ~192-bit).

The combined shared secret is derived via HKDF-Extract + HKDF-Expand with
both shared secrets as input keying material and a ciphertext-derived salt,
preventing ciphertext substitution attacks.

Sizes:
    Encapsulation key (public): 1,216 bytes  (X25519 pk 32B + ML-KEM ek 1,184B)
    Decapsulation key (secret): 2,432 bytes  (X25519 sk 32B + ML-KEM dk 2,400B)
    Ciphertext:                 1,120 bytes  (X25519 eph_pk 32B + ML-KEM ct 1,088B)
    Shared secret:                 32 bytes

NOT constant-time. For side-channel-resistant deployments, use C/Rust.
"""

import hashlib
import hmac
import os

from .x25519 import x25519_keygen, x25519
from .ml_kem import ml_kem_keygen, ml_kem_encaps, ml_kem_decaps

# Component sizes
_X25519_SK = 32
_X25519_PK = 32
_ML_KEM_EK = 1184
_ML_KEM_DK = 2400
_ML_KEM_CT = 1088

# Hybrid sizes (exported for external validation)
HYBRID_KEM_EK_SIZE = _X25519_PK + _ML_KEM_EK    # 1,216
HYBRID_KEM_DK_SIZE = _X25519_SK + _ML_KEM_DK    # 2,432
HYBRID_KEM_CT_SIZE = _X25519_PK + _ML_KEM_CT    # 1,120


def _combine_secrets(x25519_ss, ml_kem_ss, x25519_ct, ml_kem_ct):
    """Combine X25519 and ML-KEM shared secrets via HKDF.

    Uses ciphertext-bound HKDF to produce the final 32-byte shared secret:
        salt = SHA-256(x25519_ct || ml_kem_ct)
        PRK  = HMAC-SHA256(salt, x25519_ss || ml_kem_ss)    # HKDF-Extract
        SS   = HMAC-SHA256(PRK, b"hybrid-kem-v1" || 0x01)   # HKDF-Expand

    Binding the ciphertext into the salt prevents substitution attacks.
    The domain string "hybrid-kem-v1" provides separation from other uses.
    """
    salt = hashlib.sha256(x25519_ct + ml_kem_ct).digest()
    prk = hmac.new(salt, x25519_ss + ml_kem_ss, hashlib.sha256).digest()
    return hmac.new(prk, b"hybrid-kem-v1\x01", hashlib.sha256).digest()


def hybrid_kem_keygen(seed):
    """Generate hybrid X25519 + ML-KEM-768 keypair.

    Args:
        seed: 96-byte seed material.
              First 32 bytes -> X25519 keygen.
              Last 64 bytes -> ML-KEM-768 keygen (d || z).

    Returns:
        (ek_bytes, dk_bytes) tuple.
        ek_bytes: 1,216-byte hybrid encapsulation key (public).
        dk_bytes: 2,432-byte hybrid decapsulation key (secret).
    """
    if len(seed) != 96:
        raise ValueError(f"Hybrid KEM seed must be 96 bytes, got {len(seed)}")

    x_sk, x_pk = x25519_keygen(seed[:32])
    ml_ek, ml_dk = ml_kem_keygen(seed[32:])

    ek = x_pk + ml_ek
    dk = x_sk + ml_dk
    return ek, dk


def hybrid_kem_encaps(ek, randomness=None):
    """Encapsulate: produce hybrid ciphertext and combined shared secret.

    Performs X25519 ephemeral DH and ML-KEM-768 encapsulation, then
    combines both shared secrets via ciphertext-bound HKDF.

    Args:
        ek: 1,216-byte hybrid encapsulation key.
        randomness: 64 bytes (32B for X25519 ephemeral + 32B for ML-KEM).
                    If None, generates securely.

    Returns:
        (ct, shared_secret) tuple.
        ct: 1,120-byte hybrid ciphertext.
        shared_secret: 32-byte combined shared secret.
    """
    if len(ek) != HYBRID_KEM_EK_SIZE:
        raise ValueError(
            f"Hybrid KEM ek must be {HYBRID_KEM_EK_SIZE} bytes, got {len(ek)}"
        )

    if randomness is None:
        randomness = os.urandom(64)
    elif len(randomness) != 64:
        raise ValueError(f"Randomness must be 64 bytes, got {len(randomness)}")

    x_pk = ek[:_X25519_PK]
    ml_ek = ek[_X25519_PK:]

    # X25519 ephemeral key exchange
    eph_sk, eph_pk = x25519_keygen(randomness[:32])
    x_ss = x25519(eph_sk, x_pk)

    # ML-KEM encapsulation
    ml_ct, ml_ss = ml_kem_encaps(ml_ek, randomness[32:])

    # Combine shared secrets with ciphertext binding
    ct = eph_pk + ml_ct
    ss = _combine_secrets(x_ss, ml_ss, eph_pk, ml_ct)

    return ct, ss


def hybrid_kem_decaps(dk, ct):
    """Decapsulate: recover combined shared secret from hybrid ciphertext.

    Args:
        dk: 2,432-byte hybrid decapsulation key.
        ct: 1,120-byte hybrid ciphertext.

    Returns:
        32-byte combined shared secret.
    """
    if len(dk) != HYBRID_KEM_DK_SIZE:
        raise ValueError(
            f"Hybrid KEM dk must be {HYBRID_KEM_DK_SIZE} bytes, got {len(dk)}"
        )
    if len(ct) != HYBRID_KEM_CT_SIZE:
        raise ValueError(
            f"Hybrid KEM ct must be {HYBRID_KEM_CT_SIZE} bytes, got {len(ct)}"
        )

    x_sk = dk[:_X25519_SK]
    ml_dk = dk[_X25519_SK:]
    eph_pk = ct[:_X25519_PK]
    ml_ct = ct[_X25519_PK:]

    # X25519 shared secret recovery
    x_ss = x25519(x_sk, eph_pk)

    # ML-KEM decapsulation
    ml_ss = ml_kem_decaps(ml_dk, ml_ct)

    # Combine shared secrets with ciphertext binding
    return _combine_secrets(x_ss, ml_ss, eph_pk, ml_ct)
