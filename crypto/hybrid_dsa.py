# Copyright (c) 2026 Signer — MIT License

"""Hybrid Ed25519 + ML-DSA-65 digital signature scheme.

AND-composition: both algorithms must independently verify for the hybrid
signature to be valid. Security holds as long as *either* Ed25519 or
ML-DSA-65 remains unbroken.

Ed25519 provides classical (pre-quantum) security (~128-bit).
ML-DSA-65 provides post-quantum security (NIST Level 3, ~192-bit).

Stripping resistance: the Ed25519 component signs a domain-prefixed message
(b"hybrid-dsa-v1" + len(ctx) + ctx + message), preventing extraction of
the Ed25519 signature for standalone use outside the hybrid context.

Sizes:
    Secret key:  4,096 bytes  (Ed25519 sk 64B + ML-DSA-65 sk 4,032B)
    Public key:  1,984 bytes  (Ed25519 pk 32B + ML-DSA-65 pk 1,952B)
    Signature:   3,373 bytes  (Ed25519 sig 64B + ML-DSA-65 sig 3,309B)

NOT constant-time. For side-channel-resistant deployments, use C/Rust.
"""

from .ed25519 import ed25519_keygen, ed25519_sign, ed25519_verify
from .ml_dsa import ml_keygen, ml_sign, ml_verify

# Component sizes
_ED25519_SK = 64
_ED25519_PK = 32
_ED25519_SIG = 64
_ML_DSA_SK = 4032
_ML_DSA_PK = 1952
_ML_DSA_SIG = 3309

# Hybrid sizes (exported for external validation)
HYBRID_DSA_SK_SIZE = _ED25519_SK + _ML_DSA_SK    # 4,096
HYBRID_DSA_PK_SIZE = _ED25519_PK + _ML_DSA_PK    # 1,984
HYBRID_DSA_SIG_SIZE = _ED25519_SIG + _ML_DSA_SIG  # 3,373

# Domain prefix to prevent signature stripping attacks
_DOMAIN = b"hybrid-dsa-v1"


def _ed25519_message(message, ctx):
    """Build domain-bound message for the Ed25519 component.

    Format: b"hybrid-dsa-v1" + len(ctx) [1 byte] + ctx + message

    This ensures the Ed25519 signature cannot be stripped from the hybrid
    and presented as a valid standalone Ed25519 signature.
    """
    if len(ctx) > 255:
        raise ValueError(f"Context string must be 0-255 bytes, got {len(ctx)}")
    return _DOMAIN + len(ctx).to_bytes(1, 'big') + ctx + message


def hybrid_dsa_keygen(seed):
    """Generate hybrid Ed25519 + ML-DSA-65 keypair.

    Args:
        seed: 64-byte seed material.
              First 32 bytes -> Ed25519 keygen.
              Last 32 bytes -> ML-DSA-65 keygen.

    Returns:
        (sk_bytes, pk_bytes) tuple.
        sk_bytes: 4,096-byte hybrid secret key.
        pk_bytes: 1,984-byte hybrid public key.
    """
    if len(seed) != 64:
        raise ValueError(f"Hybrid DSA seed must be 64 bytes, got {len(seed)}")

    ed_sk, ed_pk = ed25519_keygen(seed[:32])
    ml_sk, ml_pk = ml_keygen(seed[32:])

    return ed_sk + ml_sk, ed_pk + ml_pk


def hybrid_dsa_sign(message, sk_bytes, ctx=b""):
    """Sign with both Ed25519 and ML-DSA-65.

    Both algorithms sign the message (Ed25519 with domain prefix for
    stripping resistance, ML-DSA with native context parameter).

    Args:
        message: Arbitrary-length message bytes.
        sk_bytes: 4,096-byte hybrid secret key.
        ctx: Context bytes for ML-DSA-65 (0-255 bytes, default empty).
             Also bound into the Ed25519 signing message.

    Returns:
        3,373-byte hybrid signature.
    """
    if len(sk_bytes) != HYBRID_DSA_SK_SIZE:
        raise ValueError(
            f"Hybrid DSA sk must be {HYBRID_DSA_SK_SIZE} bytes, got {len(sk_bytes)}"
        )

    ed_sk = sk_bytes[:_ED25519_SK]
    ml_sk = sk_bytes[_ED25519_SK:]

    # Ed25519 signs domain-prefixed message (stripping resistance)
    ed_sig = ed25519_sign(_ed25519_message(message, ctx), ed_sk)

    # ML-DSA signs raw message with its native context parameter.
    # Note: ML-DSA's FIPS 204 "pure" API already prepends 0x00 || len(ctx) ||
    # ctx to the message internally, providing its own domain separation.
    # We intentionally do NOT add a second "hybrid-dsa-v1" prefix here because
    # that would deviate from the FIPS 204 specification's message format.
    # The Ed25519 side carries the hybrid domain prefix to prevent stripping.
    ml_sig = ml_sign(message, ml_sk, ctx=ctx)

    return ed_sig + ml_sig


def hybrid_dsa_verify(message, sig_bytes, pk_bytes, ctx=b""):
    """Verify hybrid Ed25519 + ML-DSA-65 signature.

    BOTH component signatures must independently verify. If either
    fails, the hybrid signature is rejected.

    Args:
        message: Arbitrary-length message bytes.
        sig_bytes: 3,373-byte hybrid signature.
        pk_bytes: 1,984-byte hybrid public key.
        ctx: Context bytes (must match what was used during signing).

    Returns:
        True only if both Ed25519 AND ML-DSA-65 verify.
    """
    if len(sig_bytes) != HYBRID_DSA_SIG_SIZE:
        return False
    if len(pk_bytes) != HYBRID_DSA_PK_SIZE:
        return False

    ed_sig = sig_bytes[:_ED25519_SIG]
    ml_sig = sig_bytes[_ED25519_SIG:]
    ed_pk = pk_bytes[:_ED25519_PK]
    ml_pk = pk_bytes[_ED25519_PK:]

    # Both must verify
    if not ed25519_verify(_ed25519_message(message, ctx), ed_sig, ed_pk):
        return False
    if not ml_verify(message, ml_sig, ml_pk, ctx=ctx):
        return False

    return True
