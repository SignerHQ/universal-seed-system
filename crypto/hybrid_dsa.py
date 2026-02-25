# Copyright (c) 2026 Signer — MIT License

"""Hybrid Ed25519 + ML-DSA-65 digital signature scheme.

AND-composition: both algorithms must independently verify for the hybrid
signature to be valid. Security holds as long as *either* Ed25519 or
ML-DSA-65 remains unbroken.

Ed25519 provides classical (pre-quantum) security (~128-bit).
ML-DSA-65 provides post-quantum security (NIST Level 3, ~192-bit).

Stripping resistance: BOTH component signatures are domain-separated so
neither can be extracted and used as a valid standalone signature:
    - Ed25519 signs: b"hybrid-dsa-v1" || len(ctx) || ctx || message
    - ML-DSA uses ctx: b"hybrid-dsa-v1" || 0x00 || ctx (within FIPS 204
      pure-mode formatting, which prepends 0x00 || len(ctx) internally)

This means ML-DSA signatures produced by the hybrid scheme are NOT valid
standalone ML-DSA-65 signatures on the same (ctx, message) pair.

Context strings are limited to 241 bytes (255 minus 14 bytes of domain
separation overhead for the ML-DSA component).

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
    return _DOMAIN + len(ctx).to_bytes(1, 'big') + ctx + message


def _ml_dsa_ctx(ctx):
    """Build domain-separated context for the ML-DSA component.

    Format: b"hybrid-dsa-v1" + 0x00 + ctx

    This ensures the ML-DSA signature cannot be stripped from the hybrid and
    presented as a valid standalone ML-DSA-65 signature. The 0x00 separator
    prevents ambiguity between prefix and caller-supplied context bytes.

    Combined with FIPS 204's internal formatting (0x00 || len(ctx) || ctx ||
    message), this preserves standard ML-DSA message structure while making
    the signature non-portable outside the hybrid context.
    """
    return _DOMAIN + b"\x00" + ctx


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

    Both algorithms sign the message with domain-separated contexts for
    stripping resistance: neither component signature is usable standalone.

    Args:
        message: Arbitrary-length message bytes.
        sk_bytes: 4,096-byte hybrid secret key.
        ctx: Context bytes (0-241 bytes, default empty).
             Bound into both Ed25519 and ML-DSA signing contexts.

    Returns:
        3,373-byte hybrid signature.
    """
    if len(sk_bytes) != HYBRID_DSA_SK_SIZE:
        raise ValueError(
            f"Hybrid DSA sk must be {HYBRID_DSA_SK_SIZE} bytes, got {len(sk_bytes)}"
        )

    ml_ctx = _ml_dsa_ctx(ctx)
    if len(ml_ctx) > 255:
        raise ValueError(
            f"Context string must be 0-241 bytes for hybrid DSA, got {len(ctx)}"
        )

    ed_sk = sk_bytes[:_ED25519_SK]
    ml_sk = sk_bytes[_ED25519_SK:]

    # Ed25519 signs domain-prefixed message (stripping resistance)
    ed_sig = ed25519_sign(_ed25519_message(message, ctx), ed_sk)

    # ML-DSA signs raw message with domain-separated context (stripping
    # resistance). The hybrid domain prefix in ml_ctx ensures this signature
    # cannot be presented as a valid standalone ML-DSA-65 signature.
    ml_sig = ml_sign(message, ml_sk, ctx=ml_ctx)

    return ed_sig + ml_sig


def hybrid_dsa_verify(message, sig_bytes, pk_bytes, ctx=b""):
    """Verify hybrid Ed25519 + ML-DSA-65 signature.

    BOTH component signatures must independently verify. If either
    fails, the hybrid signature is rejected.

    Args:
        message: Arbitrary-length message bytes.
        sig_bytes: 3,373-byte hybrid signature.
        pk_bytes: 1,984-byte hybrid public key.
        ctx: Context bytes (0-241 bytes, must match what was used during signing).

    Returns:
        True only if both Ed25519 AND ML-DSA-65 verify.
    """
    if len(sig_bytes) != HYBRID_DSA_SIG_SIZE:
        return False
    if len(pk_bytes) != HYBRID_DSA_PK_SIZE:
        return False

    ml_ctx = _ml_dsa_ctx(ctx)
    if len(ml_ctx) > 255:
        return False

    ed_sig = sig_bytes[:_ED25519_SIG]
    ml_sig = sig_bytes[_ED25519_SIG:]
    ed_pk = pk_bytes[:_ED25519_PK]
    ml_pk = pk_bytes[_ED25519_PK:]

    # Both must verify (with domain-separated contexts)
    if not ed25519_verify(_ed25519_message(message, ctx), ed_sig, ed_pk):
        return False
    if not ml_verify(message, ml_sig, ml_pk, ctx=ml_ctx):
        return False

    return True
