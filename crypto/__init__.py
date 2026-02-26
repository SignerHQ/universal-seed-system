# Copyright (c) 2026 Signer — MIT License

"""Cryptography modules — classical, post-quantum, hybrid, and KDF.

Classical:
    Ed25519 (RFC 8032)  — digital signature, ~128-bit classical security.
    X25519  (RFC 7748)  — Diffie-Hellman key exchange, ~128-bit classical security.

Post-quantum:
    ML-DSA-65 (FIPS 204)        — lattice-based digital signature, NIST Level 3.
    SLH-DSA-SHAKE-128s (FIPS 205) — hash-based digital signature, NIST Level 1.
    ML-KEM-768 (FIPS 203)       — lattice-based key encapsulation, NIST Level 3.

Hybrid (classical + post-quantum):
    Hybrid-DSA-65  — Ed25519 + ML-DSA-65  (both must verify).
    Hybrid-KEM-768 — X25519  + ML-KEM-768 (shared secrets combined via HKDF).

KDF:
    Argon2id (RFC 9106) — memory-hard KDF. Uses argon2-cffi when available,
    falls back to pure Python implementation.
"""

# Classical primitives
from .ed25519 import (
    ed25519_keygen, ed25519_sign, ed25519_verify,
    ED25519_SEED_SIZE, ED25519_SK_SIZE, ED25519_PK_SIZE, ED25519_SIG_SIZE,
)
from .x25519 import (
    x25519_keygen, x25519,
    X25519_SK_SIZE, X25519_PK_SIZE, X25519_SS_SIZE,
)

# Post-quantum
from .ml_dsa import ml_keygen, ml_sign, ml_verify
from .slh_dsa import slh_keygen, slh_sign, slh_verify
from .ml_kem import ml_kem_keygen, ml_kem_encaps, ml_kem_decaps

# Hybrid
from .hybrid_dsa import hybrid_dsa_keygen, hybrid_dsa_sign, hybrid_dsa_verify
from .hybrid_kem import hybrid_kem_keygen, hybrid_kem_encaps, hybrid_kem_decaps

# KDF
from .argon2 import hash_secret_raw as argon2_hash, argon2id, blake2b

__all__ = [
    # Classical
    "ed25519_keygen", "ed25519_sign", "ed25519_verify",
    "ED25519_SEED_SIZE", "ED25519_SK_SIZE", "ED25519_PK_SIZE", "ED25519_SIG_SIZE",
    "x25519_keygen", "x25519",
    "X25519_SK_SIZE", "X25519_PK_SIZE", "X25519_SS_SIZE",
    # Post-quantum
    "ml_keygen", "ml_sign", "ml_verify",
    "slh_keygen", "slh_sign", "slh_verify",
    "ml_kem_keygen", "ml_kem_encaps", "ml_kem_decaps",
    # Hybrid
    "hybrid_dsa_keygen", "hybrid_dsa_sign", "hybrid_dsa_verify",
    "hybrid_kem_keygen", "hybrid_kem_encaps", "hybrid_kem_decaps",
    # KDF
    "argon2_hash", "argon2id", "blake2b",
]
