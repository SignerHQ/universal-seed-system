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

Best-effort constant-time: X25519 uses branchless conditional swaps,
ML-KEM uses constant-time Barrett reduction and branchless selection.
The X25519 fallback for low-order points uses constant-time byte
selection instead of exception-based branching.
"""

import hashlib
import hmac
import os

from .x25519 import x25519_keygen, x25519, x25519_pk_from_sk, _x25519_raw_bytes
from .ml_kem import ml_kem_keygen, ml_kem_encaps, ml_kem_decaps

# ── Secure memory utilities (libsodium-backed) ────────────────
_HAS_SODIUM = False
try:
    from nacl._sodium import ffi as _ffi, lib as _lib
    _HAS_SODIUM = True
except ImportError:
    pass


def _secure_zero(buf):
    """Securely wipe a mutable buffer (bytearray / memoryview)."""
    if not isinstance(buf, (bytearray, memoryview)):
        return
    n = len(buf)
    if n == 0:
        return
    if _HAS_SODIUM:
        _lib.sodium_memzero(_ffi.from_buffer(buf), n)
    else:
        for i in range(n):
            buf[i] = 0


def _mlock(buf):
    """Lock memory pages to prevent swapping to disk."""
    if _HAS_SODIUM and isinstance(buf, (bytearray, memoryview)) and len(buf):
        _lib.sodium_mlock(_ffi.from_buffer(buf), len(buf))


def _munlock(buf):
    """Unlock memory pages (also zeros the region)."""
    if _HAS_SODIUM and isinstance(buf, (bytearray, memoryview)) and len(buf):
        _lib.sodium_munlock(_ffi.from_buffer(buf), len(buf))

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


def _combine_secrets(x25519_ss, ml_kem_ss, x25519_ct, ml_kem_ct,
                     x25519_pk, ml_kem_ek):
    """Combine X25519 and ML-KEM shared secrets via HKDF.

    Uses ciphertext-bound and public-key-bound HKDF to produce the final
    32-byte shared secret:
        salt = SHA-256(x25519_ct || ml_kem_ct)
        PRK  = HMAC-SHA256(salt, x25519_ss || ml_kem_ss)    # HKDF-Extract
        info = b"hybrid-kem-v1" || SHA-256(x25519_pk || ml_kem_ek) || 0x01
        SS   = HMAC-SHA256(PRK, info)                        # HKDF-Expand

    Binding:
      - Ciphertext into the salt prevents substitution attacks.
      - Receiver public keys into the info prevents cross-context reuse: if the
        same ciphertext is decapsulated against a different recipient's key, the
        derived shared secret changes.  Cheap and makes audits easier.
    The domain string "hybrid-kem-v1" provides separation from other protocols.
    """
    salt = hashlib.sha256(x25519_ct + ml_kem_ct).digest()
    prk = hmac.new(salt, x25519_ss + ml_kem_ss, hashlib.sha256).digest()
    pk_hash = hashlib.sha256(x25519_pk + ml_kem_ek).digest()
    info = b"hybrid-kem-v1" + pk_hash + b"\x01"
    return hmac.new(prk, info, hashlib.sha256).digest()


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

    Memory hardening: intermediate component shared secrets are securely
    wiped after HKDF combination.

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
    eph_sk_buf = bytearray(randomness[:32])
    _mlock(eph_sk_buf)
    try:
        eph_sk, eph_pk = x25519_keygen(bytes(eph_sk_buf))
        x_ss_buf = bytearray(x25519(eph_sk, x_pk))
        _mlock(x_ss_buf)
        try:
            # ML-KEM encapsulation
            ml_ct, ml_ss = ml_kem_encaps(ml_ek, randomness[32:])
            ml_ss_buf = bytearray(ml_ss)
            _mlock(ml_ss_buf)
            try:
                # Combine shared secrets with ciphertext + public key binding
                ct = eph_pk + ml_ct
                ss = _combine_secrets(
                    bytes(x_ss_buf), bytes(ml_ss_buf),
                    eph_pk, ml_ct, x_pk, ml_ek,
                )
                return ct, ss
            finally:
                _munlock(ml_ss_buf)
                _secure_zero(ml_ss_buf)
        finally:
            _munlock(x_ss_buf)
            _secure_zero(x_ss_buf)
    finally:
        _munlock(eph_sk_buf)
        _secure_zero(eph_sk_buf)


def _ct_select_bytes(flag, a, b):
    """Return a if flag is truthy, b otherwise. Constant-time.

    Expands flag into a per-byte mask without any data-dependent branch.
    """
    f = int(bool(flag)) & 1
    m = ((f - 1) & 0xFF) ^ 0xFF
    nm = m ^ 0xFF
    return bytes((ai & m) | (bi & nm) for ai, bi in zip(a, b))


def _x25519_shared_or_fallback(x_sk, eph_pk, ct):
    """Compute X25519 shared secret with implicit rejection on failure.

    Constant-time: always computes BOTH the DH result AND the fallback,
    then selects based on whether the result is all-zeros (low-order point).
    No exception-based branching — uses branchless byte selection.
    """
    # Always compute the raw DH result (never raises)
    result = _x25519_raw_bytes(x_sk, eph_pk)
    # Always compute the fallback
    fallback = hmac.new(
        x_sk, b"hybrid-kem-x25519-fail" + ct, hashlib.sha256
    ).digest()
    # Constant-time low-order check: accumulate OR of all bytes
    acc = 0
    for byte in result:
        acc |= byte
    # acc != 0 means valid result; acc == 0 means low-order (select fallback)
    return _ct_select_bytes(acc != 0, result, fallback)


def hybrid_kem_decaps(dk, ct):
    """Decapsulate: recover combined shared secret from hybrid ciphertext.

    Uses implicit rejection for both components:
    - ML-KEM: returns K_bar on ciphertext mismatch (FIPS 203 built-in).
    - X25519: derives a secret fallback on low-order/invalid ephemeral keys,
      preventing a validity oracle and keeping the hybrid robust.

    Memory hardening: decapsulation key and intermediate shared secrets are
    locked in RAM and securely wiped in finally blocks.

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

    # Copy secret key into mutable buffer for secure wiping
    dk_buf = bytearray(dk)
    _mlock(dk_buf)
    try:
        x_sk = bytes(dk_buf[:_X25519_SK])
        ml_dk = bytes(dk_buf[_X25519_SK:])
        eph_pk = ct[:_X25519_PK]
        ml_ct = ct[_X25519_PK:]

        # Recover receiver public keys from dk for HKDF binding.
        ml_ek = ml_dk[384*3:384*3+_ML_KEM_EK]
        x_pk = x25519_pk_from_sk(x_sk)

        # X25519 shared secret recovery (implicit rejection on failure)
        x_ss_buf = bytearray(_x25519_shared_or_fallback(x_sk, eph_pk, ct))
        _mlock(x_ss_buf)
        try:
            # ML-KEM decapsulation (implicit rejection built-in)
            ml_ss_buf = bytearray(ml_kem_decaps(ml_dk, ml_ct))
            _mlock(ml_ss_buf)
            try:
                # Combine shared secrets with ciphertext + public key binding
                return _combine_secrets(
                    bytes(x_ss_buf), bytes(ml_ss_buf),
                    eph_pk, ml_ct, x_pk, ml_ek,
                )
            finally:
                _munlock(ml_ss_buf)
                _secure_zero(ml_ss_buf)
        finally:
            _munlock(x_ss_buf)
            _secure_zero(x_ss_buf)
    finally:
        _munlock(dk_buf)
        _secure_zero(dk_buf)
