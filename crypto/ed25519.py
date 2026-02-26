# Copyright (c) 2026 Signer — MIT License

"""Pure-Python Ed25519 digital signatures (RFC 8032).

Ed25519 curve: -x^2 + y^2 = 1 + d*x^2*y^2  (mod p)

Uses extended coordinates (X, Y, Z, T) where x=X/Z, y=Y/Z, X*Y=Z*T for ~2x
faster point operations compared to affine coordinates.

Includes precomputed table for fast scalar*G multiplication.

Sizes:
    Secret key:  64 bytes (seed || public_key)
    Public key:  32 bytes (compressed Edwards point)
    Signature:   64 bytes (R || S)

Best-effort constant-time: all scalar multiplications use branchless
conditional swaps/moves (Montgomery ladder with cswap for arbitrary-point
scalar multiplication, precomputed table with branchless cmov for base-point
multiplication). Point addition and doubling use complete formulas with no
identity-point shortcuts. Encoding uses branchless sign-bit injection.

While the CPython interpreter cannot provide hardware-level constant-time
guarantees (GC pauses, object allocation, dynamic dispatch), this
implementation eliminates all *algorithmic* timing channels:
  - No data-dependent branches on secret values.
  - No early returns conditioned on secret comparisons.

When pynacl (libsodium) is available, keygen/sign/verify delegate to
C for additional side-channel resistance.
"""

import hashlib
import hmac
from typing import Optional

# ── Constant-time backend ──────────────────────────────────────
# pynacl (libsodium) provides constant-time Ed25519 operations.
# When available, keygen/sign/verify delegate to C for side-channel
# resistance. Pure Python internals are retained as fallback.
_HAS_NACL = False
try:
    import nacl.bindings
    _HAS_NACL = True
except ImportError:
    pass

# ── Secure memory utilities (libsodium-backed) ────────────────
# sodium_memzero:  Compiler-resistant secure zeroing.
# sodium_mlock:    Locks pages to prevent swapping secrets to disk.
# sodium_munlock:  Unlocks + zeros the pages on release.
# Degrades gracefully to pure-Python fallbacks when PyNaCl is absent.
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

# ── Exported Size Constants ────────────────────────────────────────
ED25519_SEED_SIZE = 32
ED25519_SK_SIZE = 64    # seed || public_key
ED25519_PK_SIZE = 32    # compressed Edwards point
ED25519_SIG_SIZE = 64   # R || S

# ── Field & Curve Constants ─────────────────────────────────────

_P = 2**255 - 19  # Field prime
_L = 2**252 + 27742317777372353535851937790883648493  # Group order
_D = -121665 * pow(121666, _P - 2, _P) % _P  # Curve constant d

# Base point G (RFC 8032): y = 4/5
_Gy = 4 * pow(5, _P - 2, _P) % _P

# Recover x from y: x^2 = (y^2 - 1) / (d*y^2 + 1)
_Gx_sq = (_Gy * _Gy - 1) * pow(_D * _Gy * _Gy + 1, _P - 2, _P) % _P
_Gx = pow(_Gx_sq, (_P + 3) // 8, _P)
if (_Gx * _Gx - _Gx_sq) % _P != 0:
    _Gx = (_Gx * pow(2, (_P - 1) // 4, _P)) % _P
if _Gx & 1:  # RFC 8032: base point has even x
    _Gx = (-_Gx) % _P

_G = (_Gx % _P, _Gy % _P, 1, (_Gx * _Gy) % _P)  # Extended coordinates
_ZERO = (0, 1, 1, 0)  # Neutral element

# ── Constant-Time Constants ───────────────────────────────────
_MASK256 = (1 << 256) - 1  # 256-bit mask for branchless operations
_IDENTITY_ENCODED = b'\x01' + b'\x00' * 31  # Encoding of identity point (0, 1)


# ── Field Helpers ───────────────────────────────────────────────

def _modinv(a, m=_P):
    """Modular inverse via Fermat's little theorem (m is prime)."""
    return pow(a, m - 2, m)


def _to_affine(P):
    """Extended coordinates (X, Y, Z, T) -> affine (x, y).

    Z is always non-zero for valid curve points. No branch on Z.
    """
    X, Y, Z, T = P
    z_inv = _modinv(Z)
    return ((X * z_inv) % _P, (Y * z_inv) % _P)


def _from_affine(x, y):
    """Affine (x, y) -> extended coordinates (X, Y, Z, T)."""
    return (x % _P, y % _P, 1, (x * y) % _P)


# ── Constant-Time Point Helpers ───────────────────────────────

def _ct_cswap_points(P, Q, swap):
    """Constant-time conditional swap. If swap=1, swap P<->Q; if 0, no-op.

    Uses XOR-mask technique: mask = -swap (all-zeros or all-ones in 256 bits),
    then XOR the masked difference into both operands.
    """
    mask = -(swap & 1) & _MASK256
    x0 = mask & (P[0] ^ Q[0])
    x1 = mask & (P[1] ^ Q[1])
    x2 = mask & (P[2] ^ Q[2])
    x3 = mask & (P[3] ^ Q[3])
    return (P[0] ^ x0, P[1] ^ x1, P[2] ^ x2, P[3] ^ x3), \
           (Q[0] ^ x0, Q[1] ^ x1, Q[2] ^ x2, Q[3] ^ x3)


def _ct_cmov_point(P, Q, flag):
    """Constant-time conditional move. If flag=1 return Q, if 0 return P.

    Uses XOR-mask technique to select between two points without branching.
    """
    mask = -(flag & 1) & _MASK256
    return (
        P[0] ^ (mask & (P[0] ^ Q[0])),
        P[1] ^ (mask & (P[1] ^ Q[1])),
        P[2] ^ (mask & (P[2] ^ Q[2])),
        P[3] ^ (mask & (P[3] ^ Q[3])),
    )


# ── Point Arithmetic ───────────────────────────────────────────

def _point_add(P, Q):
    """Add two points in extended coordinates.

    Complete addition formula — handles all inputs including identity
    and doubling without branching (no identity-point shortcuts).
    """
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q

    A = (Y1 - X1) * (Y2 - X2) % _P
    B = (Y1 + X1) * (Y2 + X2) % _P
    C = (2 * _D * T1) * T2 % _P
    DD = 2 * Z1 * Z2 % _P
    E = (B - A) % _P
    F = (DD - C) % _P
    GG = (DD + C) % _P
    H = (B + A) % _P

    return (E * F % _P, GG * H % _P, F * GG % _P, E * H % _P)


def _point_double(P):
    """Double a point in extended coordinates.

    Complete doubling formula — handles identity without branching.
    """
    X1, Y1, Z1, T1 = P

    A = X1 * X1 % _P
    B = Y1 * Y1 % _P
    C = 2 * Z1 * Z1 % _P
    DD = -A % _P
    E = ((X1 + Y1) * (X1 + Y1) - A - B) % _P
    GG = (DD + B) % _P
    F = (GG - C) % _P
    H = (DD - B) % _P

    return (E * F % _P, GG * H % _P, F * GG % _P, E * H % _P)


def _scalar_mult(k, P):
    """Constant-time scalar multiplication k*P via Montgomery ladder.

    Fixed 253-bit iteration with branchless conditional swaps.
    Always performs the same sequence of add + double operations,
    using cswap to select operands based on each scalar bit.
    """
    k = k % _L

    R0 = _ZERO
    R1 = P
    for i in range(252, -1, -1):
        bit = (k >> i) & 1
        R0, R1 = _ct_cswap_points(R0, R1, bit)
        R1 = _point_add(R0, R1)
        R0 = _point_double(R0)
        R0, R1 = _ct_cswap_points(R0, R1, bit)

    return R0


def _point_negate(P):
    """Negate: -(x, y) = (-x, y) in twisted Edwards."""
    X, Y, Z, T = P
    return ((-X) % _P, Y, Z, (-T) % _P)


# Precomputed table for fast G-multiplication (computed on first use)
_G_TABLE: Optional[list] = None


def _build_g_table():
    global _G_TABLE
    if _G_TABLE is not None:
        return
    table = [_G]
    P = _G
    for _ in range(255):
        P = _point_double(P)
        table.append(P)
    _G_TABLE = table


def _scalar_mult_base(k):
    """Constant-time k*G using precomputed table with branchless selection.

    Always iterates over all 256 table entries, using conditional move
    (cmov) to select whether to accumulate each entry. No branching on
    scalar bits.
    """
    k = k % _L

    if _G_TABLE is None:
        _build_g_table()

    result = _ZERO
    for i in range(256):
        bit = (k >> i) & 1
        added = _point_add(result, _G_TABLE[i])
        result = _ct_cmov_point(result, added, bit)

    return result


# ── Point Encoding (RFC 8032 Section 5.1.2) ────────────────────

def _encode_point(P):
    """Encode point to 32 bytes: y with sign bit of x in bit 255.

    Branchless sign-bit injection: uses arithmetic OR rather than if/else.
    """
    x, y = _to_affine(P)
    encoded = bytearray(y.to_bytes(32, 'little'))
    # Branchless: OR the parity bit into the high byte
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def _decode_point(b):
    """Decode 32-byte compressed point. Returns extended coords or None.

    Operates on public data (signatures/public keys), so early returns
    for invalid encodings do not leak secret information.
    """
    if len(b) != 32:
        return None

    y_bytes = bytearray(b)
    sign = (y_bytes[31] & 0x80) != 0
    y_bytes[31] &= 0x7F
    y = int.from_bytes(bytes(y_bytes), 'little')

    if y >= _P:
        return None

    # x^2 = (y^2 - 1) / (d*y^2 + 1)
    y_sq = (y * y) % _P
    x_sq = ((y_sq - 1) * _modinv((_D * y_sq + 1) % _P)) % _P

    if x_sq == 0:
        if sign:
            return None
        x = 0
    else:
        x = pow(x_sq, (_P + 3) // 8, _P)
        if (x * x - x_sq) % _P != 0:
            x = (x * pow(2, (_P - 1) // 4, _P)) % _P
            if (x * x - x_sq) % _P != 0:
                return None

        if (x & 1) != sign:
            x = (-x) % _P

    # Verify on curve: -x^2 + y^2 = 1 + d*x^2*y^2
    lhs = ((-x * x) % _P + y * y) % _P
    rhs = (1 + (_D * x * x % _P * y * y % _P)) % _P
    if lhs != rhs:
        return None

    return _from_affine(x, y)


# ── RFC 8032 Signing API ───────────────────────────────────────

def _clamp(h):
    """Apply RFC 8032 bit clamping to the first 32 bytes of SHA-512 output."""
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return bytes(a)


def ed25519_keygen(seed):
    """Generate Ed25519 keypair from 32-byte seed (RFC 8032 Section 5.1.5).

    Args:
        seed: 32-byte random seed.

    Returns:
        (sk_bytes, pk_bytes) tuple.
        sk_bytes: 64-byte secret key (seed || public_key).
        pk_bytes: 32-byte public key (compressed Edwards point).
    """
    if len(seed) != 32:
        raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(seed)}")

    if _HAS_NACL:
        pk, sk = nacl.bindings.crypto_sign_seed_keypair(seed)
        return sk, pk

    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(_clamp(h), 'little')
    pk_point = _scalar_mult_base(a)
    pk_bytes = _encode_point(pk_point)

    return seed + pk_bytes, pk_bytes


def ed25519_sign(message, sk_bytes):
    """Sign a message with Ed25519 (RFC 8032 Section 5.1.6).

    Fault injection countermeasure: verifies the signature before returning.
    If a hardware fault corrupts the computation, the broken signature is
    never released — preventing key recovery from faulty signatures.

    Args:
        message: Arbitrary-length message bytes.
        sk_bytes: 64-byte secret key from ed25519_keygen.

    Returns:
        64-byte signature (R || S).

    Raises:
        RuntimeError: If verify-after-sign detects a fault.
    """
    if len(sk_bytes) != 64:
        raise ValueError(f"Ed25519 sk must be 64 bytes, got {len(sk_bytes)}")

    pk_bytes = sk_bytes[32:]

    if _HAS_NACL:
        signed = nacl.bindings.crypto_sign(bytes(message), sk_bytes)
        sig = bytes(signed[:64])
        # Verify-after-sign (fault injection countermeasure)
        if not ed25519_verify(message, sig, pk_bytes):
            raise RuntimeError("Ed25519 verify-after-sign failed (fault detected)")
        return sig

    seed = sk_bytes[:32]

    # Use bytearray for secret intermediates so they can be securely wiped
    h_buf = bytearray(hashlib.sha512(seed).digest())
    _mlock(h_buf)
    try:
        a = int.from_bytes(_clamp(h_buf[:32]), 'little')
        prefix = bytes(h_buf[32:])  # Upper 32 bytes

        # r = SHA-512(prefix || message) mod L
        r = int.from_bytes(hashlib.sha512(prefix + message).digest(), 'little') % _L

        # R = r * G
        R = _scalar_mult_base(r)
        R_bytes = _encode_point(R)

        # S = (r + SHA-512(R || pk || message) * a) mod L
        h_ram = int.from_bytes(
            hashlib.sha512(R_bytes + pk_bytes + message).digest(), 'little'
        ) % _L
        S = (r + h_ram * a) % _L

        sig = R_bytes + S.to_bytes(32, 'little')

        # Verify-after-sign (fault injection countermeasure)
        if not ed25519_verify(message, sig, pk_bytes):
            raise RuntimeError("Ed25519 verify-after-sign failed (fault detected)")

        return sig
    finally:
        _munlock(h_buf)
        _secure_zero(h_buf)


def _is_small_order(P):
    """Check if point has small order (order dividing cofactor 8).

    Computes [8]P via three doublings and checks if the result is the
    identity. Constant-time: uses hmac.compare_digest on encoded points
    rather than branching on affine coordinate comparisons.
    """
    P8 = _point_double(_point_double(_point_double(P)))
    return hmac.compare_digest(_encode_point(P8), _IDENTITY_ENCODED)


def ed25519_verify(message, sig_bytes, pk_bytes):
    """Verify an Ed25519 signature (RFC 8032 Section 5.1.7).

    When pynacl is available, uses libsodium's constant-time verification.
    Pure Python fallback uses cofactor-less [S]B == R + [h]A with small-order
    rejection for defence-in-depth. All scalar multiplications use
    constant-time Montgomery ladder / precomputed table with branchless
    selection. Final comparison uses hmac.compare_digest.

    Args:
        message: Arbitrary-length message bytes.
        sig_bytes: 64-byte signature.
        pk_bytes: 32-byte public key.

    Returns:
        True if valid, False otherwise.
    """
    if len(sig_bytes) != 64 or len(pk_bytes) != 32:
        return False

    if _HAS_NACL:
        try:
            # crypto_sign_open expects sig || message, returns message on success
            nacl.bindings.crypto_sign_open(bytes(sig_bytes) + bytes(message), pk_bytes)
            return True
        except Exception:
            return False

    # Decode R and A
    R = _decode_point(sig_bytes[:32])
    A = _decode_point(pk_bytes)
    if R is None or A is None:
        return False

    # Reject small-order public keys (cofactor subgroup)
    if _is_small_order(A):
        return False

    # Reject small-order R (commitment point) — prevents edge-case forgeries
    # where R lies in the cofactor subgroup.  Cheap (three doublings) and
    # recommended by defensive crypto engineering practice.
    if _is_small_order(R):
        return False

    S = int.from_bytes(sig_bytes[32:], 'little')
    if S >= _L:
        return False

    # h = SHA-512(R || pk || message) mod L
    h = int.from_bytes(
        hashlib.sha512(sig_bytes[:32] + pk_bytes + message).digest(), 'little'
    ) % _L

    # Check: [S]B == R + [h]A
    # Compare via encoded point bytes using hmac.compare_digest to avoid
    # Python's early-exit == comparison on tuples.
    lhs = _scalar_mult_base(S)
    rhs = _point_add(R, _scalar_mult(h, A))

    return hmac.compare_digest(_encode_point(lhs), _encode_point(rhs))
