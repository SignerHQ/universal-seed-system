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

NOT constant-time. For side-channel-resistant deployments, use C/Rust.
"""

import hashlib
from typing import Optional

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


# ── Field Helpers ───────────────────────────────────────────────

def _modinv(a, m=_P):
    """Modular inverse via Fermat's little theorem (m is prime)."""
    return pow(a, m - 2, m)


def _to_affine(P):
    """Extended coordinates (X, Y, Z, T) -> affine (x, y)."""
    X, Y, Z, T = P
    if Z == 0:
        return (0, 1)
    z_inv = _modinv(Z)
    return ((X * z_inv) % _P, (Y * z_inv) % _P)


def _from_affine(x, y):
    """Affine (x, y) -> extended coordinates (X, Y, Z, T)."""
    return (x % _P, y % _P, 1, (x * y) % _P)


# ── Point Arithmetic ───────────────────────────────────────────

def _point_add(P, Q):
    """Add two points in extended coordinates."""
    if P == _ZERO:
        return Q
    if Q == _ZERO:
        return P

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
    """Double a point in extended coordinates."""
    if P == _ZERO:
        return _ZERO

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
    """Scalar multiplication k*P via Montgomery ladder."""
    if k == 0:
        return _ZERO
    if k < 0:
        k = -k
        P = _point_negate(P)

    k = k % _L
    if k == 0:
        return _ZERO

    R0 = _ZERO
    R1 = P
    for i in range(k.bit_length() - 1, -1, -1):
        if (k >> i) & 1:
            R0 = _point_add(R0, R1)
            R1 = _point_double(R1)
        else:
            R1 = _point_add(R0, R1)
            R0 = _point_double(R0)
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
    """Fast k*G using precomputed table (~2-3x faster than _scalar_mult)."""
    if k == 0:
        return _ZERO
    if k < 0:
        k = -k
        negate = True
    else:
        negate = False

    k = k % _L

    if _G_TABLE is None:
        _build_g_table()

    result = _ZERO
    for i, bit_power in enumerate(_G_TABLE):
        if k & (1 << i):
            result = _point_add(result, bit_power)

    return _point_negate(result) if negate else result


# ── Point Encoding (RFC 8032 Section 5.1.2) ────────────────────

def _encode_point(P):
    """Encode point to 32 bytes: y with sign bit of x in bit 255."""
    x, y = _to_affine(P)
    encoded = bytearray(y.to_bytes(32, 'little'))
    if x & 1:
        encoded[31] |= 0x80
    return bytes(encoded)


def _decode_point(b):
    """Decode 32-byte compressed point. Returns extended coords or None."""
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

    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(_clamp(h), 'little')
    pk_point = _scalar_mult_base(a)
    pk_bytes = _encode_point(pk_point)

    return seed + pk_bytes, pk_bytes


def ed25519_sign(message, sk_bytes):
    """Sign a message with Ed25519 (RFC 8032 Section 5.1.6).

    Args:
        message: Arbitrary-length message bytes.
        sk_bytes: 64-byte secret key from ed25519_keygen.

    Returns:
        64-byte signature (R || S).
    """
    if len(sk_bytes) != 64:
        raise ValueError(f"Ed25519 sk must be 64 bytes, got {len(sk_bytes)}")

    seed = sk_bytes[:32]
    pk_bytes = sk_bytes[32:]

    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(_clamp(h), 'little')
    prefix = h[32:]  # Upper 32 bytes

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

    return R_bytes + S.to_bytes(32, 'little')


def ed25519_verify(message, sig_bytes, pk_bytes):
    """Verify an Ed25519 signature (RFC 8032 Section 5.1.7).

    Uses the cofactor-less verification equation [S]B == R + [h]A, which is
    the standard Ed25519 behaviour matching most deployed libraries (libsodium,
    OpenSSL, Go, etc.).  This does NOT reject small-order or mixed-order public
    keys; if attacker-supplied public keys are used as identities in a protocol,
    consider adding an explicit main-subgroup check or adopting a cofactored
    verification equation (ZIP-215 / ed25519ctx style) as appropriate.

    Args:
        message: Arbitrary-length message bytes.
        sig_bytes: 64-byte signature.
        pk_bytes: 32-byte public key.

    Returns:
        True if valid, False otherwise.
    """
    if len(sig_bytes) != 64 or len(pk_bytes) != 32:
        return False

    # Decode R and A
    R = _decode_point(sig_bytes[:32])
    A = _decode_point(pk_bytes)
    if R is None or A is None:
        return False

    S = int.from_bytes(sig_bytes[32:], 'little')
    if S >= _L:
        return False

    # h = SHA-512(R || pk || message) mod L
    h = int.from_bytes(
        hashlib.sha512(sig_bytes[:32] + pk_bytes + message).digest(), 'little'
    ) % _L

    # Check: [S]B == R + [h]A
    lhs = _scalar_mult_base(S)
    rhs = _point_add(R, _scalar_mult(h, A))

    return _to_affine(lhs) == _to_affine(rhs)
