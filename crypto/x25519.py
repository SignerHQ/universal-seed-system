# Copyright (c) 2026 Signer — MIT License

"""Pure-Python X25519 Diffie-Hellman key exchange (RFC 7748).

Montgomery curve: y^2 = x^3 + 486662*x^2 + x  over GF(2^255 - 19).

Uses the Montgomery ladder for scalar multiplication (x-coordinate only),
producing a 32-byte shared secret from a 32-byte private key and a 32-byte
public key (u-coordinate).

Sizes:
    Private key: 32 bytes (clamped scalar)
    Public key:  32 bytes (u-coordinate of [sk] * basepoint)
    Shared secret: 32 bytes

NOT constant-time. For side-channel-resistant deployments, use C/Rust.
"""

_P = 2**255 - 19  # Field prime (same as Ed25519)
_A24 = 121665     # (A - 2) / 4 where A = 486662 (RFC 7748 Section 5)


def _clamp(k_bytes):
    """Apply RFC 7748 scalar clamping."""
    k = bytearray(k_bytes)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def _decode_u(u_bytes):
    """Decode 32-byte little-endian u-coordinate, masking top bit."""
    u = bytearray(u_bytes)
    u[31] &= 127  # Mask bit 255 per RFC 7748
    return int.from_bytes(bytes(u), 'little')


def _encode_u(u):
    """Encode u-coordinate as 32 bytes little-endian."""
    return (u % _P).to_bytes(32, 'little')


def _x25519_raw(k_bytes, u_bytes):
    """Core X25519 scalar multiplication (RFC 7748 Section 5).

    Montgomery ladder operating on projective (X : Z) coordinates.
    Returns the u-coordinate of [k] * (u, ...) as an integer mod p.
    """
    k = int.from_bytes(_clamp(k_bytes), 'little')
    u = _decode_u(u_bytes)

    # Montgomery ladder with projective coordinates
    x_2, z_2 = 1, 0  # Represents point at infinity
    x_3, z_3 = u, 1  # Represents (u, ...)

    # Note on cswap: RFC 7748 recommends implementing the conditional swap
    # in constant time (mask/XOR style) to avoid leaking scalar bits via
    # branch timing.  In Python, true constant-time branching is not
    # achievable regardless of technique, so we use a plain branch here.
    # For side-channel-resistant deployments, use a C/Rust binding.
    swap = 0
    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t

        A = (x_2 + z_2) % _P
        AA = (A * A) % _P
        B = (x_2 - z_2) % _P
        BB = (B * B) % _P
        E = (AA - BB) % _P
        C = (x_3 + z_3) % _P
        D = (x_3 - z_3) % _P
        DA = (D * A) % _P
        CB = (C * B) % _P

        x_3 = pow(DA + CB, 2, _P)
        z_3 = (u * pow(DA - CB, 2, _P)) % _P
        x_2 = (AA * BB) % _P
        z_2 = (E * (AA + _A24 * E)) % _P

    # Final conditional swap
    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2

    # Convert from projective: result = x_2 * z_2^(p-2) mod p
    return (x_2 * pow(z_2, _P - 2, _P)) % _P


def x25519_keygen(seed):
    """Generate X25519 keypair from 32-byte seed.

    Args:
        seed: 32-byte random seed (used directly as private scalar after clamping).

    Returns:
        (sk_bytes, pk_bytes) tuple.
        sk_bytes: 32-byte private key (clamped scalar).
        pk_bytes: 32-byte public key (u-coordinate of [sk] * basepoint 9).
    """
    if len(seed) != 32:
        raise ValueError(f"X25519 seed must be 32 bytes, got {len(seed)}")

    sk = _clamp(seed)
    # Base point u = 9
    basepoint = (9).to_bytes(32, 'little')
    u = _x25519_raw(sk, basepoint)
    pk = _encode_u(u)
    return sk, pk


def x25519(sk, pk):
    """Compute X25519 shared secret.

    Args:
        sk: 32-byte private key.
        pk: 32-byte peer's public key (u-coordinate).

    Returns:
        32-byte shared secret.

    Raises:
        ValueError: If the result is the all-zero point (low-order input).
    """
    if len(sk) != 32:
        raise ValueError(f"X25519 sk must be 32 bytes, got {len(sk)}")
    if len(pk) != 32:
        raise ValueError(f"X25519 pk must be 32 bytes, got {len(pk)}")

    u = _x25519_raw(sk, pk)
    result = _encode_u(u)

    # Reject low-order points (all-zero output) per RFC 7748 Section 6.1
    if result == b'\x00' * 32:
        raise ValueError("X25519: low-order input point (all-zero shared secret)")

    return result
