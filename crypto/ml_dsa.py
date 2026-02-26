# Copyright (c) 2026 Signer — MIT License

"""ML-DSA-65 (Dilithium) — FIPS 204 post-quantum digital signature.

Pure-Python implementation of the Module-Lattice-Based Digital Signature
Standard (ML-DSA) at Security Level 3 (ML-DSA-65).

Operates over the polynomial ring Z_q[X]/(X^256 + 1) where q = 8380417.
Uses NTT (Number Theoretic Transform) for efficient polynomial multiplication.

Key sizes:
    Public key:  1,952 bytes
    Secret key:  4,032 bytes
    Signature:   3,309 bytes

Security: NIST Level 3 (~192-bit post-quantum security).
Assumption: Module Learning With Errors (MLWE) hardness.

Reference: NIST FIPS 204 (August 2024).

Public API:
    ml_keygen(seed)              -> (sk_bytes, pk_bytes)
    ml_sign(msg, sk, ctx=b"")    -> sig_bytes    (pure FIPS 204)
    ml_verify(msg, sig, pk, ctx) -> bool          (pure FIPS 204)

Notes:
    - Messages are byte-aligned (Python bytes). Bit-level granularity is not
      supported (would require a bit-level SHAKE interface).
    - Signing defaults to hedged mode (rnd generated via os.urandom) as
      recommended by FIPS 204. Pass deterministic=True for reproducible
      signatures (uses rnd=0^32).
    - Best-effort constant-time: uses Barrett reduction (no variable-time `%`),
      branchless conditionals, and no early-exit loops on secret data.
"""

import hashlib
import hmac
import os
import struct

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

# ── ML-DSA-65 Parameters (FIPS 204 Table 1) ──────────────────────

_Q = 8380417          # Prime modulus: 2^23 - 2^13 + 1
_N = 256              # Polynomial degree
_D = 13               # Dropped bits from t
_K = 6                # Rows in matrix A (module dimension)
_L = 5                # Columns in matrix A
_ETA = 4              # Secret key coefficient bound
_TAU = 49             # Challenge polynomial weight (number of ±1)
_BETA = _TAU * _ETA   # = 196 — FIPS 204 Table 1: beta for ML-DSA-65
_GAMMA1 = 1 << 19     # 2^19 = 524288 — masking range
_GAMMA2 = (_Q - 1) // 32  # = 261888 — decomposition divisor
_OMEGA = 55           # Max number of 1s in hint
_C_TILDE_BYTES = 48   # Challenge seed bytes
_LAMBDA = 192         # Bit security (Level 3)


# ── Barrett Reduction Constants ───────────────────────────────────
# Replace Python's variable-time `%` operator with fixed-point
# multiply + shift for predictable timing on fixed-size inputs.

# For NTT products (x in [0, q^2)): shift=70 ensures error <= 1
_BARRETT_SHIFT_Q = 70
_BARRETT_MULT_Q = 140875044847698   # floor(2^70 / 8380417)

# For decomposition (x in [0, q), modulus 2*GAMMA2 = 523776)
_2GAMMA2 = 2 * _GAMMA2              # 523776
_BARRETT_SHIFT_2G = 43
_BARRETT_MULT_2G = 16793616         # floor(2^43 / 523776)

_HALF_Q = _Q >> 1                   # 4190208

# ── Constant-time Arithmetic Helpers ─────────────────────────────

def _ct_mod_q(x):
    """Barrett reduction: x mod q for x in [0, q^2). Branchless."""
    t = (x * _BARRETT_MULT_Q) >> _BARRETT_SHIFT_Q
    r = x - t * _Q
    mask = 1 + ((r - _Q) >> 63)
    return r - mask * _Q


def _ct_add_mod_q(a, b):
    """(a + b) mod q for a, b in [0, q). Branchless."""
    r = a + b
    mask = 1 + ((r - _Q) >> 63)
    return r - mask * _Q


def _ct_sub_mod_q(a, b):
    """(a - b) mod q for a, b in [0, q). Branchless."""
    r = a - b
    mask = r >> 63
    return r - mask * _Q


# ── NTT Constants ─────────────────────────────────────────────────

def _bitrev8(n):
    """Reverse the lower 8 bits of an integer."""
    r = 0
    for _ in range(8):
        r = (r << 1) | (n & 1)
        n >>= 1
    return r


# Primitive 512th root of unity modulo q.
# 1753^256 ≡ -1 (mod q) and 1753^512 ≡ 1 (mod q).
_ROOT = 1753

# Precompute 256 zetas in bit-reversed order (FIPS 204 Section 4.6).
# _ZETAS[0] = zeta^(bitrev8(0)) = zeta^0 = 1, but we set it to 0 to match
# the spec's array layout where index 0 is unused (NTT starts at index 1).
_ZETAS = [pow(_ROOT, _bitrev8(i), _Q) for i in range(256)]
_ZETAS[0] = 0

# Inverse of 256 mod q, for inverse NTT scaling.
_N_INV = pow(_N, _Q - 2, _Q)


# ── NTT Operations ────────────────────────────────────────────────

def _ntt(a):
    """Forward NTT (Algorithm 41, FIPS 204).

    Transforms polynomial from coefficient domain to NTT evaluation domain.
    In-place Cooley-Tukey butterfly with bit-reversed zetas.
    Uses Barrett reduction instead of variable-time `%`.
    """
    f = list(a)
    k = 1
    length = 128
    _bm = _BARRETT_MULT_Q
    _bs = _BARRETT_SHIFT_Q
    _q = _Q
    while length >= 1:
        start = 0
        while start < _N:
            zeta = _ZETAS[k]
            k += 1
            for j in range(start, start + length):
                # Barrett reduction of zeta * f[j+length]
                x = zeta * f[j + length]
                bt = (x * _bm) >> _bs
                t = x - bt * _q
                t -= _q * (1 + ((t - _q) >> 63))
                # f[j+length] = (f[j] - t) mod q
                r = f[j] - t
                f[j + length] = r - (r >> 63) * _q
                # f[j] = (f[j] + t) mod q
                s = f[j] + t
                f[j] = s - _q * (1 + ((s - _q) >> 63))
            start += 2 * length
        length >>= 1
    return f


def _inv_ntt(f):
    """Inverse NTT (Algorithm 42, FIPS 204).

    Transforms from NTT domain back to coefficient domain.
    Gentleman-Sande butterfly with inverse zetas.
    Uses Barrett reduction instead of variable-time `%`.
    """
    a = list(f)
    k = 255
    length = 1
    _bm = _BARRETT_MULT_Q
    _bs = _BARRETT_SHIFT_Q
    _q = _Q
    while length < _N:
        start = 0
        while start < _N:
            zeta = _ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = a[j]
                # a[j] = (t + a[j+length]) mod q
                s = t + a[j + length]
                a[j] = s - _q * (1 + ((s - _q) >> 63))
                # a[j+length] = (zeta * (a[j+length] - t)) mod q
                # Original uses -zeta, equivalent to zeta * (a[j+length] - t)
                diff = a[j + length] - t
                diff -= (diff >> 63) * _q  # make non-negative
                x = zeta * diff
                bt = (x * _bm) >> _bs
                r = x - bt * _q
                a[j + length] = r - _q * (1 + ((r - _q) >> 63))
            start += 2 * length
        length <<= 1
    # Final scaling by N_INV
    for i in range(_N):
        x = a[i] * _N_INV
        bt = (x * _bm) >> _bs
        r = x - bt * _q
        a[i] = r - _q * (1 + ((r - _q) >> 63))
    return a


def _ntt_mult(a, b):
    """Pointwise multiplication of two NTT-domain polynomials.
    Uses Barrett reduction."""
    return [_ct_mod_q(a[i] * b[i]) for i in range(_N)]


# ── Polynomial Arithmetic ─────────────────────────────────────────

def _poly_add(a, b):
    """Coefficient-wise addition mod q. Branchless."""
    return [_ct_add_mod_q(a[i], b[i]) for i in range(_N)]


def _poly_sub(a, b):
    """Coefficient-wise subtraction mod q. Branchless."""
    return [_ct_sub_mod_q(a[i], b[i]) for i in range(_N)]


def _poly_zero():
    """Zero polynomial."""
    return [0] * _N


# ── Module (Vector/Matrix) Operations ─────────────────────────────

def _vec_ntt(v):
    """Apply NTT to each polynomial in a vector."""
    return [_ntt(p) for p in v]


def _vec_inv_ntt(v):
    """Apply inverse NTT to each polynomial in a vector."""
    return [_inv_ntt(p) for p in v]


def _vec_add(u, v):
    """Vector addition."""
    return [_poly_add(u[i], v[i]) for i in range(len(u))]


def _vec_sub(u, v):
    """Vector subtraction."""
    return [_poly_sub(u[i], v[i]) for i in range(len(u))]


def _mat_vec_ntt(A, v):
    """Matrix-vector product in NTT domain.

    A is k×l matrix of NTT-domain polynomials.
    v is l-vector of NTT-domain polynomials.
    Returns k-vector of NTT-domain polynomials.
    """
    result = []
    for i in range(len(A)):
        acc = _poly_zero()
        for j in range(len(v)):
            acc = _poly_add(acc, _ntt_mult(A[i][j], v[j]))
        result.append(acc)
    return result


def _inner_product_ntt(a, b):
    """Inner product of two vectors in NTT domain."""
    acc = _poly_zero()
    for i in range(len(a)):
        acc = _poly_add(acc, _ntt_mult(a[i], b[i]))
    return acc


# ── Sampling Functions ─────────────────────────────────────────────

def _rej_ntt_poly(seed34):
    """Sample uniform polynomial in Tq via rejection (Algorithm 30, FIPS 204).

    Uses CoeffFromThreeBytes: each 3-byte group yields a 23-bit candidate
    (top bit of b2 cleared). Reject if >= q. Result is already in NTT domain.

    seed34: 34-byte input (rho || IntegerToBytes(s,1) || IntegerToBytes(r,1)).
    """
    xof = hashlib.shake_128(seed34)
    coeffs = []
    need = 3 * _N  # ~256 candidates; rejection rate is ~0.4%
    buf = xof.digest(need)
    pos = 0
    while len(coeffs) < _N:
        if pos + 3 > len(buf):
            need += 3 * 64
            buf = xof.digest(need)
        b0 = buf[pos]
        b1 = buf[pos + 1]
        b2 = buf[pos + 2]
        pos += 3
        z = b0 | (b1 << 8) | ((b2 & 0x7F) << 16)  # 23-bit candidate
        if z < _Q:
            coeffs.append(z)
    return coeffs


def _sample_rej_eta(seed, nonce):
    """Sample polynomial with coefficients in [-eta, eta] via rejection.

    Uses SHAKE-256 XOF, processes half-bytes (nibbles) (Algorithm 14/33, FIPS 204).
    For eta=4: accept nibble if < 9, coefficient = eta - nibble.
    """
    stream = hashlib.shake_256(seed + struct.pack("<H", nonce)).digest(512)
    coeffs = []
    pos = 0
    while len(coeffs) < _N:
        if pos >= len(stream):
            stream = hashlib.shake_256(seed + struct.pack("<H", nonce)).digest(len(stream) + 256)
        b = stream[pos]
        pos += 1
        t0 = b & 0x0F
        t1 = b >> 4
        if t0 < 9:
            coeffs.append((_ETA - t0) % _Q)
        if t1 < 9 and len(coeffs) < _N:
            coeffs.append((_ETA - t1) % _Q)
    return coeffs


def _expand_A(rho):
    """Expand seed rho into k*l matrix of NTT-domain polynomials.

    Algorithm 32, FIPS 204. Each entry sampled via RejNTTPoly
    (already in Tq — no additional NTT needed).
    """
    A = []
    for r in range(_K):
        row = []
        for s in range(_L):
            seed34 = rho + bytes([s, r])
            row.append(_rej_ntt_poly(seed34))
        A.append(row)
    return A


def _expand_S(rho_prime):
    """Expand rho' into secret vectors s1 (l-vector) and s2 (k-vector).

    Algorithm 33, FIPS 204.
    """
    s1 = []
    for j in range(_L):
        s1.append(_sample_rej_eta(rho_prime, j))
    s2 = []
    for j in range(_K):
        s2.append(_sample_rej_eta(rho_prime, _L + j))
    return s1, s2


def _expand_mask(rho_prime, kappa):
    """Expand rho'' into masking vector y (l-vector).

    Algorithm 34, FIPS 204. Coefficients in [-gamma1+1, gamma1].
    """
    y = []
    # gamma1 = 2^19, so need 20 bits per coefficient
    for j in range(_L):
        seed_bytes = hashlib.shake_256(
            rho_prime + struct.pack("<H", kappa + j)
        ).digest(5 * _N // 2)  # 20 bits * 256 / 8 = 640 bytes
        coeffs = []
        for i in range(_N):
            # Extract 20-bit value
            bit_offset = i * 20
            byte_idx = bit_offset // 8
            bit_shift = bit_offset % 8
            val = (seed_bytes[byte_idx] | (seed_bytes[byte_idx + 1] << 8) |
                   (seed_bytes[min(byte_idx + 2, len(seed_bytes) - 1)] << 16))
            val = (val >> bit_shift) & 0xFFFFF  # 20-bit mask
            coeffs.append((_GAMMA1 - val) % _Q)
        y.append(coeffs)
    return y


def _sample_in_ball(c_tilde):
    """Sample challenge polynomial c with exactly tau non-zero coefficients.

    Algorithm 35, FIPS 204. c has tau entries of ±1, rest 0.
    """
    xof = hashlib.shake_256(c_tilde)
    buf = xof.digest(8 + _TAU)  # First 8 bytes for sign bits, then rejection samples
    # Extract sign bits from first 8 bytes
    sign_bits = int.from_bytes(buf[:8], "little")
    c = [0] * _N
    pos = 8  # Start after sign bytes
    for i in range(_N - _TAU, _N):
        # Rejection sample j in [0, i]
        while True:
            if pos >= len(buf):
                buf = xof.digest(len(buf) + 256)
            j = buf[pos]
            pos += 1
            if j <= i:
                break
        c[i] = c[j]
        sign = (sign_bits >> (i - (_N - _TAU))) & 1
        # Branchless: sign=0 -> 1, sign=1 -> Q-1
        c[j] = 1 + sign * (_Q - 2)
    return c


# ── Rounding & Decomposition ──────────────────────────────────────

def _power2_round(r):
    """Decompose r into (r1, r0) where r = r1*2^d + r0 (Algorithm 36).

    r0 in [-2^(d-1), 2^(d-1)). Branchless.
    """
    r_pos = r  # already in [0, q)
    r0 = r_pos & ((1 << _D) - 1)  # r_pos mod 2^d (bitmask, no division)
    # Branchless centering: if r0 > 2^(d-1), subtract 2^d
    _half = 1 << (_D - 1)  # 4096
    gt = 1 + ((r0 - _half - 1) >> 63)  # 1 if r0 > 4096, else 0
    r0 = r0 - gt * (1 << _D)
    r1 = (r_pos - r0) >> _D
    return r1, r0


def _decompose(r):
    """High-order/low-order decomposition using gamma2 (Algorithm 37).

    Returns (r1, r0) where r = r1*2*gamma2 + r0 with |r0| <= gamma2.
    Branchless with Barrett reduction.
    """
    r_pos = r  # already in [0, q)
    # Barrett reduction: r0 = r_pos mod (2*GAMMA2)
    t = (r_pos * _BARRETT_MULT_2G) >> _BARRETT_SHIFT_2G
    r0 = r_pos - t * _2GAMMA2
    # Correction step (Barrett may underestimate by 1)
    corr = 1 + ((r0 - _2GAMMA2) >> 63)  # 1 if r0 >= 2*GAMMA2
    r0 = r0 - corr * _2GAMMA2
    t = t + corr
    # Branchless centering: if r0 > GAMMA2, subtract 2*GAMMA2
    gt = 1 + ((r0 - _GAMMA2 - 1) >> 63)  # 1 if r0 > GAMMA2
    r0 = r0 - gt * _2GAMMA2
    t = t + gt
    # Branchless special case: if t == 16 (i.e., r_pos - r0 == q-1)
    # then r1 = 0, r0 -= 1
    diff_t = t - 16
    eq = 1 + ((diff_t | -diff_t) >> 63)  # 1 if t == 16, else 0
    r1 = t * (1 - eq)
    r0 = r0 - eq
    return r1, r0


def _high_bits(r):
    """Return high-order bits of r."""
    r1, _ = _decompose(r)
    return r1


def _low_bits(r):
    """Return low-order bits of r."""
    _, r0 = _decompose(r)
    return r0


def _make_hint(z, r):
    """Compute hint bit: 1 if high_bits(r) != high_bits(r+z) (Algorithm 38).

    Branchless comparison.
    """
    r1 = _high_bits(r)
    # Branchless (r + z) mod q for r, z in [0, q)
    s = r + z
    s_mod = s - _Q * (1 + ((s - _Q) >> 63))
    v1 = _high_bits(s_mod)
    diff = r1 - v1
    return -((diff | -diff) >> 63)  # 0 if equal, 1 if different


def _use_hint(h, r):
    """Recover correct high bits using hint (Algorithm 39).

    Branchless: if h=0, return high_bits(r). If h=1, adjust by +-1.
    """
    _m = 16  # (_Q - 1) // (2 * _GAMMA2)
    r1, r0 = _decompose(r)
    # Branchless sign of r0: adjustment = +1 if r0 > 0, -1 if r0 <= 0
    is_pos = 1 + ((r0 - 1) >> 63)  # 1 if r0 > 0, 0 if r0 <= 0
    adj = 2 * is_pos - 1  # +1 or -1
    r1_adj = r1 + adj
    # Branchless mod m for r1_adj in [-1, 16]
    mask_neg = r1_adj >> 63
    r1_adj = r1_adj - mask_neg * _m  # add m if negative
    mask_over = 1 + ((r1_adj - _m) >> 63)
    r1_adj = r1_adj - mask_over * _m  # subtract m if >= m
    # Select: h=0 -> r1, h=1 -> r1_adj
    return r1 * (1 - h) + r1_adj * h


# ── Bit Packing / Encoding ────────────────────────────────────────

def _bit_pack(coeffs, bits):
    """Pack polynomial coefficients into bytes using `bits` bits each."""
    buf = bytearray()
    acc = 0
    acc_bits = 0
    for c in coeffs:
        acc |= (c & ((1 << bits) - 1)) << acc_bits
        acc_bits += bits
        while acc_bits >= 8:
            buf.append(acc & 0xFF)
            acc >>= 8
            acc_bits -= 8
    if acc_bits > 0:
        buf.append(acc & 0xFF)
    return bytes(buf)


def _bit_unpack(data, n, bits):
    """Unpack `n` coefficients of `bits` bits each from bytes."""
    coeffs = []
    acc = 0
    acc_bits = 0
    pos = 0
    mask = (1 << bits) - 1
    for _ in range(n):
        while acc_bits < bits:
            acc |= data[pos] << acc_bits
            pos += 1
            acc_bits += 8
        coeffs.append(acc & mask)
        acc >>= bits
        acc_bits -= bits
    return coeffs


def _pack_signed(coeffs, a, bits):
    """Pack signed coefficients: each mapped to a - c, then packed in `bits` bits.

    Used for z (gamma1 - z_i) and r0 components.
    """
    mapped = [(a - c) % _Q for c in coeffs]
    return _bit_pack(mapped, bits)


def _unpack_signed(data, n, a, bits):
    """Unpack signed coefficients packed with _pack_signed."""
    raw = _bit_unpack(data, n, bits)
    return [(a - r) % _Q for r in raw]


# ── Public Key Encoding ────────────────────────────────────────────

def _pk_encode(rho, t1):
    """Encode public key: rho (32 bytes) || bitpack(t1, 10 bits each).

    Algorithm 22, FIPS 204. t1 coefficients are in [0, 2^10).
    Public key size: 32 + k*256*10/8 = 32 + 6*320 = 1952 bytes.
    """
    buf = bytearray(rho)
    for i in range(_K):
        buf.extend(_bit_pack(t1[i], 10))
    return bytes(buf)


def _pk_decode(pk_bytes):
    """Decode public key into (rho, t1)."""
    rho = pk_bytes[:32]
    t1 = []
    offset = 32
    for _ in range(_K):
        chunk = pk_bytes[offset:offset + 320]
        t1.append(_bit_unpack(chunk, _N, 10))
        offset += 320
    return rho, t1


# ── Secret Key Encoding ────────────────────────────────────────────

def _sk_encode(rho, K, tr, s1, s2, t0):
    """Encode secret key (Algorithm 24, FIPS 204).

    Layout: rho(32) || K(32) || tr(64) || bitpack(s1) || bitpack(s2) || bitpack(t0)
    For eta=4: each s coefficient in [-4,4] packed as 4 bits (mapped to [0,8]).
    t0 coefficients in [-2^12, 2^12) packed as 13 bits.
    Secret key size: 32+32+64 + 5*256*4/8 + 6*256*4/8 + 6*256*13/8 = 4032 bytes.
    """
    buf = bytearray(rho)
    buf.extend(K)
    buf.extend(tr)
    # s1: l polynomials, eta=4 -> 4 bits per coefficient (mapped: eta - c)
    for i in range(_L):
        buf.extend(_bit_pack([(_ETA - c) % _Q for c in s1[i]], 4))
    # s2: k polynomials, same encoding
    for i in range(_K):
        buf.extend(_bit_pack([(_ETA - c) % _Q for c in s2[i]], 4))
    # t0: k polynomials, 13 bits per coefficient (mapped: 2^(d-1) - c)
    half = 1 << (_D - 1)  # 4096
    for i in range(_K):
        buf.extend(_bit_pack([(half - c) % _Q for c in t0[i]], 13))
    return bytes(buf)


def _sk_decode(sk_bytes):
    """Decode secret key into (rho, K, tr, s1, s2, t0)."""
    rho = sk_bytes[:32]
    K = sk_bytes[32:64]
    tr = sk_bytes[64:128]

    offset = 128
    # s1: l polynomials, 4 bits each
    s1 = []
    s_bytes = _N * 4 // 8  # 128 bytes per polynomial
    for _ in range(_L):
        raw = _bit_unpack(sk_bytes[offset:offset + s_bytes], _N, 4)
        s1.append([(_ETA - r) % _Q for r in raw])
        offset += s_bytes
    # s2: k polynomials, 4 bits each
    s2 = []
    for _ in range(_K):
        raw = _bit_unpack(sk_bytes[offset:offset + s_bytes], _N, 4)
        s2.append([(_ETA - r) % _Q for r in raw])
        offset += s_bytes
    # t0: k polynomials, 13 bits each
    t0 = []
    t0_bytes = _N * 13 // 8  # 416 bytes per polynomial
    half = 1 << (_D - 1)
    for _ in range(_K):
        raw = _bit_unpack(sk_bytes[offset:offset + t0_bytes], _N, 13)
        t0.append([(half - r) % _Q for r in raw])
        offset += t0_bytes
    return rho, K, tr, s1, s2, t0


# ── Signature Encoding ─────────────────────────────────────────────

def _sig_encode(c_tilde, z, h):
    """Encode signature (Algorithm 26, FIPS 204).

    Layout: c_tilde(48) || bitpack(z, 20 bits) || hint_encode(h)
    Signature size: 48 + 5*640 + 61 = 3309 bytes (FIPS 204 Table 2).
    """
    buf = bytearray(c_tilde)
    # z: l polynomials, 20 bits each (gamma1 - z_i)
    for i in range(_L):
        buf.extend(_bit_pack([(_GAMMA1 - c) % _Q for c in z[i]], 20))
    # Hint encoding: omega + k bytes (Algorithm 27)
    hint_buf = bytearray(_OMEGA + _K)
    idx = 0
    for i in range(_K):
        for j in range(_N):
            if h[i][j] != 0:
                hint_buf[idx] = j
                idx += 1
        hint_buf[_OMEGA + i] = idx
    buf.extend(hint_buf)
    return bytes(buf)


def _sig_decode(sig_bytes):
    """Decode signature into (c_tilde, z, h)."""
    c_tilde = sig_bytes[:_C_TILDE_BYTES]

    offset = _C_TILDE_BYTES
    # z: l polynomials, 20 bits each
    z = []
    z_bytes = _N * 20 // 8  # 640 bytes per polynomial
    for _ in range(_L):
        raw = _bit_unpack(sig_bytes[offset:offset + z_bytes], _N, 20)
        z.append([(_GAMMA1 - r) % _Q for r in raw])
        offset += z_bytes

    # Hint decoding (Algorithm 28)
    # Hint data is from the public signature — early returns do not leak secrets.
    hint_section = sig_bytes[offset:offset + _OMEGA + _K]
    h = [[0] * _N for _ in range(_K)]
    idx = 0
    for i in range(_K):
        end = hint_section[_OMEGA + i]
        if end < idx or end > _OMEGA:
            return None  # Malformed hint
        for j in range(idx, end):
            if j > idx and hint_section[j] <= hint_section[j - 1]:
                return None  # Not sorted
            h[i][hint_section[j]] = 1
        idx = end
    # Check remaining positions are zero
    for j in range(idx, _OMEGA):
        if hint_section[j] != 0:
            return None
    return c_tilde, z, h


# ── Key Sizes ──────────────────────────────────────────────────────

_PK_SIZE = 32 + _K * 320           # 32 + 6*320 = 1952
_SK_SIZE = 128 + (_L + _K) * 128 + _K * 416  # 128 + 11*128 + 6*416 = 4032
_SIG_SIZE = _C_TILDE_BYTES + _L * 640 + _OMEGA + _K  # 48 + 3200 + 61 = 3309


# ── Core Algorithms ────────────────────────────────────────────────

def ml_keygen(seed):
    """ML-DSA-65 key generation (Algorithm 1, FIPS 204).

    Args:
        seed: 32-byte random seed (xi).

    Returns:
        (sk_bytes, pk_bytes) tuple.
        sk_bytes: 4,032-byte secret key.
        pk_bytes: 1,952-byte public key.
    """
    if len(seed) != 32:
        raise ValueError(f"seed must be 32 bytes, got {len(seed)}")

    # Step 1: Expand seed into (rho, rho', K) via SHAKE-256
    expanded = hashlib.shake_256(seed + bytes([_K, _L])).digest(128)
    rho = expanded[:32]
    rho_prime = expanded[32:96]
    K = expanded[96:128]

    # Step 2: Expand A from rho (in NTT domain)
    A_hat = _expand_A(rho)

    # Step 3: Sample secret vectors s1, s2 from rho'
    s1, s2 = _expand_S(rho_prime)

    # Step 4: Compute t = A*s1 + s2 (via NTT)
    s1_hat = _vec_ntt(s1)
    t = _vec_inv_ntt(_vec_add(_mat_vec_ntt(A_hat, s1_hat), _vec_ntt(s2)))

    # Step 5: Compress t into (t1, t0)
    t1 = []
    t0_list = []
    for i in range(_K):
        t1_poly = []
        t0_poly = []
        for j in range(_N):
            hi, lo = _power2_round(t[i][j])
            t1_poly.append(hi)
            t0_poly.append(lo)
        t1.append(t1_poly)
        t0_list.append(t0_poly)

    # Step 6: Encode public key and compute tr = H(pk)
    pk_bytes = _pk_encode(rho, t1)
    tr = hashlib.shake_256(pk_bytes).digest(64)

    # Step 7: Encode secret key
    sk_bytes = _sk_encode(rho, K, tr, s1, s2, t0_list)

    return sk_bytes, pk_bytes


def _pk_from_sk(sk_bytes):
    """Reconstruct public key from secret key.

    Decodes rho and recomputes t1 = (A*s1 + s2) >> d from the secret
    vectors stored in the SK. Used for verify-after-sign.
    """
    rho, K, tr, s1, s2, t0 = _sk_decode(sk_bytes)
    A_hat = _expand_A(rho)
    s1_hat = _vec_ntt(s1)
    t = _vec_inv_ntt(_vec_add(_mat_vec_ntt(A_hat, s1_hat), _vec_ntt(s2)))
    t1 = []
    for i in range(_K):
        t1_poly = []
        for j in range(_N):
            hi, _ = _power2_round(t[i][j])
            t1_poly.append(hi)
        t1.append(t1_poly)
    return _pk_encode(rho, t1)


def _ml_sign_internal(message, sk_bytes, rnd=None, deterministic=False):
    """ML-DSA-65 internal signing (Algorithm 7, FIPS 204).

    Signs pre-processed message M' directly. Use ml_sign() for the
    pure FIPS 204 API with context string support.

    Memory hardening: secret key material (K, s1, s2, t0, rho_prime)
    is locked in RAM during signing and securely wiped in a finally block.

    rnd: Explicit 32-byte randomness. If provided, overrides both modes.
    deterministic: If True and rnd is None, uses 0^32 (deterministic).
                   If False and rnd is None, generates os.urandom(32) (hedged).
    """
    if len(sk_bytes) != _SK_SIZE:
        raise ValueError(f"secret key must be {_SK_SIZE} bytes, got {len(sk_bytes)}")
    if rnd is not None:
        rnd = bytes(rnd)
        if len(rnd) != 32:
            raise ValueError(f"rnd must be 32 bytes, got {len(rnd)}")

    # Copy secret key into mutable buffer for secure wiping
    sk_buf = bytearray(sk_bytes)
    _mlock(sk_buf)
    try:
        # Step 1: Decode secret key
        rho, K, tr, s1, s2, t0 = _sk_decode(bytes(sk_buf))

        # Step 2: Pre-compute NTT of secret vectors
        s1_hat = _vec_ntt(s1)
        s2_hat = _vec_ntt(s2)
        t0_hat = _vec_ntt(t0)

        # Step 3: Expand A from rho
        A_hat = _expand_A(rho)

        # Step 4: Compute mu = H(tr || msg) — message representative
        mu = hashlib.shake_256(tr + message).digest(64)

        # Step 5: rho'' = H(K || rnd || mu) (FIPS 204 Algorithm 7)
        if rnd is not None:
            pass  # Explicit rnd provided, use as-is
        elif deterministic:
            rnd = bytes(32)
        else:
            rnd = os.urandom(32)
        rho_prime_buf = bytearray(hashlib.shake_256(K + rnd + mu).digest(64))
        _mlock(rho_prime_buf)

        try:
            # Step 6: Rejection sampling loop.
            kappa = 0
            max_attempts = 1000
            for attempt in range(max_attempts):
                # 6a: Generate masking vector y
                y = _expand_mask(bytes(rho_prime_buf), kappa)
                kappa += _L

                # 6b: Compute w = A*y (via NTT)
                y_hat = _vec_ntt(y)
                w = _vec_inv_ntt(_mat_vec_ntt(A_hat, y_hat))

                # 6c: Decompose w into high/low parts
                w1 = []
                for i in range(_K):
                    w1_poly = []
                    for j in range(_N):
                        w1_poly.append(_high_bits(w[i][j]))
                    w1.append(w1_poly)

                # 6d: Pack w1 and compute challenge
                w1_packed = bytearray()
                for i in range(_K):
                    w1_packed.extend(_bit_pack(w1[i], 4))
                c_tilde = hashlib.shake_256(mu + bytes(w1_packed)).digest(_C_TILDE_BYTES)
                c = _sample_in_ball(c_tilde)
                c_hat = _ntt(c)

                # 6e: Compute z = y + c*s1
                cs1 = _vec_inv_ntt([_ntt_mult(c_hat, s1_hat[i]) for i in range(_L)])
                z = _vec_add(y, cs1)

                # 6f: Compute r0 = low_bits(w - c*s2)
                cs2 = _vec_inv_ntt([_ntt_mult(c_hat, s2_hat[i]) for i in range(_K)])
                w_minus_cs2 = _vec_sub(w, cs2)

                # 6g: Check z norm bound (branchless — no early exit)
                reject = 0
                _bound_z = _GAMMA1 - _BETA
                for i in range(_L):
                    for j in range(_N):
                        val = z[i][j]
                        neg = 1 + ((val - _HALF_Q - 1) >> 63)
                        val = val - neg * (2 * val - _Q)
                        reject |= 1 + ((val - _bound_z) >> 63)
                if reject:
                    continue

                # 6h: Check ||r0||_inf < gamma2 - beta (branchless)
                reject = 0
                _bound_r0 = _GAMMA2 - _BETA
                for i in range(_K):
                    for j in range(_N):
                        _, r0_val = _decompose(w_minus_cs2[i][j])
                        neg = r0_val >> 63
                        abs_val = (r0_val ^ neg) - neg
                        reject |= 1 + ((abs_val - _bound_r0) >> 63)
                if reject:
                    continue

                # 6i: Compute hint h
                ct0 = _vec_inv_ntt([_ntt_mult(c_hat, t0_hat[i]) for i in range(_K)])
                w_cs2_ct0 = _vec_add(w_minus_cs2, ct0)

                h = [[0] * _N for _ in range(_K)]
                hint_count = 0
                for i in range(_K):
                    for j in range(_N):
                        neg_ct0 = _Q - ct0[i][j]
                        neg_ct0 -= _Q * (1 + ((neg_ct0 - _Q) >> 63))
                        h[i][j] = _make_hint(neg_ct0, w_cs2_ct0[i][j])
                        hint_count += h[i][j]
                if hint_count > _OMEGA:
                    continue

                # 6j: Check ct0 norm bound (branchless)
                reject = 0
                for i in range(_K):
                    for j in range(_N):
                        val = ct0[i][j]
                        neg = 1 + ((val - _HALF_Q - 1) >> 63)
                        val = val - neg * (2 * val - _Q)
                        reject |= 1 + ((val - _GAMMA2) >> 63)
                if reject:
                    continue

                # Success — encode signature
                return _sig_encode(c_tilde, z, h)

            raise RuntimeError(
                f"ML-DSA signing failed after {max_attempts} rejection attempts"
            )
        finally:
            _munlock(rho_prime_buf)
            _secure_zero(rho_prime_buf)
    finally:
        _munlock(sk_buf)
        _secure_zero(sk_buf)


def _ml_verify_internal(message, sig_bytes, pk_bytes):
    """ML-DSA-65 internal verification (Algorithm 8, FIPS 204).

    Verifies pre-processed message M' directly. Use ml_verify() for the
    pure FIPS 204 API with context string support.
    """
    if len(pk_bytes) != _PK_SIZE:
        return False
    if len(sig_bytes) != _SIG_SIZE:
        return False

    # Step 1: Decode public key
    rho, t1 = _pk_decode(pk_bytes)

    # Step 2: Decode signature
    decoded = _sig_decode(sig_bytes)
    if decoded is None:
        return False
    c_tilde, z, h = decoded

    # Step 3: Check z norm bound (branchless — no early exit)
    reject = 0
    _bound_z = _GAMMA1 - _BETA
    for i in range(_L):
        for j in range(_N):
            val = z[i][j]
            # Branchless centered abs: if val > q//2, val = q - val
            neg = 1 + ((val - _HALF_Q - 1) >> 63)
            val = val - neg * (2 * val - _Q)
            # Accumulate: reject if val >= bound
            reject |= 1 + ((val - _bound_z) >> 63)
    if reject:
        return False

    # Step 4: Expand A from rho
    A_hat = _expand_A(rho)

    # Step 5: Compute tr = H(pk) and mu = H(tr || msg)
    tr = hashlib.shake_256(pk_bytes).digest(64)
    mu = hashlib.shake_256(tr + message).digest(64)

    # Step 6: Recompute challenge c from c_tilde
    c = _sample_in_ball(c_tilde)
    c_hat = _ntt(c)

    # Step 7: Compute w'1 = use_hint(h, A*z - c*t1*2^d)
    z_hat = _vec_ntt(z)
    Az = _mat_vec_ntt(A_hat, z_hat)

    # Compute c*t1*2^d in NTT domain
    t1_shifted = []
    for i in range(_K):
        t1_shifted.append([_ct_mod_q(c * (1 << _D)) for c in t1[i]])
    t1_shifted_hat = _vec_ntt(t1_shifted)
    ct1_2d = [_ntt_mult(c_hat, t1_shifted_hat[i]) for i in range(_K)]

    # w' = A*z - c*t1*2^d (in NTT domain, then back)
    w_prime_hat = [_poly_sub(Az[i], ct1_2d[i]) for i in range(_K)]
    w_prime = _vec_inv_ntt(w_prime_hat)

    # Apply hints to recover w'1
    w_prime_1 = []
    hint_count = 0
    for i in range(_K):
        w1_poly = []
        for j in range(_N):
            w1_poly.append(_use_hint(h[i][j], w_prime[i][j]))
            hint_count += h[i][j]
        w_prime_1.append(w1_poly)

    # Check total hint count
    if hint_count > _OMEGA:
        return False

    # Step 8: Pack w'1 and verify challenge
    w1_packed = bytearray()
    for i in range(_K):
        w1_packed.extend(_bit_pack(w_prime_1[i], 4))
    c_tilde_check = hashlib.shake_256(mu + bytes(w1_packed)).digest(_C_TILDE_BYTES)

    return hmac.compare_digest(c_tilde, c_tilde_check)


def ml_sign(message, sk_bytes, ctx=b"", *, deterministic=False, rnd=None):
    """ML-DSA-65 pure signing (Algorithm 2, FIPS 204).

    Builds M' = 0x00 || len(ctx) || ctx || message, then calls the
    internal signing algorithm. This is the FIPS 204 "pure" mode.

    Fault injection countermeasure: verifies the signature before returning.

    Defaults to hedged signing (FIPS 204 recommended). Pass
    deterministic=True for reproducible signatures.

    Args:
        message: Arbitrary-length message bytes.
        sk_bytes: 4,032-byte secret key from ml_keygen.
        ctx: Optional context string (0-255 bytes, default empty).
        deterministic: If True, use rnd=0^32 (no randomness).
        rnd: Explicit 32-byte randomness (overrides deterministic flag).

    Returns:
        Signature bytes (3,309 bytes for ML-DSA-65).

    Raises:
        ValueError: If ctx exceeds 255 bytes or sk_bytes has wrong length.
        RuntimeError: If signing fails after too many rejection attempts,
                      or if verify-after-sign detects a fault.
    """
    if len(ctx) > 255:
        raise ValueError(f"context string must be <= 255 bytes, got {len(ctx)}")
    m_prime = b"\x00" + bytes([len(ctx)]) + ctx + message
    sig = _ml_sign_internal(m_prime, sk_bytes, rnd=rnd, deterministic=deterministic)

    # Verify-after-sign (fault injection countermeasure)
    # Extract pk from sk: rho(32) || K(32) || tr(64) = 128 header,
    # then recompute pk via rho + t1 from the signing computation.
    # Cheaper: decode pk_bytes from sk and verify directly.
    pk_bytes = _pk_from_sk(sk_bytes)
    if not _ml_verify_internal(m_prime, sig, pk_bytes):
        raise RuntimeError("ML-DSA verify-after-sign failed (fault detected)")
    return sig


def ml_verify(message, sig_bytes, pk_bytes, ctx=b""):
    """ML-DSA-65 pure verification (Algorithm 3, FIPS 204).

    Builds M' = 0x00 || len(ctx) || ctx || message, then calls the
    internal verification algorithm. This is the FIPS 204 "pure" mode.

    Args:
        message: Original message bytes.
        sig_bytes: Signature bytes from ml_sign.
        pk_bytes: Public key bytes from ml_keygen.
        ctx: Optional context string (must match what was used for signing).

    Returns:
        True if the signature is valid, False otherwise.
    """
    if len(ctx) > 255:
        return False
    m_prime = b"\x00" + bytes([len(ctx)]) + ctx + message
    return _ml_verify_internal(m_prime, sig_bytes, pk_bytes)
