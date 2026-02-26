# Copyright (c) 2026 Signer — MIT License

"""ML-KEM-768 (Kyber) — FIPS 203 post-quantum key encapsulation mechanism.

Pure-Python implementation of the Module-Lattice-Based Key-Encapsulation
Mechanism Standard (ML-KEM) at Security Level 3 (ML-KEM-768).

Operates over the polynomial ring Z_q[X]/(X^256 + 1) where q = 3329.
Uses NTT (Number Theoretic Transform) for efficient polynomial multiplication.

Key sizes:
    Encapsulation key (EK): 1,184 bytes
    Decapsulation key (DK): 2,400 bytes
    Ciphertext:             1,088 bytes
    Shared secret:             32 bytes

Security: NIST Level 3 (~192-bit post-quantum security).
Assumption: Module Learning With Errors (MLWE) hardness.

Reference: NIST FIPS 203 (August 2024).

Public API:
    ml_kem_keygen(seed)                 -> (ek_bytes, dk_bytes)
    ml_kem_encaps(ek, randomness=None)  -> (ct_bytes, shared_secret)
    ml_kem_decaps(dk, ct)               -> shared_secret

Constant-time hardening:
    All arithmetic on secret-dependent data uses constant-time Barrett
    reduction (replacing Python's variable-time ``%`` and ``//`` operators),
    branchless conditional selection (replacing ``if/else`` on secret values),
    and fixed-width masking to prevent arbitrary-precision integer growth.

    While the CPython interpreter cannot provide hardware-level constant-time
    guarantees (GC pauses, object allocation, dynamic dispatch), this
    implementation eliminates all *algorithmic* timing channels:
      - No data-dependent branches on secret values.
      - No variable-time division/modulus on secret values.
      - No early returns conditioned on secret comparisons.

    Memory hardening (requires PyNaCl / libsodium, optional):
      - sodium_memzero: compiler-resistant wiping of secret intermediates
        (decrypted pre-key, candidate shared secrets, rejection secret, key
        polynomials) in a finally block — secrets are wiped even on exceptions.
      - sodium_mlock:   secret key pages are locked during decapsulation so
        the OS never swaps them to disk (pagefile / swap partition).
      - sodium_munlock:  pages are unlocked + zeroed on cleanup.
      Without PyNaCl installed, falls back to manual byte zeroing (sufficient
      for CPython which does not perform dead-store elimination) and no-op
      for mlock/munlock.

    Implicit rejection: decaps returns J(z || ct) on failure (IND-CCA2 safe).
"""

import hashlib
import hmac
import os

# libsodium (via PyNaCl) for secure memory operations.
# Optional: gracefully degrades when PyNaCl is not installed.
try:
    from nacl._sodium import ffi as _ffi, lib as _lib
    _HAS_SODIUM = True
except ImportError:
    _HAS_SODIUM = False

# ── ML-KEM-768 Parameters (FIPS 203 Table 2) ────────────────────

_Q = 3329              # Prime modulus
_N = 256               # Polynomial degree
_K = 3                 # Module rank (768 = 256 * 3)
_ETA1 = 2              # CBD parameter for secret/error vectors
_ETA2 = 2              # CBD parameter for encryption noise
_DU = 10               # Compression bits for u (ciphertext)
_DV = 4                # Compression bits for v (ciphertext)


# ── NTT Constants ────────────────────────────────────────────────

def _bitrev7(n):
    """Reverse the lower 7 bits of an integer."""
    r = 0
    for _ in range(7):
        r = (r << 1) | (n & 1)
        n >>= 1
    return r


# 17 is a primitive 256th root of unity mod 3329:
# 17^128 ≡ -1 (mod 3329) and 17^256 ≡ 1 (mod 3329).
# Note: there is no primitive 512th root of unity in Z_q for q = 3329.
_ROOT = 17

# Precompute 128 zetas in bit-reversed order (FIPS 203 Section 4.3).
_ZETAS = [pow(_ROOT, _bitrev7(i), _Q) for i in range(128)]

# Multiplicative inverse of 128 mod q (for inverse NTT scaling).
# 128 * 3303 = 422784 = 127 * 3329 + 1 ≡ 1 (mod 3329).
_N_INV = 3303


# ── Hash helpers (SHA-3 family) ──────────────────────────────────

def _sha3_256(data):
    return hashlib.sha3_256(data).digest()

def _sha3_512(data):
    return hashlib.sha3_512(data).digest()

def _shake128(data, length):
    return hashlib.shake_128(data).digest(length)

def _shake256(data, length):
    return hashlib.shake_256(data).digest(length)


# ── Constant-time utilities ──────────────────────────────────────
#
# These primitives eliminate data-dependent timing channels that Python's
# built-in arithmetic operators (%, //) would otherwise introduce.
#
# Barrett reduction replaces variable-time division with fixed-point
# multiplication and a single branchless conditional subtraction.
# Branchless selection replaces if/else on secret-dependent values.

# ── Secure memory utilities (libsodium-backed) ──────────────────
#
# sodium_memzero:  Compiler-resistant secure zeroing — prevents dead-store
#                  elimination that could leave secrets in freed memory.
# sodium_mlock:    Locks pages so the OS never swaps secret key material
#                  to disk (swap partition / pagefile).
# sodium_munlock:  Unlocks + zeros the pages on release.
#
# All helpers degrade gracefully to pure-Python fallbacks when PyNaCl is
# not installed: manual byte zeroing (no DSE risk in CPython) and no-op
# for mlock/munlock.


def _secure_zero(buf):
    """Securely wipe a mutable buffer (bytearray / memoryview).

    Uses libsodium's sodium_memzero when available.  Immutable objects
    (bytes) are silently skipped — callers should use bytearray for
    any secret material that must be wiped.
    """
    if not isinstance(buf, (bytearray, memoryview)):
        return
    n = len(buf)
    if n == 0:
        return
    if _HAS_SODIUM:
        c_buf = _ffi.from_buffer(buf)
        _lib.sodium_memzero(c_buf, n)
    else:
        for i in range(n):
            buf[i] = 0


def _mlock(buf):
    """Lock memory pages to prevent swapping to disk.

    Uses libsodium's sodium_mlock when available.
    No-op when PyNaCl is not installed or buf is immutable.
    """
    if _HAS_SODIUM and isinstance(buf, (bytearray, memoryview)) and len(buf):
        _lib.sodium_mlock(_ffi.from_buffer(buf), len(buf))


def _munlock(buf):
    """Unlock memory pages (also zeros the region).

    Uses libsodium's sodium_munlock when available.
    No-op when PyNaCl is not installed or buf is immutable.
    """
    if _HAS_SODIUM and isinstance(buf, (bytearray, memoryview)) and len(buf):
        _lib.sodium_munlock(_ffi.from_buffer(buf), len(buf))


# Barrett constant: floor(2^25 / 3329) = 10079.
# Verified: 10079 * 3329 = 33,552,991 < 2^25 = 33,554,432.
# Approximation error for x < q^2: x / 2^25 < 11,082,241 / 33,554,432 < 1.
_BARRETT_SHIFT = 25
_BARRETT_MULT = 10079


def _ct_mod_q(x):
    """Constant-time Barrett reduction: x mod q for 0 <= x < q^2.

    Replaces Python's variable-time ``%`` operator with fixed-point
    multiplication to approximate the quotient, followed by a single
    branchless conditional subtraction.

    Valid for inputs in [0, q^2) = [0, 11,082,241).
    """
    t = (x * _BARRETT_MULT) >> _BARRETT_SHIFT
    r = x - t * 3329
    # r is in [0, 2q).  Branchless conditional subtraction:
    r_sub = r - 3329
    # Python's arithmetic right-shift propagates the sign bit.
    # For r < q: r_sub < 0, so (r_sub >> 15) & 1 == 1.
    # For r >= q: r_sub >= 0, so (r_sub >> 15) & 1 == 0.
    # (Safe because |r_sub| < 2^13 < 2^15.)
    sign = (r_sub >> 15) & 1
    mask = (-sign) & 0xFFFF          # 0xFFFF when r < q, 0x0000 otherwise
    return (r & mask) | (r_sub & (mask ^ 0xFFFF))


def _ct_div_q(x):
    """Constant-time floor(x / q) for 0 <= x < 2^22.

    Used by compression to replace variable-time ``//`` division by q.
    Same Barrett approximation with a +1 correction when the quotient
    is underestimated.
    """
    t = (x * _BARRETT_MULT) >> _BARRETT_SHIFT
    r = x - t * 3329
    adj = r - 3329
    # sign == 1 when adj < 0, meaning t is already exact.
    sign = (adj >> 15) & 1
    return t + 1 - sign


def _ct_select_bytes(flag, a, b):
    """Return *a* if flag is truthy, *b* otherwise.  Constant-time.

    Expands *flag* (0/1 or bool) into a per-byte mask without any
    data-dependent branch.  Both *a* and *b* are always fully read.
    """
    f = int(bool(flag)) & 1
    # f=1 → m=0xFF (select a), f=0 → m=0x00 (select b).
    m = ((f - 1) & 0xFF) ^ 0xFF
    nm = m ^ 0xFF
    return bytes((ai & m) | (bi & nm) for ai, bi in zip(a, b))


# ── Polynomial arithmetic ────────────────────────────────────────

def _ntt(f):
    """Forward NTT: polynomial -> NTT domain. In-place on a copy."""
    a = list(f)
    k = 1
    length = 128
    while length >= 2:
        start = 0
        while start < 256:
            zeta = _ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = _ct_mod_q(zeta * a[j + length])
                a[j + length] = _ct_mod_q(a[j] + _Q - t)
                a[j] = _ct_mod_q(a[j] + t)
            start += 2 * length
        length >>= 1
    return a


def _ntt_inv(f):
    """Inverse NTT: NTT domain -> polynomial. In-place on a copy."""
    a = list(f)
    k = 127
    length = 2
    while length <= 128:
        start = 0
        while start < 256:
            zeta = _ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = a[j]
                a[j] = _ct_mod_q(t + a[j + length])
                a[j + length] = _ct_mod_q(
                    zeta * _ct_mod_q(a[j + length] + _Q - t)
                )
            start += 2 * length
        length <<= 1
    return [_ct_mod_q(x * _N_INV) for x in a]


def _basecasemultiply(a0, a1, b0, b1, gamma):
    """Multiply two degree-1 polynomials modulo (X^2 - gamma).

    FIPS 203 Algorithm 12: BaseCaseMultiply.
    (a0 + a1*X)(b0 + b1*X) mod (X^2 - gamma) =
        (a0*b0 + a1*b1*gamma) + (a0*b1 + a1*b0)*X

    Intermediate products are reduced via Barrett reduction to keep
    operands bounded below q^2 at each multiplication step.
    """
    c0 = _ct_mod_q(
        _ct_mod_q(a0 * b0)
        + _ct_mod_q(_ct_mod_q(a1 * b1) * gamma)
    )
    c1 = _ct_mod_q(_ct_mod_q(a0 * b1) + _ct_mod_q(a1 * b0))
    return c0, c1


def _multiply_ntts(f, g):
    """Pointwise multiply two NTT-domain polynomials.

    FIPS 203 Algorithm 13: MultiplyNTTs.
    The NTT domain consists of 128 pairs, each evaluated at a root.
    """
    h = [0] * 256
    for i in range(64):
        z0 = _ZETAS[64 + i]
        # First pair: gamma = zeta
        h[4*i], h[4*i+1] = _basecasemultiply(
            f[4*i], f[4*i+1], g[4*i], g[4*i+1], z0)
        # Second pair: gamma = -zeta (constant-time negation mod q)
        h[4*i+2], h[4*i+3] = _basecasemultiply(
            f[4*i+2], f[4*i+3], g[4*i+2], g[4*i+3],
            _ct_mod_q(_Q - z0))
    return h


def _poly_add(a, b):
    return [_ct_mod_q(a[i] + b[i]) for i in range(256)]


def _poly_sub(a, b):
    # Add _Q before subtracting to keep the value non-negative for Barrett.
    return [_ct_mod_q(a[i] + _Q - b[i]) for i in range(256)]


# ── Byte encoding / decoding ────────────────────────────────────

def _byte_encode(f, d):
    """FIPS 203 Algorithm 5: ByteEncode_d.

    Encode 256 integers into a byte string.  For d < 12 the coefficients
    are masked to d bits (constant-time); for d = 12 they are reduced
    mod q via Barrett reduction.

    Uses an integer bit-accumulator instead of materialising a bit list.
    """
    mask = (1 << d) - 1
    total_bits = 256 * d
    acc = 0          # running bit-accumulator
    bit_pos = 0      # current bit position in acc
    for coeff in f:
        # Branch on d (public parameter, not secret data).
        val = _ct_mod_q(coeff) if d == 12 else (coeff & mask)
        acc |= val << bit_pos
        bit_pos += d
    return bytes(acc.to_bytes((total_bits + 7) // 8, "little"))


def _byte_decode(data, d):
    """FIPS 203 Algorithm 6: ByteDecode_d.

    Decode a byte string into 256 integers.  For d < 12 the values are
    masked to d bits; for d = 12 they are reduced mod q via Barrett
    reduction.

    Uses an integer bit-accumulator instead of materialising a bit list.
    """
    expected = (256 * d + 7) // 8
    if len(data) != expected:
        raise ValueError(
            f"ByteDecode_{d}: expected {expected} bytes, got {len(data)}"
        )
    mask = (1 << d) - 1
    acc = int.from_bytes(data, "little")
    f = []
    for _ in range(256):
        raw = acc & mask
        f.append(_ct_mod_q(raw) if d == 12 else raw)
        acc >>= d
    return f


# ── Sampling ─────────────────────────────────────────────────────

def _sample_ntt(seed, i, j):
    """FIPS 203 Algorithm 7: SampleNTT. Rejection-sample a polynomial in NTT domain.

    Uses XOF = SHAKE-128(seed || j || i) to produce uniform coefficients mod q.
    Note: FIPS 203 uses (j, i) order for the matrix indices.

    Timing note: rejection sampling operates on *public* randomness (rho is
    part of the encapsulation key), so data-dependent loop counts do not
    leak secret information.
    """
    xof_input = seed + bytes([j, i])
    # Generate enough bytes (conservative: ~960 bytes for 256 coefficients)
    buf = _shake128(xof_input, 960)
    coeffs = []
    pos = 0
    while len(coeffs) < 256:
        if pos + 3 > len(buf):
            buf = _shake128(xof_input, len(buf) * 2)
        d1 = buf[pos] | ((buf[pos + 1] & 0x0f) << 8)
        d2 = (buf[pos + 1] >> 4) | (buf[pos + 2] << 4)
        pos += 3
        if d1 < _Q:
            coeffs.append(d1)
        if d2 < _Q and len(coeffs) < 256:
            coeffs.append(d2)
    return coeffs


def _sample_cbd(data, eta):
    """FIPS 203 Algorithm 8: SamplePolyCBD_eta. Centered binomial distribution.

    For eta=2: each coefficient = (b0+b1) - (b2+b3) where b_i are individual bits.

    Uses byte-wise popcount rather than expanding into a per-bit list.
    The subtraction is offset by +q to keep the value non-negative for
    constant-time Barrett reduction.
    """
    # Convert input bytes to a single integer for fast bit extraction
    stream = int.from_bytes(data, "little")
    bits_per_coeff = 2 * eta  # 4 bits per coefficient for eta=2

    f = []
    for _ in range(256):
        chunk = stream & ((1 << bits_per_coeff) - 1)
        stream >>= bits_per_coeff
        # popcount of lower eta bits minus popcount of upper eta bits
        a_half = chunk & ((1 << eta) - 1)
        b_half = chunk >> eta
        a_sum = a_half.bit_count()
        b_sum = b_half.bit_count()
        # Add _Q before subtraction to keep non-negative for Barrett.
        f.append(_ct_mod_q(a_sum + _Q - b_sum))
    return f


# ── Compression / decompression ──────────────────────────────────

def _compress(x, d):
    """Compress: round(2^d / q * x) mod 2^d.  Constant-time.

    Uses Barrett division (_ct_div_q) instead of Python's variable-time
    ``//`` operator.  The final mod 2^d is a constant-time bit-mask.
    """
    m = 1 << d
    numerator = x * m + (_Q >> 1)
    return _ct_div_q(numerator) & (m - 1)


def _decompress(y, d):
    """Decompress: round(q / 2^d * y).

    Division by 2^d is a constant-time right-shift.
    """
    m = 1 << d
    return (y * _Q + (m >> 1)) >> d


def _compress_poly(f, d):
    return [_compress(c, d) for c in f]


def _decompress_poly(f, d):
    return [_decompress(c, d) for c in f]


# ── K-PKE (Internal PKE scheme) ─────────────────────────────────

def _k_pke_keygen(d):
    """FIPS 203 Algorithm 14: K-PKE.KeyGen.

    Args:
        d: 32-byte seed.

    Returns:
        (ek_pke, dk_pke): Encryption key and decryption key bytes.
    """
    rho_sigma = _sha3_512(d + bytes([_K]))
    rho, sigma = rho_sigma[:32], rho_sigma[32:]

    # Generate matrix A (k x k) in NTT domain
    A_hat = [[None] * _K for _ in range(_K)]
    for i in range(_K):
        for j in range(_K):
            A_hat[i][j] = _sample_ntt(rho, i, j)

    # Generate secret vector s
    s = []
    for i in range(_K):
        prf_out = _shake256(sigma + bytes([i]), 64 * _ETA1)
        s.append(_ntt(_sample_cbd(prf_out, _ETA1)))

    # Generate error vector e
    e = []
    for i in range(_K):
        prf_out = _shake256(sigma + bytes([_K + i]), 64 * _ETA1)
        e.append(_ntt(_sample_cbd(prf_out, _ETA1)))

    # t_hat = A_hat * s + e (all in NTT domain)
    t_hat = []
    for i in range(_K):
        acc = [0] * 256
        for j in range(_K):
            prod = _multiply_ntts(A_hat[i][j], s[j])
            acc = _poly_add(acc, prod)
        t_hat.append(_poly_add(acc, e[i]))

    # Encode keys
    ek_parts = [_byte_encode(t_hat[i], 12) for i in range(_K)]
    ek_parts.append(rho)
    ek_pke = b"".join(ek_parts)

    dk_pke = b"".join(_byte_encode(s[i], 12) for i in range(_K))

    return ek_pke, dk_pke


def _k_pke_encrypt(ek_pke, m, r):
    """FIPS 203 Algorithm 15: K-PKE.Encrypt.

    Args:
        ek_pke: Encryption key bytes (1,184 bytes).
        m: 32-byte message (the pre-key).
        r: 32-byte randomness.

    Returns:
        ct: Ciphertext bytes (1,088 bytes).
    """
    # Decode encryption key
    t_hat = []
    for i in range(_K):
        t_hat.append(_byte_decode(ek_pke[384*i:384*(i+1)], 12))
    rho = ek_pke[384*_K:]

    # Re-generate matrix A_hat (transposed access)
    A_hat_T = [[None] * _K for _ in range(_K)]
    for i in range(_K):
        for j in range(_K):
            A_hat_T[i][j] = _sample_ntt(rho, j, i)

    # Generate vectors r_vec, e1, e2
    r_vec = []
    for i in range(_K):
        prf_out = _shake256(r + bytes([i]), 64 * _ETA1)
        r_vec.append(_ntt(_sample_cbd(prf_out, _ETA1)))

    e1 = []
    for i in range(_K):
        prf_out = _shake256(r + bytes([_K + i]), 64 * _ETA2)
        e1.append(_sample_cbd(prf_out, _ETA2))

    prf_out = _shake256(r + bytes([2 * _K]), 64 * _ETA2)
    e2 = _sample_cbd(prf_out, _ETA2)

    # u = NTT^{-1}(A^T * r_vec) + e1
    u = []
    for i in range(_K):
        acc = [0] * 256
        for j in range(_K):
            prod = _multiply_ntts(A_hat_T[i][j], r_vec[j])
            acc = _poly_add(acc, prod)
        u.append(_poly_add(_ntt_inv(acc), e1[i]))

    # v = NTT^{-1}(t_hat . r_vec) + e2 + Decompress(Decode(m), 1)
    v_acc = [0] * 256
    for i in range(_K):
        prod = _multiply_ntts(t_hat[i], r_vec[i])
        v_acc = _poly_add(v_acc, prod)
    v = _poly_add(_ntt_inv(v_acc), e2)

    # Decode message as polynomial and add
    m_poly = _decompress_poly(_byte_decode(m, 1), 1)
    v = _poly_add(v, m_poly)

    # Compress and encode ciphertext
    c1 = b"".join(_byte_encode(_compress_poly(u[i], _DU), _DU) for i in range(_K))
    c2 = _byte_encode(_compress_poly(v, _DV), _DV)

    return c1 + c2


def _k_pke_decrypt(dk_pke, ct):
    """FIPS 203 Algorithm 16: K-PKE.Decrypt.

    Args:
        dk_pke: Decryption key bytes.
        ct: Ciphertext bytes (1,088 bytes).

    Returns:
        m: 32-byte message (the pre-key).
    """
    # Split ciphertext
    du_bytes = 32 * _DU  # 320 bytes per polynomial
    c1 = ct[:du_bytes * _K]  # 960 bytes
    c2 = ct[du_bytes * _K:]  # 128 bytes

    # Decode u (compressed)
    u = []
    for i in range(_K):
        u_compressed = _byte_decode(c1[du_bytes*i:du_bytes*(i+1)], _DU)
        u.append(_decompress_poly(u_compressed, _DU))

    # Decode v (compressed)
    v_compressed = _byte_decode(c2, _DV)
    v = _decompress_poly(v_compressed, _DV)

    # Decode secret key
    s_hat = []
    for i in range(_K):
        s_hat.append(_byte_decode(dk_pke[384*i:384*(i+1)], 12))

    # w = v - NTT^{-1}(s_hat . NTT(u))
    inner = [0] * 256
    for i in range(_K):
        u_hat = _ntt(u[i])
        prod = _multiply_ntts(s_hat[i], u_hat)
        inner = _poly_add(inner, prod)
    w = _poly_sub(v, _ntt_inv(inner))

    # Compress to 1-bit and encode
    return _byte_encode(_compress_poly(w, 1), 1)


# ── FIPS 203 Input Validation (§7.1, §7.2) ──────────────────────

def _ek_modulus_check(ek: bytes) -> bool:
    """FIPS 203 §7.1: Encapsulation key modulus check.

    Verifies every 12-bit coefficient in t_hat encodes a value in [0, q-1]
    by decoding and re-encoding each polynomial and comparing to the original.
    """
    if len(ek) != 1184:
        return False
    t_part = ek[:384 * _K]
    canonical = b"".join(
        _byte_encode(_byte_decode(t_part[384 * i:384 * (i + 1)], 12), 12)
        for i in range(_K)
    )
    return hmac.compare_digest(canonical, t_part)


def _dk_hash_check(dk: bytes) -> bool:
    """FIPS 203 §7.2: Decapsulation key hash check.

    Verifies H(ek) stored inside dk matches a fresh hash of the embedded ek.
    """
    if len(dk) != 2400:
        return False
    ek = dk[384 * _K:384 * _K + 1184]
    h_stored = dk[384 * _K + 1184:384 * _K + 1184 + 32]
    return hmac.compare_digest(_sha3_256(ek), h_stored)


# ── Public API ───────────────────────────────────────────────────

def ml_kem_keygen(seed=None):
    """Generate ML-KEM-768 keypair.

    FIPS 203 Algorithm 19: ML-KEM.KeyGen_internal.

    Args:
        seed: 64-byte seed (d || z). If None, generates randomly.
              d (first 32 bytes): seed for K-PKE key generation.
              z (last 32 bytes): implicit rejection secret.

    Returns:
        (ek_bytes, dk_bytes): Encapsulation key (1,184 bytes) and
                              decapsulation key (2,400 bytes).
    """
    if seed is None:
        seed = os.urandom(64)
    if len(seed) != 64:
        raise ValueError(f"ML-KEM-768 keygen requires 64-byte seed, got {len(seed)}")

    d, z = seed[:32], seed[32:]

    ek_pke, dk_pke = _k_pke_keygen(d)

    # DK = dk_pke || ek_pke || H(ek_pke) || z
    h_ek = _sha3_256(ek_pke)
    dk = dk_pke + ek_pke + h_ek + z

    if len(ek_pke) != 1184:
        raise RuntimeError(f"ML-KEM-768 EK must be 1184 bytes, got {len(ek_pke)}")
    if len(dk) != 2400:
        raise RuntimeError(f"ML-KEM-768 DK must be 2400 bytes, got {len(dk)}")

    return ek_pke, dk


def ml_kem_encaps(ek, randomness=None):
    """Encapsulate: produce a ciphertext and shared secret.

    FIPS 203 Algorithm 17: ML-KEM.Encaps (full checked API).
    Performs the §7.1 modulus check on ek, then runs Encaps_internal.

    Args:
        ek: 1,184-byte encapsulation key.
        randomness: 32-byte randomness m. If None, generates randomly.

    Returns:
        (ct, shared_secret): Ciphertext (1,088 bytes) and shared secret (32 bytes).

    Raises:
        ValueError: If ek fails the FIPS 203 modulus check.
    """
    if not _ek_modulus_check(ek):
        raise ValueError("Encapsulation key failed FIPS 203 modulus check (§7.1)")

    if randomness is None:
        randomness = os.urandom(32)
    if len(randomness) != 32:
        raise ValueError(f"ML-KEM-768 encaps randomness must be 32 bytes, got {len(randomness)}")

    m = randomness

    # (K, r) = G(m || H(ek))
    h_ek = _sha3_256(ek)
    g_input = m + h_ek
    g_output = _sha3_512(g_input)
    K, r = g_output[:32], g_output[32:]

    ct = _k_pke_encrypt(ek, m, r)

    if len(ct) != 1088:
        raise RuntimeError(f"ML-KEM-768 ciphertext must be 1088 bytes, got {len(ct)}")

    return ct, K


def ml_kem_decaps(dk, ct):
    """Decapsulate: recover the shared secret from a ciphertext.

    FIPS 203 Algorithm 18: ML-KEM.Decaps (full checked API).
    Performs the §7.2 hash check on dk, then runs Decaps_internal
    with implicit rejection for IND-CCA2 security.

    Constant-time: the comparison result is used via branchless
    _ct_select_bytes rather than an if/else branch, ensuring both
    code paths execute in identical time.

    Args:
        dk: 2,400-byte decapsulation key.
        ct: 1,088-byte ciphertext.

    Returns:
        shared_secret: 32-byte shared secret.

    Raises:
        ValueError: If ct or dk fails FIPS 203 input checks.
    """
    if len(ct) != 1088:
        raise ValueError(f"ML-KEM-768 decaps requires 1088-byte CT, got {len(ct)}")
    if not _dk_hash_check(dk):
        raise ValueError("Decapsulation key failed FIPS 203 hash check (§7.2)")

    # Parse DK = dk_pke || ek_pke || h || z
    # Secret components use bytearray so they can be securely wiped.
    dk_pke = bytearray(dk[:384*_K])           # 1152 bytes — SECRET
    ek_pke = dk[384*_K:384*_K+1184]           # 1184 bytes — public
    h = dk[384*_K+1184:384*_K+1184+32]        # 32 bytes   — public hash
    z = bytearray(dk[384*_K+1184+32:])        # 32 bytes   — SECRET

    # Lock secret pages to prevent swapping to disk.
    _mlock(dk_pke)
    _mlock(z)

    # All secret intermediates are bytearray for secure wiping.
    m_prime = bytearray()
    g_output = bytearray()
    K_prime = bytearray()
    r_prime = bytearray()
    K_bar = bytearray()
    try:
        # Decrypt to recover m'
        m_prime = bytearray(_k_pke_decrypt(bytes(dk_pke), ct))

        # (K', r') = G(m' || h)
        g_output = bytearray(_sha3_512(bytes(m_prime) + h))
        K_prime = bytearray(g_output[:32])
        r_prime = bytearray(g_output[32:])

        # Implicit rejection value (always computed).
        K_bar = bytearray(_shake256(bytes(z) + ct, 32))

        # Re-encrypt to verify ciphertext integrity.
        ct_prime = _k_pke_encrypt(ek_pke, bytes(m_prime), bytes(r_prime))

        # Constant-time selection: return K_prime if ct == ct_prime, else K_bar.
        # hmac.compare_digest is C-backed constant-time comparison.
        # _ct_select_bytes is branchless — no if/else on the secret flag.
        flag = hmac.compare_digest(ct, ct_prime)
        return _ct_select_bytes(flag, bytes(K_prime), bytes(K_bar))
    finally:
        # Wipe ALL secret intermediates — the non-selected key is especially
        # sensitive since it must never be observable by an attacker.
        _secure_zero(m_prime)
        _secure_zero(g_output)
        _secure_zero(K_prime)
        _secure_zero(r_prime)
        _secure_zero(K_bar)
        # Unlock + zero the secret key components.
        _munlock(dk_pke)
        _munlock(z)
        _secure_zero(dk_pke)
        _secure_zero(z)
