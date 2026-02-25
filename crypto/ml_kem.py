# Copyright (c) 2026 Signer.io — PolyForm Shield License 1.0.0

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

Notes:
    - NOT constant-time: Python arithmetic leaks timing information. For
      deployments where side-channel attacks are a concern, use a vetted
      constant-time C/Rust implementation instead.
    - Implicit rejection: decaps returns J(z || ct) on failure (IND-CCA2 safe).
"""

import hashlib
import hmac
import os

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


# ── Hash helpers (SHA-3 family) ──────────────────────────────────

def _sha3_256(data):
    return hashlib.sha3_256(data).digest()

def _sha3_512(data):
    return hashlib.sha3_512(data).digest()

def _shake128(data, length):
    return hashlib.shake_128(data).digest(length)

def _shake256(data, length):
    return hashlib.shake_256(data).digest(length)


# ── Polynomial arithmetic ────────────────────────────────────────

def _ntt(f):
    """Forward NTT: polynomial → NTT domain. In-place on a copy."""
    a = list(f)
    k = 1
    length = 128
    while length >= 2:
        start = 0
        while start < 256:
            zeta = _ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * a[j + length]) % _Q
                a[j + length] = (a[j] - t) % _Q
                a[j] = (a[j] + t) % _Q
            start += 2 * length
        length >>= 1
    return a


def _ntt_inv(f):
    """Inverse NTT: NTT domain → polynomial. In-place on a copy."""
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
                a[j] = (t + a[j + length]) % _Q
                a[j + length] = (zeta * (a[j + length] - t)) % _Q
            start += 2 * length
        length <<= 1
    # Multiply by 128^{-1} mod q = 3303.
    # ML-KEM NTT has 7 levels (len=128 down to len=2), factor is 2^7 = 128.
    n_inv = pow(128, _Q - 2, _Q)  # 3303
    return [(x * n_inv) % _Q for x in a]


def _basecasemultiply(a0, a1, b0, b1, gamma):
    """Multiply two degree-1 polynomials modulo (X^2 - gamma).

    FIPS 203 Algorithm 12: BaseCaseMultiply.
    (a0 + a1*X)(b0 + b1*X) mod (X^2 - gamma) =
        (a0*b0 + a1*b1*gamma) + (a0*b1 + a1*b0)*X
    """
    c0 = (a0 * b0 + a1 * b1 * gamma) % _Q
    c1 = (a0 * b1 + a1 * b0) % _Q
    return c0, c1


def _multiply_ntts(f, g):
    """Pointwise multiply two NTT-domain polynomials.

    FIPS 203 Algorithm 13: MultiplyNTTs.
    The NTT domain consists of 128 pairs, each evaluated at a root.
    """
    h = [0] * 256
    for i in range(64):
        z0 = _ZETAS[64 + i]
        # First pair: indices 2i, 2i+1 with gamma = zeta^(2*bitrev7(i)+1)
        h[4*i], h[4*i+1] = _basecasemultiply(
            f[4*i], f[4*i+1], g[4*i], g[4*i+1], z0)
        # Second pair: indices 2i+128, 2i+129 with gamma = -zeta
        h[4*i+2], h[4*i+3] = _basecasemultiply(
            f[4*i+2], f[4*i+3], g[4*i+2], g[4*i+3], (-z0) % _Q)
    return h


def _poly_add(a, b):
    return [(a[i] + b[i]) % _Q for i in range(256)]


def _poly_sub(a, b):
    return [(a[i] - b[i]) % _Q for i in range(256)]


# ── Byte encoding / decoding ────────────────────────────────────

def _byte_encode(f, d):
    """FIPS 203 Algorithm 5: ByteEncode_d.

    Encode 256 integers into a byte string.  For d < 12 the coefficients
    are taken mod 2^d; for d = 12 they are elements of Z_q (mod 3329).

    Uses an integer bit-accumulator instead of materialising a bit list.
    """
    m = (1 << d) if d < 12 else _Q
    total_bits = 256 * d
    acc = 0          # running bit-accumulator
    bit_pos = 0      # current bit position in acc
    for coeff in f:
        acc |= (coeff % m) << bit_pos
        bit_pos += d
    out = bytearray(acc.to_bytes((total_bits + 7) // 8, "little"))
    return bytes(out)


def _byte_decode(data, d):
    """FIPS 203 Algorithm 6: ByteDecode_d.

    Decode a byte string into 256 integers.  For d < 12 the values are
    reduced mod 2^d; for d = 12 they are reduced mod q (elements of Z_q).

    Uses an integer bit-accumulator instead of materialising a bit list.
    """
    expected = (256 * d + 7) // 8
    if len(data) != expected:
        raise ValueError(
            f"ByteDecode_{d}: expected {expected} bytes, got {len(data)}"
        )
    m = (1 << d) if d < 12 else _Q
    mask = (1 << d) - 1
    acc = int.from_bytes(data, "little")
    f = []
    for _ in range(256):
        f.append((acc & mask) % m)
        acc >>= d
    return f


# ── Sampling ─────────────────────────────────────────────────────

def _sample_ntt(seed, i, j):
    """FIPS 203 Algorithm 7: SampleNTT. Rejection-sample a polynomial in NTT domain.

    Uses XOF = SHAKE-128(seed || j || i) to produce uniform coefficients mod q.
    Note: FIPS 203 uses (j, i) order for the matrix indices.
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
        a_sum = bin(a_half).count("1")
        b_sum = bin(b_half).count("1")
        f.append((a_sum - b_sum) % _Q)
    return f


# ── Compression / decompression ──────────────────────────────────

def _compress(x, d):
    """Compress: round(2^d / q * x) mod 2^d."""
    m = 1 << d
    return ((x * m + _Q // 2) // _Q) % m


def _decompress(y, d):
    """Decompress: round(q / 2^d * y)."""
    m = 1 << d
    return (y * _Q + m // 2) // m


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
    ek_pke = b""
    for i in range(_K):
        ek_pke += _byte_encode(t_hat[i], 12)
    ek_pke += rho

    dk_pke = b""
    for i in range(_K):
        dk_pke += _byte_encode(s[i], 12)

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
    c1 = b""
    for i in range(_K):
        c1 += _byte_encode(_compress_poly(u[i], _DU), _DU)
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
    dk_pke = dk[:384*_K]           # 1152 bytes
    ek_pke = dk[384*_K:384*_K+1184]  # 1184 bytes
    h = dk[384*_K+1184:384*_K+1184+32]  # 32 bytes
    z = dk[384*_K+1184+32:]        # 32 bytes

    # Decrypt to recover m'
    m_prime = _k_pke_decrypt(dk_pke, ct)

    # (K', r') = G(m' || h)
    g_output = _sha3_512(m_prime + h)
    K_prime, r_prime = g_output[:32], g_output[32:]

    # Re-encrypt and compare (implicit rejection).
    # Note on side-channel hardening: hmac.compare_digest is constant-time,
    # but the Python-level if/else branch itself is a timing signal (the two
    # paths may take different time).  A constant-time C/Rust implementation
    # would use ct_select(flag, K_prime, K_bar) instead.  In pure Python,
    # true constant-time selection is not achievable, so we accept this
    # limitation and document it here for auditors.
    K_bar = _shake256(z + ct, 32)
    ct_prime = _k_pke_encrypt(ek_pke, m_prime, r_prime)

    if hmac.compare_digest(ct, ct_prime):
        return K_prime
    return K_bar
