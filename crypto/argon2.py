# Copyright (c) 2026 Signer — MIT License

"""Argon2id (RFC 9106) — Pure Python, zero dependencies.

Provides a fallback when argon2-cffi is not installed. Uses Blake2b for
hashing and the fBlaMka compression function per the RFC 9106 spec.

Performance note: the C library (argon2-cffi) is ~100x faster. This
module exists so the wallet works without compiled dependencies — the
wrapper in this package auto-selects the faster backend when available.
"""

import struct

# ── Constants ────────────────────────────────────────────────────

BLOCK_BYTES = 1024
BLOCK_U32 = 256       # 1024 / 4
BLOCK_U64 = 128       # 1024 / 8
SYNC_POINTS = 4
MASK32 = 0xFFFFFFFF
MASK64 = (1 << 64) - 1

# ── Little-endian helpers ────────────────────────────────────────

def _le32(n):
    return struct.pack("<I", n & MASK32)


def _load_block(data, offset=0):
    """Load 1024 bytes into a list of 256 uint32 values."""
    block = [0] * BLOCK_U32
    for i in range(BLOCK_U32):
        p = offset + i * 4
        block[i] = (data[p] | (data[p + 1] << 8) |
                    (data[p + 2] << 16) | (data[p + 3] << 24)) & MASK32
    return block


def _store_block(block):
    """Store 256 uint32 values as 1024 bytes."""
    out = bytearray(BLOCK_BYTES)
    for i in range(BLOCK_U32):
        v = block[i]
        p = i * 4
        out[p] = v & 0xFF
        out[p + 1] = (v >> 8) & 0xFF
        out[p + 2] = (v >> 16) & 0xFF
        out[p + 3] = (v >> 24) & 0xFF
    return bytes(out)


# ── Blake2b (pure Python, 64-bit integers) ──────────────────────

_B2B_IV = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
]

_SIGMA = [
    [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
    [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
    [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
    [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
    [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
    [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
    [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
    [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
    [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
    [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
]


def _b2b_g(v, a, b, c, d, x, y):
    v[a] = (v[a] + v[b] + x) & MASK64
    t = (v[d] ^ v[a]) & MASK64
    v[d] = (t >> 32 | t << 32) & MASK64
    v[c] = (v[c] + v[d]) & MASK64
    t = (v[b] ^ v[c]) & MASK64
    v[b] = (t >> 24 | t << 40) & MASK64
    v[a] = (v[a] + v[b] + y) & MASK64
    t = (v[d] ^ v[a]) & MASK64
    v[d] = (t >> 16 | t << 48) & MASK64
    v[c] = (v[c] + v[d]) & MASK64
    t = (v[b] ^ v[c]) & MASK64
    v[b] = (t >> 63 | t << 1) & MASK64


def _b2b_compress(h, data, off, t, last):
    m = [0] * 16
    for i in range(16):
        p = off + i * 8
        lo = (data[p] | (data[p + 1] << 8) |
              (data[p + 2] << 16) | (data[p + 3] << 24)) & MASK32
        hi = (data[p + 4] | (data[p + 5] << 8) |
              (data[p + 6] << 16) | (data[p + 7] << 24)) & MASK32
        m[i] = (hi << 32) | lo

    v = list(h) + list(_B2B_IV)
    v[12] ^= t & MASK64
    if last:
        v[14] ^= MASK64

    for r in range(12):
        s = _SIGMA[r % 10]
        _b2b_g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
        _b2b_g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
        _b2b_g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
        _b2b_g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
        _b2b_g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
        _b2b_g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
        _b2b_g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
        _b2b_g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])

    for i in range(8):
        h[i] = (h[i] ^ v[i] ^ v[8 + i]) & MASK64


def blake2b(data, out_len):
    """Blake2b hash with variable output length."""
    if isinstance(data, (bytes, bytearray)):
        data = memoryview(data)
    h = list(_B2B_IV)
    h[0] ^= 0x01010000 | out_len
    t = 0
    pos = 0
    data_len = len(data)

    while data_len - pos > 128:
        t += 128
        _b2b_compress(h, data, pos, t, False)
        pos += 128

    t += data_len - pos
    last = bytearray(128)
    remaining = data_len - pos
    if remaining > 0:
        last[:remaining] = data[pos:]
    _b2b_compress(h, last, 0, t, True)

    out = bytearray(out_len)
    for i in range(min(8, (out_len + 7) // 8)):
        for j in range(8):
            if i * 8 + j < out_len:
                out[i * 8 + j] = (h[i] >> (j * 8)) & 0xFF
    return bytes(out)


# ── H' variable-length hash (RFC 9106 §3.2) ─────────────────────

def _argon2_hash(data, out_len):
    """Variable-length hash H'(data) per RFC 9106."""
    if out_len <= 64:
        return blake2b(_le32(out_len) + bytes(data), out_len)

    r = -(-out_len // 32) - 2  # ceil(out_len / 32) - 2
    parts = []
    prev = blake2b(_le32(out_len) + bytes(data), 64)
    parts.append(prev[:32])
    for _ in range(r - 1):
        prev = blake2b(prev, 64)
        parts.append(prev[:32])
    prev = blake2b(prev, out_len - 32 * r)
    parts.append(prev)
    return b"".join(parts)


# ── Argon2 compression (fBlaMka + permutation) ──────────────────

def _mul_lo(a, b):
    """Lower 32 bits of a * b (both treated as unsigned 32-bit)."""
    return ((a & MASK32) * (b & MASK32)) & MASK32


def _mul_hi(a, b):
    """Upper 32 bits of a * b (both treated as unsigned 32-bit)."""
    return (((a & MASK32) * (b & MASK32)) >> 32) & MASK32


def _fBlaMka(v, ai, bi):
    """fBlaMka: v[ai] += v[bi] + 2 * trunc(v[ai]) * trunc(v[bi])"""
    a_lo = v[ai] & MASK32
    b_lo = v[bi] & MASK32
    # 2 * lo(a) * lo(b) as 64-bit, split into hi:lo pair
    prod = a_lo * b_lo  # fits in Python int, no overflow
    p_lo = (prod << 1) & MASK32
    p_hi = ((prod << 1) >> 32) & MASK32

    # v[ai] = v[ai] + v[bi] (as 64-bit stored in two u32 slots)
    orig_lo = v[ai] & MASK32
    s_lo = (orig_lo + (v[bi] & MASK32)) & MASK32
    carry = 1 if s_lo < orig_lo else 0
    s_hi = (v[ai + 1] + v[bi + 1] + carry) & MASK32

    # Add the 2*trunc product
    v[ai] = (s_lo + p_lo) & MASK32
    carry2 = 1 if v[ai] < s_lo else 0
    v[ai + 1] = (s_hi + p_hi + carry2) & MASK32


def _xor_rotr(v, di, ai, n):
    """XOR and rotate right by n bits (64-bit value stored as two u32)."""
    lo = (v[di] ^ v[ai]) & MASK32
    hi = (v[di + 1] ^ v[ai + 1]) & MASK32
    if n == 32:
        v[di] = hi
        v[di + 1] = lo
    elif n == 24:
        v[di] = ((lo >> 24) | (hi << 8)) & MASK32
        v[di + 1] = ((hi >> 24) | (lo << 8)) & MASK32
    elif n == 16:
        v[di] = ((lo >> 16) | (hi << 16)) & MASK32
        v[di + 1] = ((hi >> 16) | (lo << 16)) & MASK32
    elif n == 63:
        v[di] = ((lo << 1) | (hi >> 31)) & MASK32
        v[di + 1] = ((hi << 1) | (lo >> 31)) & MASK32


def _GB(v, a, b, c, d):
    _fBlaMka(v, a, b); _xor_rotr(v, d, a, 32)
    _fBlaMka(v, c, d); _xor_rotr(v, b, c, 24)
    _fBlaMka(v, a, b); _xor_rotr(v, d, a, 16)
    _fBlaMka(v, c, d); _xor_rotr(v, b, c, 63)


def _blamka_round(v, i0, i1, i2, i3, i4, i5, i6, i7,
                  i8, i9, i10, i11, i12, i13, i14, i15):
    _GB(v, i0, i4, i8, i12)
    _GB(v, i1, i5, i9, i13)
    _GB(v, i2, i6, i10, i14)
    _GB(v, i3, i7, i11, i15)
    _GB(v, i0, i5, i10, i15)
    _GB(v, i1, i6, i11, i12)
    _GB(v, i2, i7, i8, i13)
    _GB(v, i3, i4, i9, i14)


def _argon2_compress(state, ref, out, with_xor):
    """Compress: out = state XOR ref, run permutation, XOR result."""
    R = [state[i] ^ ref[i] for i in range(BLOCK_U32)]
    if with_xor:
        tmp = [R[i] ^ out[i] for i in range(BLOCK_U32)]
    else:
        tmp = list(R)

    # Row-wise permutation (8 rows of 128 bytes = 32 u32)
    for i in range(8):
        b = i * 32
        _blamka_round(R, b,b+2,b+4,b+6,b+8,b+10,b+12,b+14,
                      b+16,b+18,b+20,b+22,b+24,b+26,b+28,b+30)
    # Column-wise permutation
    for i in range(8):
        b = i * 4
        _blamka_round(R, b,b+2,b+32,b+34,b+64,b+66,b+96,b+98,
                      b+128,b+130,b+160,b+162,b+192,b+194,b+224,b+226)

    for i in range(BLOCK_U32):
        out[i] = tmp[i] ^ R[i]


# ── Argon2 indexing ──────────────────────────────────────────────

def _index_alpha(pass_, slice_, index, seg_len, lane_len, pseudo_rand, same_lane):
    if pass_ == 0:
        if slice_ == 0:
            ref_area = index - 1
        else:
            ref_area = (slice_ * seg_len + index - 1 if same_lane
                        else slice_ * seg_len + (-1 if index == 0 else 0))
    else:
        ref_area = (lane_len - seg_len + index - 1 if same_lane
                    else lane_len - seg_len + (-1 if index == 0 else 0))

    x = _mul_hi(pseudo_rand, pseudo_rand)
    y = _mul_hi(ref_area & MASK32, x)
    rel_pos = ref_area - 1 - y

    start_pos = 0
    if pass_ != 0:
        start_pos = 0 if slice_ == SYNC_POINTS - 1 else (slice_ + 1) * seg_len

    return (start_pos + rel_pos) % lane_len


# ── Segment filling ──────────────────────────────────────────────

def _generate_addresses(seg_len, pass_, lane, slice_, mem_blocks, passes):
    pseudo_rands = [0] * (seg_len * 2)
    zero_block = [0] * BLOCK_U32
    input_block = [0] * BLOCK_U32
    address_block = [0] * BLOCK_U32

    input_block[0] = pass_
    input_block[2] = lane
    input_block[4] = slice_
    input_block[6] = mem_blocks
    input_block[8] = passes
    input_block[10] = 2  # Argon2id type

    for i in range(seg_len):
        if i % BLOCK_U64 == 0:
            input_block[12] = (input_block[12] + 1) & MASK32
            address_block = [0] * BLOCK_U32
            _argon2_compress(zero_block, input_block, address_block, False)
            _argon2_compress(zero_block, address_block, address_block, False)
        idx = (i % BLOCK_U64) * 2
        pseudo_rands[i * 2] = address_block[idx]
        pseudo_rands[i * 2 + 1] = address_block[idx + 1]

    return pseudo_rands


def _fill_segment(memory, pass_, slice_, lane, lanes, lane_len, seg_len,
                  mem_blocks, passes):
    data_indep = (pass_ == 0 and slice_ < SYNC_POINTS // 2)
    pseudo_rands = None
    if data_indep:
        pseudo_rands = _generate_addresses(
            seg_len, pass_, lane, slice_, mem_blocks, passes)

    start_idx = 2 if (pass_ == 0 and slice_ == 0) else 0
    lane_start = lane * lane_len

    for i in range(start_idx, seg_len):
        curr_off = lane_start + slice_ * seg_len + i
        prev_off = (lane_start + lane_len - 1
                    if (i == 0 and slice_ == 0)
                    else curr_off - 1)

        if data_indep:
            j1 = pseudo_rands[i * 2]
            j2 = pseudo_rands[i * 2 + 1]
        else:
            pb = prev_off * BLOCK_U32
            j1 = memory[pb]
            j2 = memory[pb + 1]

        ref_lane = j2 % lanes
        if pass_ == 0 and slice_ == 0:
            ref_lane = lane

        same_lane = (ref_lane == lane)
        ref_idx = _index_alpha(
            pass_, slice_, i, seg_len, lane_len, j1, same_lane)
        ref_off = ref_lane * lane_len + ref_idx

        # Extract sub-block views as lists
        state_s = prev_off * BLOCK_U32
        ref_s = ref_off * BLOCK_U32
        out_s = curr_off * BLOCK_U32

        state_view = memory[state_s:state_s + BLOCK_U32]
        ref_view = memory[ref_s:ref_s + BLOCK_U32]
        out_view = memory[out_s:out_s + BLOCK_U32]

        _argon2_compress(state_view, ref_view, out_view, pass_ > 0)

        # Write back
        memory[out_s:out_s + BLOCK_U32] = out_view


# ── Main Argon2id function ───────────────────────────────────────

def argon2id(password, salt, time_cost, memory_cost, parallelism, hash_len):
    """Argon2id key derivation (RFC 9106).

    Args:
        password: Secret bytes.
        salt: Salt bytes (>= 8 bytes).
        time_cost: Number of iterations (>= 1).
        memory_cost: Memory in KiB (>= 8).
        parallelism: Number of lanes (>= 1).
        hash_len: Output length in bytes (>= 4).

    Returns:
        Derived key as bytes.
    """
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")
    if time_cost < 1:
        raise ValueError("time_cost must be >= 1")
    if memory_cost < 8:
        raise ValueError("memory_cost must be >= 8")
    if parallelism < 1:
        raise ValueError("parallelism must be >= 1")
    if hash_len < 4:
        raise ValueError("hash_len must be >= 4")
    if len(salt) < 8:
        raise ValueError("salt must be >= 8 bytes")

    p = parallelism
    m = memory_cost
    t = time_cost
    T = hash_len

    mem_blocks = m
    if mem_blocks < 2 * SYNC_POINTS * p:
        mem_blocks = 2 * SYNC_POINTS * p
    mem_blocks -= mem_blocks % (p * SYNC_POINTS)

    seg_len = mem_blocks // (p * SYNC_POINTS)
    lane_len = seg_len * SYNC_POINTS

    # Allocate memory (flat list of u32)
    memory = [0] * (mem_blocks * BLOCK_U32)

    # H0 = Blake2b-64(LE32(p) || LE32(T) || LE32(m) || LE32(t) ||
    #                  LE32(0x13) || LE32(2) ||
    #                  LE32(|P|) || P || LE32(|S|) || S ||
    #                  LE32(0) || LE32(0))
    h0_input = (
        _le32(p) + _le32(T) + _le32(m) + _le32(t) +
        _le32(0x13) + _le32(2) +
        _le32(len(password)) + bytes(password) +
        _le32(len(salt)) + bytes(salt) +
        _le32(0) + _le32(0)
    )
    H0 = blake2b(h0_input, 64)

    # Fill first two blocks of each lane
    for lane in range(p):
        b0 = _argon2_hash(H0 + _le32(0) + _le32(lane), BLOCK_BYTES)
        block0 = _load_block(b0)
        off0 = lane * lane_len * BLOCK_U32
        memory[off0:off0 + BLOCK_U32] = block0

        b1 = _argon2_hash(H0 + _le32(1) + _le32(lane), BLOCK_BYTES)
        block1 = _load_block(b1)
        off1 = (lane * lane_len + 1) * BLOCK_U32
        memory[off1:off1 + BLOCK_U32] = block1

    # Fill remaining blocks
    for pass_ in range(t):
        for slice_ in range(SYNC_POINTS):
            for lane in range(p):
                _fill_segment(memory, pass_, slice_, lane, p,
                              lane_len, seg_len, mem_blocks, t)

    # Finalize: XOR last blocks of all lanes
    final_block = [0] * BLOCK_U32
    for lane in range(p):
        off = (lane * lane_len + lane_len - 1) * BLOCK_U32
        for i in range(BLOCK_U32):
            final_block[i] ^= memory[off + i]

    result = _argon2_hash(_store_block(final_block), T)

    return result


# ── Drop-in wrapper (cffi-first, pure-Python fallback) ───────────
#
# Usage:
#   from crypto.argon2 import hash_secret_raw, Type
#
# This matches the argon2-cffi low_level API so callers only need to
# change their import line.

class _ArgonType:
    """Minimal enum matching argon2.low_level.Type."""
    D = 0
    I = 1
    ID = 2

Type = _ArgonType

# Try to use the C library — it's ~100x faster
_cffi_hash = None
try:
    from argon2.low_level import hash_secret_raw as _cffi_hash, Type as _CffiType
    # Re-export the real Type so callers get the C enum
    Type = _CffiType
    _HAS_CFFI = True
except ImportError:
    _HAS_CFFI = False

BACKEND = "cffi" if _HAS_CFFI else "pure"


def hash_secret_raw(secret, salt, time_cost, memory_cost, parallelism,
                    hash_len, type):
    """Argon2 KDF — compatible with argon2.low_level.hash_secret_raw.

    Uses the C library (argon2-cffi) when available, otherwise falls
    back to the pure Python implementation above.
    """
    if _cffi_hash is not None:
        return _cffi_hash(
            secret=secret, salt=salt, time_cost=time_cost,
            memory_cost=memory_cost, parallelism=parallelism,
            hash_len=hash_len, type=type,
        )

    # Map type enum to check it's Argon2id (only variant we support)
    type_val = type if isinstance(type, int) else getattr(type, "value", type)
    if type_val != 2:
        raise ValueError(
            f"Pure Python backend only supports Argon2id (type=2), got {type_val}")

    return argon2id(secret, salt, time_cost, memory_cost, parallelism, hash_len)
