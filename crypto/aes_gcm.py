# Copyright (c) 2026 Lock — MIT License

"""Pure-Python AES-256-GCM authenticated encryption (NIST SP 800-38D).

AES-256-GCM combines AES-256 in Counter (CTR) mode for encryption with
GHASH (Galois field multiplication in GF(2^128)) for authentication,
producing a 16-byte authentication tag that protects both the ciphertext
and optional associated authenticated data (AAD).

Sizes:
    Key:   32 bytes (AES-256)
    Nonce: 12 bytes (recommended per NIST SP 800-38D)
    Tag:   16 bytes (appended to ciphertext)

This module provides a pure-Python implementation with no external
dependencies.  All operations use table lookups and branchless logic
where possible, but CPython cannot guarantee hardware-level constant-time
behavior.

When the ``cryptography`` package is available, encrypt/decrypt delegate
to OpenSSL's AES-GCM for constant-time performance.

References:
    - NIST SP 800-38D: Galois/Counter Mode of Operation (GCM)
    - FIPS 197: Advanced Encryption Standard (AES)
"""

import hmac as _hmac_mod
import os

try:
    from .secure_wipe import wipe_all
except ImportError:
    try:
        from crypto.secure_wipe import wipe_all
    except ImportError:
        def wipe_all(*bufs):
            for b in bufs:
                if isinstance(b, (bytearray, list)):
                    for i in range(len(b)):
                        b[i] = 0

# ── Optional C backend ────────────────────────────────────────

_HAS_CRYPTO = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    _HAS_CRYPTO = True
except ImportError:
    pass

# ── Size constants ────────────────────────────────────────────

AES_GCM_KEY_SIZE = 32    # AES-256
AES_GCM_NONCE_SIZE = 12  # 96-bit nonce (recommended)
AES_GCM_TAG_SIZE = 16    # 128-bit authentication tag

# ── AES S-Box ─────────────────────────────────────────────────

_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
])

# ── Round constants ───────────────────────────────────────────

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)


# ── AES-256 internals ────────────────────────────────────────

def _xtime(a: int) -> int:
    """Multiply by 2 in GF(2^8) with reduction polynomial x^8 + x^4 + x^3 + x + 1."""
    return ((a << 1) ^ (0x1b if (a & 0x80) else 0)) & 0xFF


def _key_expansion(key: bytes) -> bytearray:
    """AES-256 key expansion: 32-byte key -> 240 bytes (15 round keys)."""
    w = bytearray(240)
    w[:32] = key
    for i in range(8, 60):
        t0, t1, t2, t3 = w[(i - 1) * 4:(i - 1) * 4 + 4]
        if i % 8 == 0:
            t0, t1, t2, t3 = (
                _SBOX[t1] ^ _RCON[i // 8 - 1],
                _SBOX[t2],
                _SBOX[t3],
                _SBOX[t0],
            )
        elif i % 8 == 4:
            t0, t1, t2, t3 = _SBOX[t0], _SBOX[t1], _SBOX[t2], _SBOX[t3]
        base = (i - 8) * 4
        w[i * 4] = w[base] ^ t0
        w[i * 4 + 1] = w[base + 1] ^ t1
        w[i * 4 + 2] = w[base + 2] ^ t2
        w[i * 4 + 3] = w[base + 3] ^ t3
    return w


def _aes_block(state: bytearray, rk: bytearray) -> None:
    """Encrypt one 16-byte block in-place with AES-256 (14 rounds)."""
    # AddRoundKey(0)
    for i in range(16):
        state[i] ^= rk[i]
    for r in range(1, 15):
        # SubBytes
        for i in range(16):
            state[i] = _SBOX[state[i]]
        # ShiftRows
        state[1], state[5], state[9], state[13] = (
            state[5], state[9], state[13], state[1])
        state[2], state[10] = state[10], state[2]
        state[6], state[14] = state[14], state[6]
        state[3], state[7], state[11], state[15] = (
            state[15], state[3], state[7], state[11])
        # MixColumns (skip on last round)
        if r < 14:
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = state[c], state[c + 1], state[c + 2], state[c + 3]
                state[c] = _xtime(a0) ^ _xtime(a1) ^ a1 ^ a2 ^ a3
                state[c + 1] = a0 ^ _xtime(a1) ^ _xtime(a2) ^ a2 ^ a3
                state[c + 2] = a0 ^ a1 ^ _xtime(a2) ^ _xtime(a3) ^ a3
                state[c + 3] = _xtime(a0) ^ a0 ^ a1 ^ a2 ^ _xtime(a3)
        # AddRoundKey
        off = r * 16
        for i in range(16):
            state[i] ^= rk[off + i]


# ── GCM internals ─────────────────────────────────────────────

def _ghash_mul(X: bytearray, Y: bytearray) -> bytearray:
    """Multiply X and Y in GF(2^128) using the GCM reduction polynomial."""
    V = bytearray(Y)
    Z = bytearray(16)
    for i in range(128):
        if (X[i >> 3] >> (7 - (i & 7))) & 1:
            for j in range(16):
                Z[j] ^= V[j]
        lsb = V[15] & 1
        for j in range(15, 0, -1):
            V[j] = ((V[j] >> 1) | ((V[j - 1] & 1) << 7)) & 0xFF
        V[0] = (V[0] >> 1) & 0xFF
        if lsb:
            V[0] ^= 0xe1  # reduction: x^128 + x^7 + x^2 + x + 1
    return Z


def _ghash(H: bytearray, data: bytes) -> bytearray:
    """Compute GHASH over data using hash subkey H."""
    Y = bytearray(16)
    for off in range(0, len(data), 16):
        block = data[off:off + 16]
        for i in range(len(block)):
            Y[i] ^= block[i]
        Y = _ghash_mul(Y, H)
    return Y


def _inc_ctr(ctr: bytearray) -> None:
    """Increment the 32-bit big-endian counter in bytes 12..15.

    Raises OverflowError if the 32-bit counter wraps — continuing
    would reuse keystream blocks, catastrophically breaking CTR mode.
    """
    for i in range(15, 11, -1):
        ctr[i] = (ctr[i] + 1) & 0xFF
        if ctr[i] != 0:
            return
    raise OverflowError(
        "AES-GCM: 32-bit counter exhausted (2^32 blocks). "
        "Plaintext exceeds the NIST SP 800-38D maximum for a "
        "single invocation (~64 GB). Use a new nonce."
    )


# NIST SP 800-38D maximum: 2^39 - 256 bits = (2^36 - 32) bytes
_MAX_PLAINTEXT_BYTES = (1 << 36) - 32



def _pad16(length: int) -> int:
    """Bytes needed to pad to next 16-byte boundary."""
    r = length % 16
    return 0 if r == 0 else 16 - r


# ── Public API ────────────────────────────────────────────────

def aes_gcm_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> bytes:
    """Encrypt with AES-256-GCM.

    Args:
        key: 32-byte AES-256 key.
        nonce: 12-byte nonce (must never be reused with the same key).
        plaintext: Data to encrypt (any length).
        aad: Additional authenticated data (authenticated but not encrypted).

    Returns:
        ciphertext || tag (16 bytes appended).

    Raises:
        ValueError: If key is not 32 bytes or nonce is not 12 bytes.
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"Nonce must be 12 bytes, got {len(nonce)}")

    if len(plaintext) > _MAX_PLAINTEXT_BYTES:
        raise ValueError(
            f"Plaintext ({len(plaintext)} bytes) exceeds NIST SP 800-38D "
            f"maximum ({_MAX_PLAINTEXT_BYTES} bytes)")

    if _HAS_CRYPTO:
        cipher = _AESGCM(key)
        return cipher.encrypt(nonce, plaintext, aad or None)

    # Pure-Python fallback
    rk = _key_expansion(key)
    H = bytearray(16)
    _aes_block(H, rk)

    try:
        # J0 = nonce || 0x00000001
        J0 = bytearray(16)
        J0[:12] = nonce
        J0[15] = 1

        # Encrypt with AES-CTR starting at J0+1
        ct = bytearray(len(plaintext))
        ctr = bytearray(J0)
        for off in range(0, len(plaintext), 16):
            _inc_ctr(ctr)
            ks = bytearray(ctr)
            _aes_block(ks, rk)
            end = min(16, len(plaintext) - off)
            for i in range(end):
                ct[off + i] = plaintext[off + i] ^ ks[i]

        # GHASH input: AAD (padded) || CT (padded) || len_AAD(64) || len_CT(64)
        aad_pad = _pad16(len(aad))
        ct_pad = _pad16(len(ct))
        ghash_input = (
            aad + b"\x00" * aad_pad
            + bytes(ct) + b"\x00" * ct_pad
            + (len(aad) * 8).to_bytes(8, "big")
            + (len(ct) * 8).to_bytes(8, "big")
        )

        tag = _ghash(H, ghash_input)

        # Tag = GHASH XOR AES_K(J0)
        enc_j0 = bytearray(J0)
        _aes_block(enc_j0, rk)
        for i in range(16):
            tag[i] ^= enc_j0[i]

        return bytes(ct) + bytes(tag)
    finally:
        wipe_all(rk, H)


def aes_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes = b"",
) -> bytes:
    """Decrypt with AES-256-GCM.

    Args:
        key: 32-byte AES-256 key.
        nonce: 12-byte nonce.
        ciphertext: Ciphertext with 16-byte tag appended.
        aad: Additional authenticated data.

    Returns:
        Decrypted plaintext.

    Raises:
        ValueError: If key/nonce size is wrong or ciphertext is too short.
        RuntimeError: If the authentication tag does not verify.
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"Nonce must be 12 bytes, got {len(nonce)}")
    if len(ciphertext) < 16:
        raise ValueError("Ciphertext too short (must include 16-byte tag)")

    if len(ciphertext) - 16 > _MAX_PLAINTEXT_BYTES:
        raise ValueError(
            f"Ciphertext ({len(ciphertext) - 16} bytes payload) exceeds "
            f"NIST SP 800-38D maximum ({_MAX_PLAINTEXT_BYTES} bytes)")

    if _HAS_CRYPTO:
        cipher = _AESGCM(key)
        return cipher.decrypt(nonce, ciphertext, aad or None)

    # Pure-Python fallback
    ct = ciphertext[:-16]
    received_tag = ciphertext[-16:]

    rk = _key_expansion(key)
    H = bytearray(16)
    _aes_block(H, rk)

    try:
        # J0
        J0 = bytearray(16)
        J0[:12] = nonce
        J0[15] = 1

        # Verify tag first
        aad_pad = _pad16(len(aad))
        ct_pad = _pad16(len(ct))
        ghash_input = (
            aad + b"\x00" * aad_pad
            + ct + b"\x00" * ct_pad
            + (len(aad) * 8).to_bytes(8, "big")
            + (len(ct) * 8).to_bytes(8, "big")
        )

        computed_tag = _ghash(H, ghash_input)
        enc_j0 = bytearray(J0)
        _aes_block(enc_j0, rk)
        for i in range(16):
            computed_tag[i] ^= enc_j0[i]

        # Constant-time tag comparison
        if not _hmac_mod.compare_digest(bytes(computed_tag), bytes(received_tag)):
            raise RuntimeError("AES-GCM: authentication tag mismatch")

        # Decrypt
        plaintext = bytearray(len(ct))
        ctr = bytearray(J0)
        for off in range(0, len(ct), 16):
            _inc_ctr(ctr)
            ks = bytearray(ctr)
            _aes_block(ks, rk)
            end = min(16, len(ct) - off)
            for i in range(end):
                plaintext[off + i] = ct[off + i] ^ ks[i]

        return bytes(plaintext)
    finally:
        wipe_all(rk, H)
