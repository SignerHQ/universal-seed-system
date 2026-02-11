# Universal Seed System — Specification v2

**Status:** Active
**Version:** 2.0+
**Domain separator:** `universal-seed-v2`

> **Compatibility contract:** v2 seeds MUST always derive the same outputs forever.
> No parameter may be changed within v2. If parameters change, a new version (v3+)
> with a new domain separator and spec folder MUST be created. Never "tune Argon2"
> or adjust PBKDF2 rounds inside v2.

---

## 1. Overview

v2 adds a 16-bit checksum (2 dedicated words), increases word counts to 24/36,
uses a new domain separator (`universal-seed-v2`), strict word resolution in KDF,
and an 8-char fingerprint.

| Property | Value |
|:---|:---|
| Word counts | 24 or 36 |
| Data words | 22 (compact) or 34 (standard) |
| Checksum words | 2 (last two positions) |
| Entropy | 24 words = 176-bit, 36 words = 272-bit |
| Checksum | 16-bit HMAC-SHA-256 (1-in-65,536 error detection) |
| Fingerprint | 8-char hex (4 bytes = 32 bits) |
| Domain separator | `b"universal-seed-v2"` |
| Icon set | 256 icons, indexed 0-255 (same as v1) |

---

## 2. Icon-Index Mapping

Identical to v1. See `spec/v1/SPEC.md` section 2 for the complete mapping.

Icons are identified by their index (0-255), not by filename. The mapping is frozen.

---

## 3. Encoding

A seed is an ordered list of N icon indexes where:
- First N-2 indexes are **data** (random entropy)
- Last 2 indexes are **checksum** (derived from data)

```
full_seed = [data_0, data_1, ..., data_{N-3}, checksum_0, checksum_1]
```

- 24 words: 22 data bytes + 2 checksum = 176 bits of entropy
- 36 words: 34 data bytes + 2 checksum = 272 bits of entropy

---

## 4. Checksum

The checksum is computed via HMAC-SHA-256 with domain separation:

```python
def compute_checksum(data_indexes):
    key = b"universal-seed-v2-checksum"
    message = bytes(data_indexes)
    digest = HMAC-SHA256(key, message)
    return [digest[0], digest[1]]
```

| Property | Value |
|:---|:---|
| Algorithm | HMAC-SHA-256 |
| Key | `b"universal-seed-v2-checksum"` (25 bytes) |
| Message | data indexes as raw bytes |
| Output | First 2 bytes of HMAC digest |
| Error detection | 16 bits (1-in-65,536 false positive) |

### Verification

```python
def verify_checksum(full_indexes):
    if len(full_indexes) not in (24, 36):
        return False
    data = full_indexes[:-2]
    expected = compute_checksum(data)
    return full_indexes[-2:] == expected
```

---

## 5. Passphrase Normalization

Identical to v1. Passphrases are **raw UTF-8 bytes with no normalization**.

```python
passphrase_bytes = passphrase_string.encode("utf-8")
```

- No NFKC/NFC normalization
- No whitespace trimming or case folding
- Empty string `""` is equivalent to no passphrase

---

## 6. Key Derivation Pipeline (6 layers)

### 6.0 Checksum Verification & Stripping

Before any KDF computation:
1. Verify the seed has exactly 24 or 36 indexes
2. Verify the last 2 indexes match `compute_checksum(indexes[:-2])`
3. Strip the checksum: `data_indexes = indexes[:-2]`

If verification fails, key derivation MUST be rejected with an error.

### 6.1 Positional Binding

Each data icon index is packed with its zero-based position as a little-endian (pos, index) byte pair:

```python
payload = b""
for pos, idx in enumerate(data_indexes):
    payload += struct.pack("<BB", pos, idx)
```

This binds each icon to its slot, preventing reordering attacks.

### 6.2 Passphrase Mixing

If a passphrase is provided, its raw UTF-8 bytes are appended:

```python
if passphrase:
    payload += passphrase.encode("utf-8")
```

### 6.3 HKDF-Extract (RFC 5869)

The payload is collapsed into a pseudorandom key (PRK) using HMAC-SHA512:

```python
prk = HMAC-SHA512(key=b"universal-seed-v2", message=payload)
```

- Key: domain separator `b"universal-seed-v2"` (17 bytes)
- Message: positional payload + optional passphrase bytes
- Output: 64 bytes (512 bits)

### 6.4 Chained KDF Stretching

The PRK is hardened through two KDFs in series:

**Stage 1: PBKDF2-SHA512**
```
salt    = b"universal-seed-v2-stretch-pbkdf2"
rounds  = 600,000
dklen   = 64 bytes
output  = PBKDF2-SHA512(prk, salt, rounds, dklen)
```

**Stage 2: Argon2id**
```
secret      = stage1_output (64 bytes)
salt        = b"universal-seed-v2-stretch-argon2id"
time_cost   = 3
memory_cost = 65536 (64 MiB)
parallelism = 4
hash_len    = 64 bytes
type        = Argon2id
```

### 6.5 HKDF-Expand (RFC 5869)

Final key derivation with domain separation:

```
info    = b"universal-seed-v2-master"
length  = 64 bytes
output  = HKDF-Expand-SHA512(stretched, info, 64)
```

HKDF-Expand implementation:
```python
def hkdf_expand(prk, info, length):
    n = ceil(length / 64)
    okm = b""
    prev = b""
    for i in range(1, n + 1):
        prev = HMAC-SHA512(key=prk, message=prev + info + bytes([i]))
        okm += prev
    return okm[:length]
```

### 6.6 Output

The final output is **64 bytes (512 bits)** of key material:
- First 32 bytes: 256-bit encryption key
- Last 32 bytes: 256-bit authentication key
- Or used whole as a master key for further derivation

---

## 7. Fingerprint

**Without passphrase** (instant):
```python
payload = positional_payload(data_indexes)  # checksum already stripped
key = HMAC-SHA512(key=b"universal-seed-v2", message=payload)
fingerprint = key[0:4].hex().upper()   # 8-char hex, e.g. "A3F1B2C4"
```

**With passphrase** (runs full KDF):
```python
key = get_private_key(full_seed, passphrase)  # verifies + strips checksum internally
fingerprint = key[0:4].hex().upper()
```

| Property | Value |
|:---|:---|
| Length | 8 hex characters (4 bytes = 32 bits) |
| Format | Uppercase hex, e.g. `"A3F1B2C4"` |
| Derived from | Data indexes only (checksum stripped) |

---

## 8. Word Resolution

### Strict Mode (used in key derivation)

`_to_indexes()` uses `resolve(words, strict=True)`:
- NFKC normalization + lowercase
- Exact lookup table match only
- Emoji variation selector stripping
- **No fuzzy fallbacks** (no diacritics, no articles, no suffixes)

### Fuzzy Mode (used in UI/recovery)

`resolve(words, strict=False)` (default) tries fallbacks:
1. Diacritic stripping (Latin, Greek, Arabic, Hebrew, Cyrillic)
2. Arabic `ال` prefix stripping
3. Hebrew `ה` prefix stripping
4. French/Italian `l'` contraction stripping
5. Scandinavian/Romanian/Icelandic suffix stripping

Fuzzy mode is for user convenience during recovery. The checksum catches any misresolution.

---

## 9. Security Notes

### Protected against
- Brute-force (272-bit entropy + chained KDF)
- GPU/ASIC attacks (Argon2id memory-hardness)
- Reordering attacks (positional binding)
- Transcription errors (16-bit checksum)
- Weak RNG (8 independent entropy sources, validated before use)
- Fuzzy misresolution in KDF (strict mode)

### NOT protected against
- Physical seed theft (paper backup compromise)
- Keylogger capturing passphrase
- Compromised implementation (supply chain)
- Social engineering

### Improvements over v1
- New domain separator (`universal-seed-v2`) — clean protocol separation
- 16-bit checksum detects transcription errors (v1 had none)
- Strict word resolution prevents accidental misresolution in KDF
- 8-char fingerprint (32-bit) vs v1's 4-char (16-bit)
- Higher entropy: 272-bit (v1: 256-bit) and 176-bit (v1: 128-bit)

---

## 10. Verification Signals

v2 provides two independent verification signals:

| Signal | Bits | Derived from | When available |
|:---|:---:|:---|:---|
| Checksum (last 2 words) | 16 | Data indexes via HMAC-SHA-256 | Always (built into seed) |
| Fingerprint | 32 | Data indexes via HMAC-SHA-512 (or full KDF with passphrase) | After resolution |

Both MUST be specified and implemented. The fingerprint changes with passphrase; the checksum does not.

---

## 11. Compatibility

### v1 and v2 are fully independent

v2 uses a different domain separator (`universal-seed-v2`) than v1 (`universal-seed-v1`).
Even for the same data indexes and passphrase, v1 and v2 produce **different keys**.

v1 seeds (16/32 words, no checksum) cannot be used with v2's `get_private_key()` because:
1. v2 enforces 24/36 word count
2. v2 requires valid checksum (with `universal-seed-v2` domain)
3. v2 uses a different domain separator throughout the KDF

v1 seeds should continue to use v1 derivation (seed.py v1.0-v1.3).
