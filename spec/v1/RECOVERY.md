# Universal Quantum Seed — Recovery Guide v1

**Spec version:** 1.0
**Domain separator:** `universal-seed-v1`

> This document describes exactly how to recover keys from a Universal Quantum Seed
> backup using only standard cryptographic primitives. No proprietary code is needed.

---

## What You Need

1. Your **24 or 36 words** (or icon indexes 0–255)
2. Your **passphrase** (if one was set; empty string if none)
3. A system that can compute:
   - HMAC-SHA-256 (checksum verification)
   - HMAC-SHA-512 (HKDF-Extract, HKDF-Expand, profiles)
   - PBKDF2-SHA-512
   - Argon2id
4. The **icon-to-index mapping** (see SPEC.md Section 2, or `words.py`)

---

## Step-by-Step Recovery

### Step 1: Resolve Words to Indexes

Each word maps to an index 0–255. The canonical list is in SPEC.md Section 2.

```
eye=0, ear=1, nose=2, mouth=3, tongue=4, bone=5, ...
```

If you wrote your seed in another language, resolve each word through the
42-language lookup table in `words.py`. The checksum (Step 2) will catch
any misresolution.

**Result:** A list of N indexes (N = 24 or 36).

### Step 2: Verify Checksum

The last 2 indexes are a 16-bit HMAC-SHA-256 checksum over the data indexes.

```python
data_indexes = indexes[:-2]         # first N-2
checksum     = indexes[-2:]         # last 2

key     = b"universal-seed-v1-checksum"
message = bytes(data_indexes)
digest  = HMAC-SHA256(key, message)

assert checksum == [digest[0], digest[1]]
```

If the checksum doesn't match, you have a transcription error. Fix it before
proceeding — incorrect data will derive a wrong (and useless) key.

### Step 3: Strip Checksum

Only the data indexes enter the key derivation pipeline:

```python
data_indexes = indexes[:-2]   # 22 data (24-word) or 34 data (36-word)
```

### Step 4: Positional Binding

Pack each data index with its zero-based position as a (position, index) byte pair,
little-endian:

```python
import struct

payload = b""
for pos, idx in enumerate(data_indexes):
    payload += struct.pack("<BB", pos, idx)
```

This produces 44 bytes (24-word seed) or 68 bytes (36-word seed).

### Step 5: Passphrase Mixing

If a passphrase was used, append its raw UTF-8 bytes:

```python
if passphrase:
    payload += passphrase.encode("utf-8")
```

**No normalization** — the passphrase is used as-is (no NFKC, no trimming, no case folding).
An empty string `""` produces the same result as no passphrase.

### Step 6: HKDF-Extract (RFC 5869)

Collapse the payload into a 64-byte pseudorandom key using HMAC-SHA-512:

```python
prk = HMAC-SHA512(key=b"universal-seed-v1", message=payload)
```

- Key: `b"universal-seed-v1"` (17 bytes)
- Message: positional payload + optional passphrase bytes
- Output: 64 bytes (512 bits)

### Step 7: PBKDF2-SHA-512

Stretch the PRK through PBKDF2:

```python
stage1 = PBKDF2-SHA512(
    password = prk,
    salt     = b"universal-seed-v1-stretch-pbkdf2",
    rounds   = 600000,
    dklen    = 64
)
```

### Step 8: Argon2id

Further harden through Argon2id:

```python
stage2 = Argon2id(
    secret      = stage1,
    salt        = b"universal-seed-v1-stretch-argon2id",
    time_cost   = 3,
    memory_cost = 65536,    # 64 MiB
    parallelism = 4,
    hash_len    = 64,
    type        = Argon2id
)
```

### Step 9: HKDF-Expand (RFC 5869)

Derive the final 64-byte master key:

```python
def hkdf_expand(prk, info, length):
    from math import ceil
    n = ceil(length / 64)
    okm = b""
    prev = b""
    for i in range(1, n + 1):
        prev = HMAC-SHA512(key=prk, message=prev + info + bytes([i]))
        okm += prev
    return okm[:length]

master_key = hkdf_expand(stage2, b"universal-seed-v1-master", 64)
```

### Step 10: Done

`master_key` is your 64-byte (512-bit) master seed.

- First 32 bytes: 256-bit encryption key
- Last 32 bytes: 256-bit authentication key
- Or use the full 64 bytes as a master seed for further derivation

---

## Profile Recovery

If you used a hidden profile password:

```python
def get_profile(master_key, profile_password):
    if not profile_password:
        return master_key   # empty = default profile
    payload = b"universal-seed-v1-profile" + profile_password.encode("utf-8")
    return HMAC-SHA512(key=master_key, message=payload)
```

Each profile password produces an independent 64-byte key. Without the password,
the profile's existence cannot be detected.

---

## Cryptographic Key Recovery

If you derived keypairs, the seeds are derived from the master key via HKDF-Expand:

```python
_QUANTUM_SEED_SIZES = {
    "ml-dsa-65": 32,            # xi seed for FIPS 204 KeyGen
    "slh-dsa-shake-128s": 48,   # SK.seed(16) + SK.prf(16) + PK.seed(16)
    "ml-kem-768": 64,           # d (32B) || z (32B) for FIPS 203 KeyGen
    "hybrid-dsa-65": 64,        # Ed25519 seed (32B) + ML-DSA-65 seed (32B)
    "hybrid-kem-768": 96,       # X25519 seed (32B) + ML-KEM-768 seed (64B d||z)
}

def get_quantum_seed(master_key, algorithm, key_index=0):
    import struct
    size = _QUANTUM_SEED_SIZES[algorithm]
    info = b"universal-seed-v1-quantum-" + algorithm.encode("ascii") + struct.pack("<I", key_index)
    return hkdf_expand(master_key, info, size)
```

Feed the resulting seed into the appropriate keygen:

### Post-quantum algorithms

- **ML-DSA-65 (FIPS 204):** 32-byte seed -> `KeyGen(xi)` -> (sk: 4,032 B, pk: 1,952 B)
- **SLH-DSA-SHAKE-128s (FIPS 205):** 48-byte seed -> `slh_keygen(seed)` -> (sk: 64 B, pk: 32 B)
- **ML-KEM-768 (FIPS 203):** 64-byte seed (d||z) -> `KeyGen(d, z)` -> (ek: 1,184 B, dk: 2,400 B)

### Hybrid algorithms

- **Hybrid-DSA-65 (Ed25519 + ML-DSA-65):**
  64-byte seed -> first 32B to Ed25519 keygen, last 32B to ML-DSA-65 keygen
  -> sk: 4,096 B (Ed25519 sk 64B + ML-DSA sk 4,032B)
  -> pk: 1,984 B (Ed25519 pk 32B + ML-DSA pk 1,952B)

- **Hybrid-KEM-768 (X25519 + ML-KEM-768):**
  96-byte seed -> first 32B to X25519 keygen, last 64B to ML-KEM-768 keygen (d||z)
  -> ek: 1,216 B (X25519 pk 32B + ML-KEM ek 1,184B)
  -> dk: 2,432 B (X25519 sk 32B + ML-KEM dk 2,400B)

### Hybrid DSA verification

Both Ed25519 AND ML-DSA-65 must independently verify. The component signatures use
domain separation to prevent stripping:
- Ed25519 verifies: `b"hybrid-dsa-v1" || len(ctx) [1 byte] || ctx || message`
- ML-DSA-65 verifies with context: `b"hybrid-dsa-v1\x00" || ctx`

### Hybrid KEM shared secret recovery

The two component shared secrets are combined via HKDF:
```python
salt = SHA-256(x25519_ct || ml_kem_ct)
PRK  = HMAC-SHA256(salt, x25519_ss || ml_kem_ss)
info = b"hybrid-kem-v1" || SHA-256(x25519_pk || ml_kem_ek) || 0x01
SS   = HMAC-SHA256(PRK, info)
```

---

## Fingerprint Verification

To verify you've recovered correctly, compute the fingerprint:

**Without passphrase** (instant — uses HKDF-Extract only):
```python
payload = b""
for pos, idx in enumerate(data_indexes):
    payload += struct.pack("<BB", pos, idx)
prk = HMAC-SHA512(key=b"universal-seed-v1", message=payload)
fingerprint = prk[0:4].hex().upper()   # e.g. "0FBFBBCB"
```

**With passphrase** (runs full KDF):
```python
master_key = ...  # full recovery from Steps 4–9
fingerprint = master_key[0:4].hex().upper()
```

Compare this fingerprint against your saved fingerprint. If it matches, recovery
was successful.

---

## Quick Reference — All Domain Strings

| Stage | String | Usage |
|:---|:---|:---|
| Checksum | `b"universal-seed-v1-checksum"` | HMAC-SHA-256 key |
| HKDF-Extract | `b"universal-seed-v1"` | HMAC-SHA-512 key |
| PBKDF2 salt | `b"universal-seed-v1-stretch-pbkdf2"` | PBKDF2-SHA-512 salt |
| Argon2id salt | `b"universal-seed-v1-stretch-argon2id"` | Argon2id salt |
| HKDF-Expand | `b"universal-seed-v1-master"` | info string |
| Profile | `b"universal-seed-v1-profile"` | HMAC-SHA-512 message prefix |
| ML-DSA-65 | `b"universal-seed-v1-quantum-ml-dsa-65"` + index | HKDF-Expand info |
| SLH-DSA | `b"universal-seed-v1-quantum-slh-dsa-shake-128s"` + index | HKDF-Expand info |
| ML-KEM-768 | `b"universal-seed-v1-quantum-ml-kem-768"` + index | HKDF-Expand info |
| Hybrid-DSA-65 | `b"universal-seed-v1-quantum-hybrid-dsa-65"` + index | HKDF-Expand info |
| Hybrid-KEM-768 | `b"universal-seed-v1-quantum-hybrid-kem-768"` + index | HKDF-Expand info |
| Hybrid DSA domain | `b"hybrid-dsa-v1"` | Stripping resistance prefix |
| Hybrid KEM domain | `b"hybrid-kem-v1"` | HKDF info prefix |
| Hybrid KEM fail | `b"hybrid-kem-x25519-fail"` | X25519 implicit rejection |

---

## Test Vector (Minimal)

All-zeros 24-word seed, no passphrase:

```
Data indexes:     [0, 0, 0, ..., 0]  (22 zeros)
Checksum indexes: [169, 111]
Full indexes:     [0, 0, ..., 0, 169, 111]  (24 total)
Passphrase:       "" (empty)

PRK (HKDF-Extract only):
  0fbfbbcbe6763d2395f3502ff2c4fc099caa2fbf0476dd0117696a9afb51e3d1
  996e4232da6c04f6bb2e346878487d101ebddaf15b6e8ea0c95f72cce4bf675f

Fingerprint: 0FBFBBCB
```

See `test-vectors.json` for the full set of test vectors including quantum key derivation.

---

## Compatibility

This guide describes v1 of the Universal Quantum Seed. The compatibility contract:

> **v1 seeds MUST always derive the same outputs forever.**
> No parameter may be changed within v1. If parameters change, a new version
> with a new domain separator and spec folder MUST be created.
