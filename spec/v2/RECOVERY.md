# Universal Seed System v2 — Recovery Guide

This document explains how to recover a master key from a v2 seed without the Signer app.

---

## What You Need

1. Your **seed words** (24 or 36 words) written on paper
2. Your **passphrase** (if you set one — empty string if not)
3. Python 3.8+ with `argon2-cffi` installed
4. The `seed.py` file (v2.0+) and `words.json`

---

## Step-by-Step Recovery

### Step 1: Resolve words to icon indexes

Each word maps to an icon index (0-255). Use the lookup table in `words.json`:

```python
from seed import resolve

# Type your words exactly as written
my_words = ["dog", "sun", "key", "moon", ...]  # all 24 or 36

indexes, errors = resolve(my_words)
if errors:
    print(f"Could not resolve: {errors}")
    # Check spelling, try synonyms, or select icons visually
else:
    print(f"Indexes: {indexes}")
```

If you wrote words in a non-English language, they still resolve:
```python
indexes, errors = resolve(["perro", "sol", "llave", "luna", ...])
```

### Step 2: Verify checksum

The last 2 words are a 16-bit checksum. Verify before proceeding:

```python
from seed import verify_checksum

if verify_checksum(my_words):
    print("Checksum valid — seed is intact")
else:
    print("Checksum FAILED — check for transcription errors")
    # Re-check your words, especially the last two
```

If the checksum fails:
- Double-check every word for typos
- Verify word order matches what you wrote
- The last 2 words ARE the checksum — they must be exactly right
- Try the visual icon verification (Step 3)

### Step 3: Verify visually (recommended)

Check that each resolved index matches the icon you remember:
```
Index  0 = eye      Index 15 = dog     Index 63 = sun
Index 64 = moon     Index 136 = key    ...
```

The full mapping is in `SPEC.md` section 2 (v1) or in `seed.py`'s `_BASE_WORDS` tuple.

### Step 4: Derive the master key

```python
from seed import get_private_key, get_fingerprint

# Without passphrase
key = get_private_key(indexes)
fp = get_fingerprint(indexes)
print(f"Fingerprint: {fp}")
print(f"Master key: {key.hex()}")

# With passphrase
key = get_private_key(indexes, "your passphrase here")
fp = get_fingerprint(indexes, "your passphrase here")
```

### Step 5: Verify the fingerprint

Compare the displayed fingerprint (8 hex chars, e.g. `"A3F1B2C4"`) with what you recorded. If they match, the recovery is correct.

---

## Manual Recovery (No seed.py)

If you only have Python + `argon2-cffi` and no seed.py, you can derive manually:

```python
import hashlib, hmac, struct
from argon2.low_level import hash_secret_raw, Type

DOMAIN = b"universal-seed-v2"

# Your icon indexes (replace with your actual values)
all_indexes = [15, 63, 136, ...]  # all 24 or 36 integers, each 0-255

# Step 0: Verify and strip checksum
data_indexes = all_indexes[:-2]
checksum_indexes = all_indexes[-2:]

digest = hmac.new(DOMAIN + b"-checksum", bytes(data_indexes), hashlib.sha256).digest()
expected = [digest[0], digest[1]]
if checksum_indexes != expected:
    raise ValueError("Checksum failed! Check your seed words.")
print("Checksum valid")

# Now work with data_indexes only (22 or 34 indexes)
indexes = data_indexes

# Step 1: Positional binding
payload = b""
for pos, idx in enumerate(indexes):
    payload += struct.pack("<BB", pos, idx)

# Step 2: Passphrase (skip if none)
passphrase = ""  # or "your passphrase"
if passphrase:
    payload += passphrase.encode("utf-8")

# Step 3: HKDF-Extract
prk = hmac.new(DOMAIN, payload, hashlib.sha512).digest()

# Step 4a: PBKDF2-SHA512
stage1 = hashlib.pbkdf2_hmac(
    "sha512", prk,
    DOMAIN + b"-stretch-pbkdf2",
    iterations=600_000, dklen=64
)

# Step 4b: Argon2id
stretched = hash_secret_raw(
    secret=stage1,
    salt=DOMAIN + b"-stretch-argon2id",
    time_cost=3, memory_cost=65536,
    parallelism=4, hash_len=64,
    type=Type.ID
)

# Step 5: HKDF-Expand
info = DOMAIN + b"-master"
prev = b""
prev = hmac.new(stretched, prev + info + bytes([1]), hashlib.sha512).digest()
master_key = prev  # 64 bytes

print(f"Master key: {master_key.hex()}")

# Fingerprint (no passphrase only):
fp_payload = b""
for pos, idx in enumerate(data_indexes):
    fp_payload += struct.pack("<BB", pos, idx)
fp_key = hmac.new(DOMAIN, fp_payload, hashlib.sha512).digest()
print(f"Fingerprint: {fp_key[:4].hex().upper()}")
```

---

## Troubleshooting

| Problem | Solution |
|:---|:---|
| Word doesn't resolve | Try the base English word, a synonym, or the icon index directly |
| Checksum fails | Re-check every word carefully, especially the last 2 — they are the checksum |
| Fingerprint doesn't match | Double-check word order, check for swapped words |
| Wrong key derived | Verify passphrase is exactly right (case-sensitive, no extra spaces) |
| Missing seed.py | Use the manual recovery code above — only needs Python + argon2-cffi |
| Got 16 or 32 words (v1 seed) | Use v1 recovery — v1 seeds cannot be used with v2's `get_private_key()` |

---

## Important Notes

- v2 has a **16-bit checksum** — always verify it before derivation
- The checksum catches ~99.998% of single-word errors (1-in-65,536 false positive)
- Passphrase is **not normalized** — `"Hello"` and `"hello"` produce different keys
- The fingerprint is 8 hex chars (32 bits) — much stronger visual verification than v1's 4 chars
- If you have the icon images, you can verify visually that each index matches
- v1 seeds (16/32 words) are incompatible — use v1 recovery procedures for those
