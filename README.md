<div align="center">

# Universal Quantum Seed

### The world's first quantum-safe visual + multilingual seed phrase system

**272-bit entropy** · **Hybrid quantum-safe crypto** · **42 languages** · **256 icons** · **16-bit checksum**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Quantum Safe](https://img.shields.io/badge/Quantum-Safe-00d4aa?style=for-the-badge)](#-quantum-security)
[![Hybrid Crypto](https://img.shields.io/badge/Hybrid-Classical_+_PQ-ff6b6b?style=for-the-badge)](#tier-3--hybrid-classical--post-quantum)
[![Languages](https://img.shields.io/badge/Languages-42-blueviolet?style=for-the-badge)](#-supported-languages)
[![Icons](https://img.shields.io/badge/Visual_Icons-256-orange?style=for-the-badge)](#-visual-icon-library)
[![Entropy](https://img.shields.io/badge/Entropy-272_bit-brightgreen?style=for-the-badge)](#-entropy)
[![Lookup Keys](https://img.shields.io/badge/Lookup_Keys-38,730-red?style=for-the-badge)](#-word-lookup-system)

<br>

*Write your seed in any language. Recover it in any other. Or skip words entirely — select the icons.*

<br>

| | | | | | | | | |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| :gb: `dog` | :es: `perro` | :fr: `chien` | :de: `Hund` | :jp: `犬` | :kr: `개` | :ru: `собака` | :saudi_arabia: `كلب` | :dog2: |

**One concept. Infinite expressions. One universal recovery.**

---

<br>

*Screenshots from Signer's treasury app*

<table>
<tr>
<td><img src="examples/screenshots/treasury1.png" width="270"></td>
<td><img src="examples/screenshots/treasury2.png" width="270"></td>
<td><img src="examples/screenshots/treasury3.png" width="270"></td>
</tr>
</table>

</div>

<br>

## Quantum Security

The **36-word seed is quantum-safe by design**. Its 272-bit entropy survives Grover's algorithm with 136-bit post-quantum security — well above the 128-bit floor. The 24-word compact format (176-bit) is designed for classical use; for quantum-safe key derivation, **use 36 words**.

Beyond the quantum-resistant seed, this system includes a **complete three-tier cryptography stack** — classical, post-quantum, and hybrid — all pure Python with zero external crypto dependencies. Every algorithm is derived deterministically from the same master seed using HKDF domain separation.

### Tier 1 — Classical

| Algorithm | Standard | Security | Public Key | Use |
|:---|:---:|:---:|:---:|:---|
| **Ed25519** | RFC 8032 | ~128-bit | 32 B | Digital signatures |
| **X25519** | RFC 7748 | ~128-bit | 32 B | Diffie-Hellman key exchange |

### Tier 2 — Post-Quantum

| Algorithm | Standard | Security | Public Key | Signature / CT | Assumption |
|:---|:---:|:---:|:---:|:---:|:---|
| **ML-DSA-65** (Dilithium) | FIPS 204 | Level 3 (192-bit PQ) | 1,952 B | 3,309 B sig | Lattice (MLWE) |
| **SLH-DSA-SHAKE-128s** (SPHINCS+) | FIPS 205 | Level 1 (128-bit PQ) | 32 B | 7,856 B sig | Hash-only (SHAKE-256) |
| **ML-KEM-768** (Kyber) | FIPS 203 | Level 3 (192-bit PQ) | 1,184 B | 1,088 B ct | Lattice (MLWE) |

### Tier 3 — Hybrid (Classical + Post-Quantum)

Hybrid schemes combine a classical and post-quantum algorithm in **AND-composition** — security holds as long as *either* component remains unbroken. This provides defense in depth during the cryptographic transition period.

| Algorithm | Components | Public Key | Signature / CT | Design |
|:---|:---|:---:|:---:|:---|
| **Hybrid-DSA-65** | Ed25519 + ML-DSA-65 | 1,984 B | 3,373 B sig | Both must verify |
| **Hybrid-KEM-768** | X25519 + ML-KEM-768 | 1,216 B | 1,120 B ct | Secrets combined via HKDF |

**Hybrid-DSA-65** — Both Ed25519 and ML-DSA-65 independently sign and verify every message. The Ed25519 component signs a domain-prefixed message (`hybrid-dsa-v1 + ctx + message`) to prevent **signature stripping attacks** — an adversary cannot extract the Ed25519 signature and present it as a valid standalone signature.

**Hybrid-KEM-768** — X25519 ephemeral DH and ML-KEM-768 encapsulation each produce a shared secret. Both are combined via **ciphertext-bound HKDF**: the salt includes `SHA-256(x25519_ct || ml_kem_ct)`, preventing ciphertext substitution attacks. The domain string `hybrid-kem-v1` provides protocol separation.

```python
from seed import generate_words, get_seed, generate_quantum_keypair

words = generate_words(36)
seed  = get_seed(words, "passphrase")

# Post-quantum signatures
sk, pk = generate_quantum_keypair(seed, "ml-dsa-65")            # NIST Level 3 lattice
sk, pk = generate_quantum_keypair(seed, "slh-dsa-shake-128s")   # NIST Level 1 hash-based

# Post-quantum key encapsulation
ek, dk = generate_quantum_keypair(seed, "ml-kem-768")           # NIST Level 3 lattice KEM

# Hybrid signatures — Ed25519 + ML-DSA-65
sk, pk = generate_quantum_keypair(seed, "hybrid-dsa-65")

# Hybrid key encapsulation — X25519 + ML-KEM-768
ek, dk = generate_quantum_keypair(seed, "hybrid-kem-768")

# Default is ML-DSA-65
sk, pk = generate_quantum_keypair(seed)
```

### Using Hybrid Crypto Directly

The `crypto/` module exposes all algorithms for direct use:

```python
from crypto import (
    # Hybrid signatures
    hybrid_dsa_keygen, hybrid_dsa_sign, hybrid_dsa_verify,
    # Hybrid key encapsulation
    hybrid_kem_keygen, hybrid_kem_encaps, hybrid_kem_decaps,
)

# Hybrid-DSA-65: sign and verify
sk, pk = hybrid_dsa_keygen(seed_64_bytes)
sig = hybrid_dsa_sign(b"message", sk, ctx=b"my-protocol")
assert hybrid_dsa_verify(b"message", sig, pk, ctx=b"my-protocol")

# Hybrid-KEM-768: encapsulate and decapsulate
ek, dk = hybrid_kem_keygen(seed_96_bytes)
ct, shared_secret_sender = hybrid_kem_encaps(ek)
shared_secret_receiver = hybrid_kem_decaps(dk, ct)
assert shared_secret_sender == shared_secret_receiver  # 32-byte shared secret
```

Classical ECC keys (secp256k1, Ed25519) will be broken by Shor's algorithm on quantum computers. The hybrid and post-quantum algorithms ensure your seed remains secure and usable in a post-quantum world — while the classical components provide a fallback if post-quantum assumptions are ever weakened.

<br>

## Security Model

> Traditional seed phrases (BIP-39) use a single word per position from a fixed list in one language.
> A seed written on paper is immediately recognizable and usable by anyone who finds it.

The Universal Quantum Seed takes a fundamentally different approach:

| | Traditional (BIP-39) | Universal Quantum Seed |
|---|:---:|:---:|
| Words per position | 1 | **Multiple** (synonyms, slang, abbreviations) |
| Languages | 10 | **42** |
| Visual recovery | :x: | :white_check_mark: **Select icons directly** |
| Checksum | 4–8 bit | :white_check_mark: **16-bit** |
| Paper backup recognizable as crypto? | :warning: Yes | :shield: **No** — looks like random notes |
| Mixed-language backup | :x: | :white_check_mark: Write in any combination |
| Accent/diacritic flexible | :x: | :white_check_mark: `corazón` = `corazon` |
| Emoji input | :x: | :white_check_mark: Paste :dog2: :sunny: :key: directly |
| Key stretching | PBKDF2 | **PBKDF2 + Argon2id** (chained, defense in depth) |
| Passphrase support | :white_check_mark: | :white_check_mark: **Second factor** — same seed + different passphrase = unrelated keys |
| Multiple accounts per seed | :x: One seed = one wallet | :white_check_mark: **Unlimited hidden profiles** — one seed, many accounts |

<br>

## How It Works

```
36 words = 34 random + 2 checksum = 272 bits of entropy (2²⁷² combinations)
24 words = 22 random + 2 checksum = 176 bits of entropy (2¹⁷⁶ combinations)
```

<table>
<tr>
<td width="60" align="center"><h3>1</h3></td>
<td><b>Generate</b> — Cryptographically secure random positions selected from 256 icons using defense-in-depth entropy collection</td>
</tr>
<tr>
<td align="center"><h3>2</h3></td>
<td><b>Display</b> — Each position shows its visual icon alongside accepted words in the user's language</td>
</tr>
<tr>
<td align="center"><h3>3</h3></td>
<td><b>Backup</b> — Write down 36 words in whatever language and form you prefer</td>
</tr>
<tr>
<td align="center"><h3>4</h3></td>
<td><b>Derive</b> — Seed + optional passphrase are hardened through PBKDF2 + Argon2id into a 512-bit master key</td>
</tr>
<tr>
<td align="center"><h3>5</h3></td>
<td><b>Recover</b> — Type your words in any supported language, or select the 36 icons visually</td>
</tr>
</table>

<br>

## Entropy

The system supports two entropy configurations:

<div align="center">

| Configuration | Words | Random + Checksum | Entropy | Post-Quantum | Use Case |
|:---|:---:|:---:|:---:|:---:|:---|
| **Standard (Quantum-Safe)** | 36 | 34 + 2 | 272-bit | 136-bit (Grover) | Quantum-safe — required for post-quantum key derivation |
| **Compact (Classical)** | 24 | 22 + 2 | 176-bit | 88-bit (Grover) | Classical security — sufficient for traditional crypto |

</div>

<br>

**272-bit** exceeds the strongest entropy level used in cryptocurrency. Brute-forcing a 272-bit seed would require more energy than the sun produces in its lifetime. Both configurations use the same 256-position icon set with full positional encoding, and include a 16-bit checksum (2 dedicated words) for error detection.

> **For quantum-safe applications, always use the 36-word format.** The 36-word seed provides 272-bit entropy (136-bit post-quantum), which exceeds NIST Level 3 (ML-DSA-65) and Level 5 requirements. The 24-word compact format (176-bit / 88-bit post-quantum) is suitable for classical cryptographic use only.

### Strength Comparison

| System | Effective Security | Post-Quantum | Brute-Force Resistance |
|:---|:---:|:---:|:---|
| Bitcoin (BIP-39, 24 words) | 256-bit | 128-bit (Grover) | Higher security industry standard |
| **Universal Quantum Seed (36 words)** | **272-bit** | **136-bit (Grover)** | **Quantum-safe tier** |
| **Universal Quantum Seed + passphrase** | **272+ bits** | **136+ bits** | **Second factor expands the keyspace further** |

The 36-word seed retains **136-bit security** even against a quantum computer running Grover's algorithm — well above the 128-bit post-quantum threshold. The 24-word format provides strong classical security (176-bit) but is not recommended for post-quantum key derivation.

<br>

## Seed Generation — Defense-in-Depth Entropy

Every generated seed mixes entropy from **multiple sources** through SHA-512 (a cryptographic randomness extractor). Even if some sources are weak, the output remains cryptographically strong as long as **any single source** provides real entropy. The OS CSPRNG alone is sufficient; additional sources provide defense in depth.

<div align="center">

| # | Source | What It Captures | Est. Entropy |
|:---:|:---|:---|:---:|
| 1 | **`secrets.token_bytes`** | OS CSPRNG (CryptGenRandom / `/dev/urandom`) | 512 bits |
| 2 | **`os.urandom`** | Separate OS CSPRNG call (defense-in-depth) | 512 bits |
| 3 | **`time.perf_counter_ns`** | Timer state mixed as additional input | low |
| 4 | **`os.getpid`** | Process-level uniqueness | low |
| 5 | **CPU jitter** | Instruction timing variance (cache/TLB/branch predictor) | variable |
| 6 | **Thread scheduling** | OS scheduler nondeterminism (4 batches × 8 threads) | variable |
| 7 | **Hardware RNG** | BCryptGenRandom (Windows) / `/dev/random` (Linux) + ASLR | 512 bits |
| 8 | **Mouse entropy** | User-supplied cursor movement (sub-pixel timing + position) | ~512 bits |

</div>

All sources are combined into a single SHA-512 pool, then a final `secrets.token_bytes` call is folded in to guarantee the output is **at minimum** as strong as the OS CSPRNG alone.

### Entropy Validation — Verified Before Use

Every call to `generate_words()` validates its entropy **before** using it for seed generation. Four statistical tests (based on NIST SP 800-22) are run on every sample:

| Test | What It Catches |
|:---|:---|
| **Monobit** | Bit bias — rejects if 0s and 1s aren't ~50/50 |
| **Chi-squared** | Byte frequency bias — rejects if byte values aren't uniformly distributed |
| **Runs** | Stuck patterns — rejects if bit transitions are predictable |
| **Autocorrelation** | Bit correlations — rejects if bit positions are dependent (Bonferroni-corrected) |

If any test fails, the entropy is **discarded and regenerated** — up to 10 attempts. Only entropy that passes all four tests is ever used. If all 10 attempts fail (indicating a broken or compromised RNG), seed generation raises a `RuntimeError` and refuses to produce a seed.

This means every seed generated by this system is backed by **statistically validated** entropy — not just trusted blindly from the OS.

### Why Multiple Sources?

A single CSPRNG (like `secrets`) is already sufficient for most applications. We go further because:

- **Defense in depth** — if one source has a flaw, the others compensate
- **Hardware diversity** — CPU jitter and thread scheduling capture physical nondeterminism independent from the OS random pool
- **User involvement** — mouse entropy gives users tangible participation in their own security
- **Provable minimum** — the SHA-512 mixing ensures the output has *at least* as much entropy as the best single source

<br>

## Key Derivation Pipeline — 6 Hardening Layers

After generation, the seed is transformed into a 512-bit master key through a **6-layer hardening pipeline**. Each layer addresses a specific attack vector:

```
  Seed (34 × 8-bit icons + 2 checksum) + optional Passphrase
         │
    ┌────▼─────────────────────┐
    │ 0. Checksum Verification │  Verifies the 2 checksum words
    │    & Stripping           │  Then strips them — only data words enter KDF
    └────┬─────────────────────┘
         │
    ┌────▼─────────────────────┐
    │ 1. Positional Binding    │  Each data icon tagged with its slot index
    │    (pos, icon) pairs     │  Prevents reordering attacks
    └────┬─────────────────────┘
         │
    ┌────▼─────────────────────┐
    │ 2. Passphrase Mixing     │  Optional second factor
    │                          │  Appended to payload before extraction
    └────┬─────────────────────┘
         │
    ┌────▼─────────────────────┐
    │ 3. HKDF-Extract          │  HMAC-SHA512 with domain separator
    │    RFC 5869              │  Collapses (seed + passphrase) → PRK
    └────┬─────────────────────┘
         │
    ┌────▼─────────────────────┐
    │ 4. Chained KDF           │  PBKDF2-SHA512 (600k rounds)
    │    PBKDF2 → Argon2id     │  then Argon2id (64 MiB × 3 iter × 4 lanes)
    └────┬─────────────────────┘
         │
    ┌────▼─────────────────────┐
    │ 5. HKDF-Expand           │  Domain-separated final derivation
    │    RFC 5869              │  Produces 64 bytes of key material
    └────┬─────────────────────┘
         │
    ┌────▼─────────────────────┐
    │ 512-bit Master Key       │  First 32 bytes: encryption key
    │ (64 bytes)               │  Last 32 bytes: authentication key
    └──────────────────────────┘
```

### Layer 1 — Positional Binding

Each icon is tagged with its **slot position** before hashing:

```
payload = [(pos=0, icon=15), (pos=1, icon=63), (pos=2, icon=136), ...]
```

**Why:** Each icon is cryptographically bound to its exact slot. Position tagging makes the security property **explicit** rather than relying on implicit byte ordering — the position-value relationship is part of the hashed data itself. This is a cryptographic best practice (structured commitment) that ensures `[dog, sun, key]` and `[sun, dog, key]` always produce completely different keys, regardless of how the payload is serialized.

### Layer 2 — Passphrase Mixing

The optional passphrase is UTF-8 encoded and appended to the position-tagged payload **before** extraction. This ensures the passphrase influences every downstream step:

```
payload = [(pos=0, icon=15), (pos=1, icon=63), ...] + passphrase_bytes
```

**Why:** The passphrase acts as a **second factor** (something you *know* in addition to the seed you *have*). By mixing it into the input keying material before HKDF-Extract, it becomes part of the PRK — and therefore affects the chained KDF, HKDF-Expand, and every derived key. Same seed + different passphrase = completely unrelated output. Brute-forcing the passphrase costs ~2 seconds per attempt (full PBKDF2 + Argon2id chain).

### Layer 3 — HKDF-Extract (RFC 5869)

The combined payload (seed + passphrase) is collapsed into a fixed-size **pseudorandom key (PRK)** using HMAC-SHA512 with a domain separator (`universal-seed-v1`):

```
PRK = HMAC-SHA512(key="universal-seed-v1", msg=payload)
```

**Why:** HKDF-Extract is a proven randomness extractor. It takes the variable-length payload (which may have structure — repeating icons, short seeds, passphrase) and produces a uniformly distributed 512-bit key. The domain separator ensures that keys derived by this system can **never collide** with keys from any other system, even if the input data is identical.

### Layer 4 — Chained Key Stretching (PBKDF2 → Argon2id)

The PRK is stretched through **two KDFs in series** — PBKDF2-SHA512 first, then Argon2id on top. Both always run; an attacker must break both to recover the key.

| Parameter | Stage 1: PBKDF2-SHA512 | Stage 2: Argon2id |
|:---|:---|:---|
| **Rounds / Iterations** | 600,000 | 3 |
| **Memory** | N/A | 64 MiB per guess |
| **Parallelism** | N/A | 4 lanes |
| **Output** | 64 bytes → fed into Stage 2 | 64 bytes (final) |
| **GPU resistance** | Low | **High** (memory-hard) |
| **ASIC resistance** | Low | **High** (memory-hard) |

```
stage1    = PBKDF2-SHA512(PRK, salt="universal-seed-v1-stretch-pbkdf2", rounds=600000)
stretched = Argon2id(secret=stage1, salt="universal-seed-v1-stretch-argon2id")
```

**Why:** Defense in depth. PBKDF2-SHA512 provides a proven, NIST-approved baseline that resists brute force through sheer iteration count. Argon2id adds memory-hardness on top, making GPU/ASIC parallelization impractical — each attempt requires 64 MiB of RAM. If a vulnerability were ever found in one algorithm, the other still protects the key.

Argon2id is the **winner of the Password Hashing Competition** (2015) and the current OWASP recommendation for high-value targets.

```bash
pip install argon2-cffi   # required
```

### Layer 5 — HKDF-Expand (RFC 5869)

The stretched key is expanded into the final 64-byte master key using HKDF-Expand with a domain-specific info string:

```
master_key = HKDF-Expand(PRK=stretched, info="universal-seed-v1-master", length=64)
```

**Why:** HKDF-Expand provides **domain separation** for the final output. If this system ever needs to derive multiple keys (e.g., encryption key + authentication key), each can use a different info string. The first 32 bytes serve as a 256-bit encryption key, and the last 32 bytes serve as a 256-bit authentication key.

<br>

## Passphrase — Optional Second Factor

The passphrase acts as a **second factor** that makes the derived key dependent on something the user **knows**, in addition to the seed they **have**.

| Scenario | Result |
|:---|:---|
| Same seed, no passphrase | Always produces the same key |
| Same seed + passphrase A | Key X |
| Same seed + passphrase B | Completely unrelated Key Y |
| Different seed + passphrase A | Completely unrelated Key Z |

Key properties:
- The passphrase **only affects the derived key and fingerprint**, not the displayed words/icons
- An empty passphrase is valid and produces a deterministic key
- The passphrase goes through the full PBKDF2 + Argon2id pipeline — brute-forcing is expensive
- Entropy from the passphrase **adds to** the seed entropy (272 + passphrase bits)

### Entropy Estimation

The `get_entropy_bits()` function estimates total security strength:

```python
from seed import get_entropy_bits

get_entropy_bits(36)                    # → 272.0 (seed only)
get_entropy_bits(36, "hunter2")         # → 305.3 (+ passphrase)
get_entropy_bits(36, "Tr0ub4dor&3")    # → 337.2 (mixed case + digits + symbols)
get_entropy_bits(24)                    # → 176.0 (compact seed)
get_entropy_bits(24, "パスワード")       # → 225.2 (+ Unicode passphrase)
```

Passphrase entropy is estimated from the character set used:

| Character Set | Bits per Character |
|:---|:---:|
| Digits only (0-9) | ~3.32 |
| Lowercase only (a-z) | ~4.70 |
| Mixed case (a-z, A-Z) | ~5.70 |
| Mixed + digits | ~5.95 |
| Full printable (+ symbols) | ~6.55 |
| Unicode (non-ASCII) | ~7.00 |

<br>

## Hidden Profiles — Multiple Accounts, One Seed

Hidden profiles let you derive **unlimited independent keys** from a single master key using profile passwords. Each profile password produces a completely unrelated key — and without the password, no one can detect that the profile exists.

```
Seed → Master Key (expensive KDF — runs once)
  ├── default (no password) = master key
  ├── "personal"  → independent 64-byte key
  ├── "business"  → independent 64-byte key
  └── "savings"   → independent 64-byte key
```

```python
from seed import generate_words, get_seed, get_profile

words = generate_words(36)
seed  = get_seed(words)

personal = get_profile(seed, "personal")    # independent key
business = get_profile(seed, "business")    # completely unrelated
savings  = get_profile(seed, "savings")     # each password = new account
default  = get_profile(seed, "")            # empty = master key itself
```

| Property | Detail |
|:---|:---|
| Algorithm | HMAC-SHA512(master_key, domain + password) |
| Speed | Instant — single HMAC, no KDF (master key is already hardened) |
| Deterministic | Same password always produces the same key |
| Independent | Profiles cannot be derived from each other |
| Hidden | No way to enumerate how many profiles exist |
| Plausible deniability | Under duress, reveal only the default profile |

**Why this matters:** With BIP-39, one seed = one wallet. To manage multiple accounts you need multiple seeds. With the Universal Quantum Seed, one seed + profile passwords = unlimited independent wallets, all hidden behind a single backup.

<br>

## Using seed.py in Python

Everything lives in a single file — `seed.py`. Import it and you get seed generation, key derivation, word lookup, and entropy estimation.

### Installation

```bash
pip install argon2-cffi   # required — used in the chained KDF pipeline
```

No other dependencies required. `seed.py` uses only Python standard library plus `argon2-cffi`.

### Quick Start

```python
from seed import generate_words, get_seed, get_fingerprint, get_entropy_bits, get_languages, verify_checksum

# Generate 36 words (272-bit entropy, 34 random + 2 checksum)
words = generate_words(36)
# → [(15, "dog"), (63, "sun"), (136, "key"), ..., (cs1, "word"), (cs2, "word")]

# Generate in a specific language
words = generate_words(36, language="french")
# → [(15, "chien"), (63, "soleil"), (136, "clé"), ...]

# List available languages
get_languages()
# → [("english", "English"), ("arabic", "العربية"), ("french", "Français"), ...]

# Derive the master seed — pass the words directly
seed = get_seed(words)                  # 64-byte master seed
fp   = get_fingerprint(words)           # "A3F1B2C4"

# Verify checksum (last 2 words)
verify_checksum(words)                  # True

# With a passphrase (second factor — same words, different passphrase = different seed)
seed = get_seed(words, "my secret passphrase")

# Hidden profiles — multiple accounts from one seed
from seed import get_profile
personal = get_profile(seed, "personal")       # independent 64-byte key
business = get_profile(seed, "business")       # completely unrelated key

# Post-quantum keypair from the same seed
from seed import generate_quantum_keypair
sk, pk = generate_quantum_keypair(seed)                    # ML-DSA-65 (default)
sk, pk = generate_quantum_keypair(seed, "hybrid-dsa-65")   # Ed25519 + ML-DSA-65 hybrid
ek, dk = generate_quantum_keypair(seed, "hybrid-kem-768")  # X25519 + ML-KEM-768 hybrid

# Also accepts plain word strings or raw indexes (must be 24 or 36 with valid checksum)
plain = [w for _, w in words]          # extract word strings
seed  = get_seed(plain)                # resolve words → indexes → seed
seed  = get_seed([i for i, _ in words])  # raw indexes work too

# Estimate total entropy
bits = get_entropy_bits(36, "my secret passphrase")
# → 383.8 (272 seed + 111.8 passphrase)
```

### Word Resolution

```python
from seed import resolve, search

# Resolve any word in any of 42 languages → icon index
resolve("dog")       # → 15
resolve("perro")     # → 15  (Spanish)
resolve("犬")        # → 15  (Japanese)
resolve("🐕")        # → 15  (emoji)
resolve("corazón")   # → 8   (with accent)
resolve("corazon")   # → 8   (without accent — same result)
resolve("собака")    # → 15  (Russian)
resolve("unknown")   # → None

# Autocomplete suggestions
search("do")
# → [("doctor", 211), ("dog", 15), ("dolphin", 54), ("door", 158)]

# Resolve a full seed phrase at once (pass a list)
indexes, errors = resolve(["dog", "sun", "key", "heart"])
# indexes = [15, 63, 136, 8], errors = []
```

### Mouse Entropy

```python
from seed import mouse_entropy, generate_words

# Create an entropy pool
pool = mouse_entropy()

# Feed mouse movements (call on each mouse move event)
pool.add_sample(x=412, y=308)   # → True (new position)
pool.add_sample(x=412, y=308)   # → False (duplicate, skipped)
pool.add_sample(x=415, y=310)   # → True

# Check progress
pool.bits_collected   # → 4 (2 bits per unique sample)
pool.sample_count     # → 2

# Extract and use
extra = pool.digest()                         # 64 bytes of entropy
words = generate_words(36, extra_entropy=extra)  # mixed into generation
```

### Randomness Verification

Verify that the entropy source is producing high-quality randomness before trusting it for seed generation:

```python
from seed import verify_randomness

result = verify_randomness()

# Check overall result
if not result["pass"]:
    raise RuntimeError("Weak randomness detected!")

# Iterate individual tests
for test in result["tests"]:
    status = "PASS" if test["pass"] else "FAIL"
    print(f"{test['test']}: {status}")
```

Four statistical tests based on NIST SP 800-22:

| Test | What It Detects |
|:---|:---|
| **Monobit** | Bit bias — 0s and 1s should be ~50/50 |
| **Chi-squared** | Byte frequency bias — all 256 values should appear uniformly |
| **Runs** | Stuck patterns — bit transitions should be random |
| **Autocorrelation** | Bit correlations — each bit position should be independent |

The test app (`examples/universal.py`) includes a `RandomnessDialog` window that runs these tests with a progress bar and displays checkmarks for each passing test.

### KDF Backend Info

```python
from seed import kdf_info

print(kdf_info())
# → "PBKDF2-SHA512 (600,000 rounds) + Argon2id (mem=65536KB, t=3, p=4)"
```

### API Reference

| Function | Signature | Returns |
|:---|:---|:---|
| `generate_words` | `generate_words(word_count=36, extra_entropy=None, language=None)` | `list[(int, str)]` — index/word pairs (last 2 are checksum) |
| `verify_checksum` | `verify_checksum(words)` | `bool` — True if last 2 words match expected checksum |
| `get_seed` | `get_seed(words, passphrase="")` | `bytes` — 64-byte master seed (checksum verified & stripped) |
| `get_profile` | `get_profile(seed, profile_password)` | `bytes` — 64-byte profile key (instant HMAC, no KDF) |
| `get_fingerprint` | `get_fingerprint(seed, passphrase="")` | `str` — 8-char hex (checksum stripped) |
| `get_entropy_bits` | `get_entropy_bits(word_count, passphrase="")` | `float` — estimated total entropy |
| `resolve` | `resolve(word_or_list, strict=False)` | `str` → `int \| None`; `list` → `(indexes, errors)` |
| `search` | `search(prefix, limit=10)` | `list[(str, int)]` — word/index pairs |
| `verify_randomness` | `verify_randomness(sample_bytes=None, sample_size=2048, num_samples=5)` | `dict` — `{"pass": bool, "tests": [...], "summary": str}` |
| `mouse_entropy` | class | Entropy collection pool |
| `get_languages` | `get_languages()` | `list[(str, str)]` — (code, label) pairs |
| `get_quantum_seed` | `get_quantum_seed(master_key, algorithm="ml-dsa-65", key_index=0)` | `bytes` — raw quantum seed material (32–96 bytes) |
| `generate_quantum_keypair` | `generate_quantum_keypair(master_key, algorithm="ml-dsa-65", key_index=0)` | `tuple[bytes, bytes]` — (secret_key, public_key) |
| `hybrid_dsa_keygen` | `hybrid_dsa_keygen(seed_64B)` | `tuple[bytes, bytes]` — (4,096B sk, 1,984B pk) |
| `hybrid_dsa_sign` | `hybrid_dsa_sign(message, sk, ctx=b"")` | `bytes` — 3,373B hybrid signature |
| `hybrid_dsa_verify` | `hybrid_dsa_verify(message, sig, pk, ctx=b"")` | `bool` — True if both Ed25519 AND ML-DSA verify |
| `hybrid_kem_keygen` | `hybrid_kem_keygen(seed_96B)` | `tuple[bytes, bytes]` — (1,216B ek, 2,432B dk) |
| `hybrid_kem_encaps` | `hybrid_kem_encaps(ek, randomness=None)` | `tuple[bytes, bytes]` — (1,120B ct, 32B shared_secret) |
| `hybrid_kem_decaps` | `hybrid_kem_decaps(dk, ct)` | `bytes` — 32B shared secret |
| `kdf_info` | `kdf_info()` | `str` — chained KDF pipeline description |

<br>

## Supported Languages

**42 languages** covering **85%+** of the world's internet-connected population.

<br>

<table>
<thead>
<tr>
<th align="center">#</th>
<th>Flag</th>
<th>Language</th>
<th>Native Name</th>
<th>Script</th>
</tr>
</thead>
<tbody>
<tr><td align="center">1</td><td>:saudi_arabia:</td><td>Arabic</td><td>العربية</td><td>Arabic</td></tr>
<tr><td align="center">2</td><td>:bangladesh:</td><td>Bengali</td><td>বাংলা</td><td>Bengali</td></tr>
<tr><td align="center">3</td><td>:hong_kong:</td><td>Chinese (Cantonese)</td><td>廣東話</td><td>Traditional Chinese</td></tr>
<tr><td align="center">4</td><td>:cn:</td><td>Chinese (Simplified)</td><td>简体中文</td><td>Simplified Chinese</td></tr>
<tr><td align="center">5</td><td>:taiwan:</td><td>Chinese (Traditional)</td><td>繁體中文</td><td>Traditional Chinese</td></tr>
<tr><td align="center">6</td><td>:czech_republic:</td><td>Czech</td><td>Čeština</td><td>Latin</td></tr>
<tr><td align="center">7</td><td>:denmark:</td><td>Danish</td><td>Dansk</td><td>Latin</td></tr>
<tr><td align="center">8</td><td>:netherlands:</td><td>Dutch</td><td>Nederlands</td><td>Latin</td></tr>
<tr><td align="center">9</td><td>:gb:</td><td>English</td><td>English</td><td>Latin</td></tr>
<tr><td align="center">10</td><td>:philippines:</td><td>Filipino</td><td>Filipino</td><td>Latin</td></tr>
<tr><td align="center">11</td><td>:fr:</td><td>French</td><td>Français</td><td>Latin</td></tr>
<tr><td align="center">12</td><td>:de:</td><td>German</td><td>Deutsch</td><td>Latin</td></tr>
<tr><td align="center">13</td><td>:greece:</td><td>Greek</td><td>Ελληνικά</td><td>Greek</td></tr>
<tr><td align="center">14</td><td>:nigeria:</td><td>Hausa</td><td>Hausa</td><td>Latin</td></tr>
<tr><td align="center">15</td><td>:israel:</td><td>Hebrew</td><td>עברית</td><td>Hebrew</td></tr>
<tr><td align="center">16</td><td>:india:</td><td>Hindi</td><td>हिन्दी</td><td>Devanagari</td></tr>
<tr><td align="center">17</td><td>:hungary:</td><td>Hungarian</td><td>Magyar</td><td>Latin</td></tr>
<tr><td align="center">18</td><td>:iceland:</td><td>Icelandic</td><td>Íslenska</td><td>Latin</td></tr>
<tr><td align="center">19</td><td>:indonesia:</td><td>Indonesian</td><td>Bahasa Indonesia</td><td>Latin</td></tr>
<tr><td align="center">20</td><td>:ireland:</td><td>Irish</td><td>Gaeilge</td><td>Latin</td></tr>
<tr><td align="center">21</td><td>:it:</td><td>Italian</td><td>Italiano</td><td>Latin</td></tr>
<tr><td align="center">22</td><td>:jp:</td><td>Japanese</td><td>日本語</td><td>Kanji / Kana</td></tr>
<tr><td align="center">23</td><td>:kr:</td><td>Korean</td><td>한국어</td><td>Hangul</td></tr>
<tr><td align="center">24</td><td>:luxembourg:</td><td>Luxembourgish</td><td>Lëtzebuergesch</td><td>Latin</td></tr>
<tr><td align="center">25</td><td>:malaysia:</td><td>Malay</td><td>Bahasa Melayu</td><td>Latin</td></tr>
<tr><td align="center">26</td><td>:india:</td><td>Marathi</td><td>मराठी</td><td>Devanagari</td></tr>
<tr><td align="center">27</td><td>:norway:</td><td>Norwegian</td><td>Norsk</td><td>Latin</td></tr>
<tr><td align="center">28</td><td>:iran:</td><td>Persian</td><td>فارسی</td><td>Arabic</td></tr>
<tr><td align="center">29</td><td>:poland:</td><td>Polish</td><td>Polski</td><td>Latin</td></tr>
<tr><td align="center">30</td><td>:brazil:</td><td>Portuguese</td><td>Português</td><td>Latin</td></tr>
<tr><td align="center">31</td><td>:india:</td><td>Punjabi</td><td>ਪੰਜਾਬੀ</td><td>Gurmukhi</td></tr>
<tr><td align="center">32</td><td>:romania:</td><td>Romanian</td><td>Română</td><td>Latin</td></tr>
<tr><td align="center">33</td><td>:ru:</td><td>Russian</td><td>Русский</td><td>Cyrillic</td></tr>
<tr><td align="center">34</td><td>:es:</td><td>Spanish</td><td>Español</td><td>Latin</td></tr>
<tr><td align="center">35</td><td>:tanzania:</td><td>Swahili</td><td>Kiswahili</td><td>Latin</td></tr>
<tr><td align="center">36</td><td>:india:</td><td>Tamil</td><td>தமிழ்</td><td>Tamil</td></tr>
<tr><td align="center">37</td><td>:india:</td><td>Telugu</td><td>తెలుగు</td><td>Telugu</td></tr>
<tr><td align="center">38</td><td>:thailand:</td><td>Thai</td><td>ไทย</td><td>Thai</td></tr>
<tr><td align="center">39</td><td>:tr:</td><td>Turkish</td><td>Türkçe</td><td>Latin</td></tr>
<tr><td align="center">40</td><td>:ukraine:</td><td>Ukrainian</td><td>Українська</td><td>Cyrillic</td></tr>
<tr><td align="center">41</td><td>:pakistan:</td><td>Urdu</td><td>اردو</td><td>Arabic</td></tr>
<tr><td align="center">42</td><td>:vietnam:</td><td>Vietnamese</td><td>Tiếng Việt</td><td>Latin</td></tr>
</tbody>
</table>

<br>

**10 scripts supported** — Latin · Arabic · Hebrew · Devanagari · Bengali · Gurmukhi · Tamil · Telugu · Thai · CJK

<br>

## Visual Icon Library

**256 universally recognizable icons** — a dog is a dog everywhere, the sun is the sun, a key is a key.

All icons are available as **PNG** (256×256, transparent background) in `visuals/png/` and **SVG** in `visuals/svg/`, named by index (`0.png` through `255.png`).

<br>

<details>
<summary><b>Body Parts</b> &nbsp;·&nbsp; <code>0 – 14</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 0 | :eye: | eye | | 8 | :heart: | heart |
| 1 | :ear: | ear | | 9 | :brain: | brain |
| 2 | :nose: | nose | | 10 | :baby: | baby |
| 3 | :lips: | mouth | | 11 | :foot: | foot |
| 4 | :tongue: | tongue | | 12 | :muscle: | muscle |
| 5 | :bone: | bone | | 13 | :hand: | hand |
| 6 | :tooth: | tooth | | 14 | :leg: | leg |
| 7 | :skull: | skull | | | | |

</details>

<details>
<summary><b>Mammals</b> &nbsp;·&nbsp; <code>15 – 37</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 15 | :dog2: | dog | | 27 | :deer: | deer |
| 16 | :cat2: | cat | | 28 | :elephant: | elephant |
| 17 | :racehorse: | horse | | 29 | :bat: | bat |
| 18 | :cow2: | cow | | 30 | :camel: | camel |
| 19 | :pig2: | pig | | 31 | :zebra: | zebra |
| 20 | :goat: | goat | | 32 | :giraffe: | giraffe |
| 21 | :rabbit2: | rabbit | | 33 | :fox_face: | fox |
| 22 | :mouse2: | mouse | | 34 | :lion: | lion |
| 23 | :tiger2: | tiger | | 35 | :monkey: | monkey |
| 24 | :wolf: | wolf | | 36 | :panda_face: | panda |
| 25 | :bear: | bear | | 37 | :llama: | llama |
| 26 | :chipmunk: | squirrel | | | | |

</details>

<details>
<summary><b>Birds</b> &nbsp;·&nbsp; <code>38 – 44</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 38 | :chicken: | chicken | | 42 | :peacock: | peacock |
| 39 | :bird: | bird | | 43 | :owl: | owl |
| 40 | :duck: | duck | | 44 | :eagle: | eagle |
| 41 | :penguin: | penguin | | | | |

</details>

<details>
<summary><b>Reptiles & Amphibians</b> &nbsp;·&nbsp; <code>45 – 49</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 45 | :snake: | snake | | 48 | :crocodile: | crocodile |
| 46 | :frog: | frog | | 49 | :lizard: | lizard |
| 47 | :turtle: | turtle | | | | |

</details>

<details>
<summary><b>Aquatic</b> &nbsp;·&nbsp; <code>50 – 55</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 50 | :fish: | fish | | 53 | :whale: | whale |
| 51 | :octopus: | octopus | | 54 | :dolphin: | dolphin |
| 52 | :crab: | crab | | 55 | :shark: | shark |

</details>

<details>
<summary><b>Bugs & Crawlers</b> &nbsp;·&nbsp; <code>56 – 62</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 56 | :snail: | snail | | 60 | :worm: | worm |
| 57 | :ant: | ant | | 61 | :spider: | spider |
| 58 | :bee: | bee | | 62 | :scorpion: | scorpion |
| 59 | :butterfly: | butterfly | | | | |

</details>

<details>
<summary><b>Sky & Weather</b> &nbsp;·&nbsp; <code>63 – 78</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 63 | :sunny: | sun | | 71 | :rainbow: | rainbow |
| 64 | :crescent_moon: | moon | | 72 | :dash: | wind |
| 65 | :star: | star | | 73 | :zap: | thunder |
| 66 | :earth_africa: | earth | | 74 | :volcano: | volcano |
| 67 | :fire: | fire | | 75 | :tornado: | tornado |
| 68 | :droplet: | water | | 76 | :comet: | comet |
| 69 | :snowflake: | snow | | 77 | :ocean: | wave |
| 70 | :cloud: | cloud | | 78 | :cloud_with_rain: | rain |

</details>

<details>
<summary><b>Landscapes</b> &nbsp;·&nbsp; <code>79 – 84</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 79 | :desert: | desert | | 82 | :rock: | rock |
| 80 | :desert_island: | island | | 83 | :gem: | diamond |
| 81 | :mountain: | mountain | | 84 | :feather: | feather |

</details>

<details>
<summary><b>Plants & Fungi</b> &nbsp;·&nbsp; <code>85 – 90</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 85 | :deciduous_tree: | tree | | 88 | :leaves: | leaf |
| 86 | :cactus: | cactus | | 89 | :mushroom: | mushroom |
| 87 | :cherry_blossom: | flower | | 90 | :wood: | wood |

</details>

<details>
<summary><b>Fruits</b> &nbsp;·&nbsp; <code>91 – 104</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 91 | :mango: | mango | | 98 | :pineapple: | pineapple |
| 92 | :apple: | apple | | 99 | :cherries: | cherry |
| 93 | :banana: | banana | | 100 | :lemon: | lemon |
| 94 | :grapes: | grape | | 101 | :coconut: | coconut |
| 95 | :tangerine: | orange | | 102 | :cucumber: | cucumber |
| 96 | :melon: | melon | | 103 | :seedling: | seed |
| 97 | :peach: | peach | | 104 | :strawberry: | strawberry |

</details>

<details>
<summary><b>Vegetables</b> &nbsp;·&nbsp; <code>105 – 112</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 105 | :corn: | corn | | 109 | :hot_pepper: | pepper |
| 106 | :carrot: | carrot | | 110 | :tomato: | tomato |
| 107 | :onion: | onion | | 111 | :garlic: | garlic |
| 108 | :potato: | potato | | 112 | :peanuts: | peanut |

</details>

<details>
<summary><b>Prepared Food</b> &nbsp;·&nbsp; <code>113 – 120</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 113 | :bread: | bread | | 117 | :rice: | rice |
| 114 | :cheese: | cheese | | 118 | :birthday: | cake |
| 115 | :egg: | egg | | 119 | :popcorn: | snack |
| 116 | :cut_of_meat: | meat | | 120 | :candy: | sweet |

</details>

<details>
<summary><b>Food & Drink</b> &nbsp;·&nbsp; <code>121 – 128</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 121 | :honey_pot: | honey | | 125 | :wine_glass: | wine |
| 122 | :milk_glass: | milk | | 126 | :beer: | beer |
| 123 | :coffee: | coffee | | 127 | :beverage_box: | juice |
| 124 | :tea: | tea | | 128 | :salt: | salt |

</details>

<details>
<summary><b>Kitchen</b> &nbsp;·&nbsp; <code>129 – 135</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 129 | :fork_and_knife: | fork | | 133 | :sake: | bottle |
| 130 | :spoon: | spoon | | 134 | :ramen: | soup |
| 131 | :bowl_with_spoon: | bowl | | 135 | :fried_egg: | pan |
| 132 | :hocho: | knife | | | | |

</details>

<details>
<summary><b>Tools & Weapons</b> &nbsp;·&nbsp; <code>136 – 152</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 136 | :key: | key | | 145 | :compass: | compass |
| 137 | :lock: | lock | | 146 | :hook: | hook |
| 138 | :bell: | bell | | 147 | :thread: | thread |
| 139 | :hammer: | hammer | | 148 | :sewing_needle: | needle |
| 140 | :axe: | axe | | 149 | :scissors: | scissors |
| 141 | :gear: | gear | | 150 | :pencil2: | pencil |
| 142 | :magnet: | magnet | | 151 | :shield: | shield |
| 143 | :crossed_swords: | sword | | 152 | :bomb: | bomb |
| 144 | :bow_and_arrow: | bow | | | | |

</details>

<details>
<summary><b>Buildings</b> &nbsp;·&nbsp; <code>153 – 164</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 153 | :house: | house | | 159 | :window: | window |
| 154 | :european_castle: | castle | | 160 | :tent: | tent |
| 155 | :shinto_shrine: | temple | | 161 | :beach_umbrella: | beach |
| 156 | :bridge_at_night: | bridge | | 162 | :bank: | bank |
| 157 | :factory: | factory | | 163 | :tokyo_tower: | tower |
| 158 | :door: | door | | 164 | :statue_of_liberty: | statue |

</details>

<details>
<summary><b>Transport</b> &nbsp;·&nbsp; <code>165 – 176</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 165 | :wheel: | wheel | | 171 | :rocket: | rocket |
| 166 | :sailboat: | boat | | 172 | :helicopter: | helicopter |
| 167 | :steam_locomotive: | train | | 173 | :ambulance: | ambulance |
| 168 | :red_car: | car | | 174 | :fuelpump: | fuel |
| 169 | :bike: | bike | | 175 | :railway_track: | track |
| 170 | :airplane: | plane | | 176 | :world_map: | map |

</details>

<details>
<summary><b>Music & Arts</b> &nbsp;·&nbsp; <code>177 – 188</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 177 | :drum: | drum | | 183 | :performing_arts: | mask |
| 178 | :guitar: | guitar | | 184 | :camera: | camera |
| 179 | :violin: | violin | | 185 | :microphone: | microphone |
| 180 | :musical_keyboard: | piano | | 186 | :headphones: | headset |
| 181 | :art: | paint | | 187 | :clapper: | movie |
| 182 | :book: | book | | 188 | :musical_note: | music |

</details>

<details>
<summary><b>Clothing</b> &nbsp;·&nbsp; <code>189 – 195</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 189 | :dress: | dress | | 193 | :necktie: | shirt |
| 190 | :coat: | coat | | 194 | :athletic_shoe: | shoes |
| 191 | :jeans: | pants | | 195 | :tophat: | hat |
| 192 | :gloves: | glove | | | | |

</details>

<details>
<summary><b>Symbols</b> &nbsp;·&nbsp; <code>196 – 207</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 196 | :triangular_flag_on_post: | flag | | 202 | :warning: | alert |
| 197 | :latin_cross: | cross | | 203 | :zzz: | sleep |
| 198 | :o: | circle | | 204 | :magic_wand: | magic |
| 199 | :small_red_triangle: | triangle | | 205 | :speech_balloon: | message |
| 200 | :blue_square: | square | | 206 | :drop_of_blood: | blood |
| 201 | :white_check_mark: | check | | 207 | :repeat: | repeat |

</details>

<details>
<summary><b>Science & Tech</b> &nbsp;·&nbsp; <code>208 – 223</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 208 | :dna: | dna | | 216 | :artificial_satellite: | satellite |
| 209 | :microbe: | germ | | 217 | :battery: | battery |
| 210 | :pill: | pill | | 218 | :telescope: | telescope |
| 211 | :stethoscope: | doctor | | 219 | :tv: | tv |
| 212 | :microscope: | microscope | | 220 | :radio: | radio |
| 213 | :milky_way: | galaxy | | 221 | :iphone: | phone |
| 214 | :test_tube: | flask | | 222 | :bulb: | bulb |
| 215 | :atom_symbol: | atom | | 223 | :keyboard: | keyboard |

</details>

<details>
<summary><b>Home</b> &nbsp;·&nbsp; <code>224 – 235</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 224 | :chair: | chair | | 230 | :amphora: | vase |
| 225 | :bed: | bed | | 231 | :shower: | shower |
| 226 | :candle: | candle | | 232 | :razor: | razor |
| 227 | :mirror: | mirror | | 233 | :soap: | soap |
| 228 | :ladder: | ladder | | 234 | :computer: | computer |
| 229 | :basket: | basket | | 235 | :wastebasket: | trash |

</details>

<details>
<summary><b>Everyday Items</b> &nbsp;·&nbsp; <code>236 – 245</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 236 | :umbrella: | umbrella | | 241 | :ring: | ring |
| 237 | :moneybag: | money | | 242 | :game_die: | dice |
| 238 | :pray: | prayer | | 243 | :jigsaw: | piece |
| 239 | :teddy_bear: | toy | | 244 | :coin: | coin |
| 240 | :crown: | crown | | 245 | :calendar: | calendar |

</details>

<details>
<summary><b>Sports & Games</b> &nbsp;·&nbsp; <code>246 – 249</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 246 | :boxing_glove: | boxing | | 248 | :video_game: | game |
| 247 | :swimming_man: | swimming | | 249 | :soccer: | soccer |

</details>

<details>
<summary><b>Fantasy</b> &nbsp;·&nbsp; <code>250 – 254</code></summary>
<br>

| Index | Icon | Word | | Index | Icon | Word |
|:---:|:---:|---|---|:---:|:---:|---|
| 250 | :ghost: | ghost | | 253 | :angel: | angel |
| 251 | :alien: | alien | | 254 | :dragon: | dragon |
| 252 | :robot: | robot | | | | |

</details>

<details>
<summary><b>Time</b> &nbsp;·&nbsp; <code>255</code></summary>
<br>

| Index | Icon | Word |
|:---:|:---:|---|
| 255 | :clock1: | clock |

</details>

<br>

## Word Lookup System

All 42 language word lists plus emoji characters are compiled into a single Python module (`words.py`) containing a flat hash table for **instant** word resolution and embedded language maps for generation in any language.

<br>

### Capabilities

| Feature | How it works |
|---|---|
| **Emoji input** | Typing or pasting an emoji (e.g. :muscle: :dog2: :sunny:) resolves directly to its visual index |
| **NFKC normalization** | Full-width characters, ligatures, and composed forms unified automatically |
| **Zero-width removal** | ZWJ, ZWNJ, soft hyphens, BOM, and invisible characters stripped |
| **Case insensitive** | All lookups are lowercase-normalized |
| **Prefix search** | Built-in `search()` for autocomplete / search UI |

<br>

### Diacritic-Insensitive Matching

Smart per-script handling — marks are only stripped where it's safe:

| Script | Behavior | Example |
|---|---|---|
| **Latin** | Accents removed | `corazón` → `corazon`, `ß` → `ss`, `ø` → `o`, `æ` → `ae` |
| **Greek** | Tonos removed | `σκύλος` → `σκυλος` |
| **Arabic** | Tashkeel removed | Vowel marks (harakat) are optional |
| **Hebrew** | Niqqud removed | Vowel points are optional |
| **Cyrillic** | ё → е | Common Russian substitution |
| **Thai, Devanagari, Bengali, Tamil, Telugu, Gurmukhi** | **Preserved** | Marks change meaning — never stripped |

<br>

### Performance

| Operation | Time | Notes |
|:---|:---|:---|
| **Import** | ~50 ms | One-time at startup (38,730 keys, cached `.pyc`) |
| **Generate 36 words** | ~9 ms | Full entropy collection + checksum |
| **Generate 24 words** | ~5 ms | Full entropy collection + checksum |
| **Key derivation** | ~2 sec | PBKDF2 (600k rounds) + Argon2id (64 MiB) |
| **Word resolve** | ~0.01 ms | O(1) hash table lookup |
| **Prefix search** | ~0.04 ms | Binary search + dedup |
| **36-word seed resolve** | ~0.3 ms | 36 × resolve |
| **Fingerprint (no passphrase)** | <0.01 ms | HMAC only |
| **Fingerprint (with passphrase)** | ~2 sec | Full chained KDF pipeline |

### Word Coverage

| Stat | Value |
|:---|:---|
| Total lookup keys | **38,730** across 42 languages + emoji |
| Avg words per position | **3.5** |
| Max word length (shortest per index) | **7 chars** across all languages |
| Languages with 0 single-word indexes | **36** of 42 |
| Cross-language collisions | **0** |
| File size (words.py) | **1,186 KB** |

<br>

## Example

A user generates a seed and sees:

```
Position 1:  🐕  dog
Position 2:  ☀️  sun
Position 3:  🔑  key
         ...
```

They write their backup on paper — in any language, using any accepted word, or even a personal synonym that reminds them of the visual:

| Approach | Backup | Why it works |
|:---|:---|:---|
| :gb: English | `dog  sun  key  ...` | Direct base words |
| :es: Spanish | `perro  sol  llave  ...` | Native language |
| :jp: Japanese | `犬  太陽  鍵  ...` | Any supported script |
| Mixed | `dog  soleil  key  ...` | Languages can be combined freely |
| Personal hints | `puppy  bright  lock  ...` | Any accepted synonym — write what makes sense to you |

To recover, they type what they wrote — in any language — and the system maps each word back to its visual position. Alternatively, they can select the **36 icons directly**, bypassing language entirely.

<br>

## Running the Test

A test app is included for trying out seed generation and recovery.

```bash
pip install PySide6
pip install argon2-cffi   # required for key derivation
python examples/universal.py
```

<br>

## Contributing

Contributions are welcome — especially for improving word coverage across languages. Adding more synonyms, shorter alternatives, regional variants, and colloquial terms for each visual position would be very appreciated.

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute, the file format, and guidelines for adding words.

<br>

## Third-Party Licenses

Visual icons are from [Microsoft Fluent Emoji](https://github.com/microsoft/fluentui-emoji) (flat style), used under the MIT License. See [visuals/LICENSE](visuals/LICENSE) for details.

<br>

## License

MIT License. See [LICENSE](LICENSE).

<br>

---

<div align="center">

**Quantum-safe. Built for everyone, everywhere.**

<sub>Post-quantum signatures · 42 languages · 256 icons · PBKDF2 + Argon2id hardened · 272-bit quantum-safe (36 words) · 16-bit checksum</sub>

</div>
