# Universal Seed System — Specification v1

**Status:** Frozen (immutable)
**Version:** 1.0 through 1.3
**Domain separator:** `universal-seed-v1`

> **Compatibility contract:** v1 seeds MUST always derive the same outputs forever.
> No parameter may be changed within v1. If parameters change, a new version (v2+)
> with a new domain separator and spec folder MUST be created. Never "tune Argon2"
> or adjust PBKDF2 rounds inside v1.

---

## 1. Overview

v1 generates seeds as sequences of icon indexes (0-255), where every word is pure entropy
(no checksum words). Key derivation uses a 5-layer hardening pipeline.

| Property | Value |
|:---|:---|
| Word counts | 16 or 32 |
| Entropy | 16 words = 128-bit, 32 words = 256-bit |
| Checksum | None (all words are entropy) |
| Fingerprint | 4-char hex (2 bytes) |
| Domain separator | `b"universal-seed-v1"` |
| Icon set | 256 icons, indexed 0-255 |

---

## 2. Icon-Index Mapping

Each index (0-255) maps to exactly one icon. Icons are identified by their index, not by filename. Filenames are cosmetic; the index is authoritative.

The canonical icon assets are in `visuals/` (256x256 PNG + SVG, Fluent Emoji flat style). If icons are re-rendered, the index mapping MUST NOT change. The visual appearance is for human reference only — the cryptographic system operates on indexes.

See `test-vectors.json` for the complete index-to-base-word mapping.

Base word list (index 0-255):
```
  0: eye       1: ear       2: nose      3: mouth     4: tongue    5: bone
  6: tooth     7: skull     8: heart     9: brain    10: baby     11: foot
 12: muscle   13: hand     14: leg      15: dog      16: cat      17: horse
 18: cow      19: pig      20: goat     21: rabbit   22: mouse    23: tiger
 24: wolf     25: bear     26: deer     27: elephant  28: bat     29: camel
 30: zebra    31: giraffe  32: fox      33: lion     34: monkey   35: panda
 36: llama    37: squirrel 38: chicken  39: bird     40: duck     41: penguin
 42: peacock  43: owl      44: eagle    45: snake    46: frog     47: turtle
 48: crocodile 49: lizard  50: fish     51: octopus  52: crab     53: whale
 54: dolphin  55: shark    56: snail    57: ant      58: bee      59: butterfly
 60: worm     61: spider   62: scorpion 63: sun      64: moon     65: star
 66: earth    67: fire     68: water    69: snow     70: cloud    71: rain
 72: rainbow  73: wind     74: thunder  75: volcano  76: tornado  77: comet
 78: wave     79: desert   80: island   81: mountain 82: rock     83: diamond
 84: feather  85: tree     86: cactus   87: flower   88: leaf     89: mushroom
 90: wood     91: mango    92: apple    93: banana   94: grape    95: orange
 96: melon    97: peach    98: strawberry 99: pineapple 100: cherry 101: lemon
102: coconut 103: cucumber 104: seed   105: corn    106: carrot  107: onion
108: potato  109: pepper  110: tomato  111: garlic  112: peanut  113: bread
114: cheese  115: egg     116: meat    117: rice    118: cake    119: snack
120: sweet   121: honey   122: milk    123: coffee  124: tea     125: wine
126: beer    127: juice   128: salt    129: fork    130: spoon   131: bowl
132: knife   133: bottle  134: soup    135: pan     136: key     137: lock
138: bell    139: hammer  140: axe     141: gear    142: magnet  143: sword
144: bow     145: shield  146: bomb    147: compass 148: hook    149: thread
150: needle  151: scissors 152: pencil 153: house   154: castle  155: temple
156: bridge  157: factory 158: door    159: window  160: tent    161: beach
162: bank    163: tower   164: statue  165: wheel   166: boat    167: train
168: car     169: bike    170: plane   171: rocket  172: helicopter 173: ambulance
174: fuel    175: track   176: map     177: drum    178: guitar  179: violin
180: piano   181: paint   182: book    183: music   184: mask    185: camera
186: microphone 187: headset 188: movie 189: dress  190: coat    191: pants
192: glove   193: shirt   194: shoes   195: hat     196: flag    197: cross
198: circle  199: triangle 200: square 201: check   202: alert   203: sleep
204: magic   205: message 206: blood   207: repeat  208: dna     209: germ
210: pill    211: doctor  212: microscope 213: galaxy 214: flask  215: atom
216: satellite 217: battery 218: telescope 219: tv   220: radio   221: phone
222: bulb    223: keyboard 224: chair  225: bed     226: candle  227: mirror
228: ladder  229: basket  230: vase    231: shower  232: razor   233: soap
234: computer 235: trash  236: umbrella 237: money  238: prayer  239: toy
240: crown   241: ring    242: dice    243: piece   244: coin    245: calendar
246: boxing  247: swimming 248: game   249: soccer  250: ghost   251: alien
252: robot   253: angel   254: dragon  255: clock
```

---

## 3. Encoding

A seed is an ordered list of N icon indexes, where each index is a byte (0-255).

```
seed_bytes = bytes([index_0, index_1, ..., index_N-1])
```

- 16 words: 16 bytes = 128 bits of entropy
- 32 words: 32 bytes = 256 bits of entropy

Every word is pure entropy. There are no checksum words in v1.

---

## 4. Passphrase Normalization

Passphrases are **raw UTF-8 bytes with no normalization**.

```python
passphrase_bytes = passphrase_string.encode("utf-8")
```

- No NFKC, NFC, or any Unicode normalization is applied
- No whitespace trimming
- No case folding
- Empty string `""` produces zero bytes appended (same as no passphrase)
- The raw UTF-8 bytes are appended directly to the positional payload

**Warning:** This means the same visual characters encoded differently (e.g., precomposed vs decomposed Unicode) will produce different keys. Users should be warned to use consistent input methods.

---

## 5. Key Derivation Pipeline (5 layers)

### 5.1 Positional Binding

Each icon index is packed with its zero-based position as a little-endian (pos, index) byte pair:

```python
payload = b""
for pos, idx in enumerate(indexes):
    payload += struct.pack("<BB", pos, idx)
```

This binds each icon to its slot, preventing reordering attacks.

### 5.2 Passphrase Mixing

If a passphrase is provided, its raw UTF-8 bytes are appended:

```python
if passphrase:
    payload += passphrase.encode("utf-8")
```

### 5.3 HKDF-Extract (RFC 5869)

The payload is collapsed into a pseudorandom key (PRK) using HMAC-SHA512:

```python
prk = HMAC-SHA512(key=b"universal-seed-v1", message=payload)
```

- Key: domain separator `b"universal-seed-v1"` (17 bytes)
- Message: positional payload + optional passphrase bytes
- Output: 64 bytes (512 bits)

### 5.4 Chained KDF Stretching

The PRK is hardened through two KDFs in series:

**Stage 1: PBKDF2-SHA512**
```
salt    = b"universal-seed-v1-stretch-pbkdf2"
rounds  = 600,000
dklen   = 64 bytes
output  = PBKDF2-SHA512(prk, salt, rounds, dklen)
```

**Stage 2: Argon2id**
```
secret      = stage1_output (64 bytes)
salt        = b"universal-seed-v1-stretch-argon2id"
time_cost   = 3
memory_cost = 65536 (64 MiB)
parallelism = 4
hash_len    = 64 bytes
type        = Argon2id
```

### 5.5 HKDF-Expand (RFC 5869)

Final key derivation with domain separation:

```
info    = b"universal-seed-v1-master"
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

### 5.6 Output

The final output is **64 bytes (512 bits)** of key material:
- First 32 bytes: 256-bit encryption key
- Last 32 bytes: 256-bit authentication key
- Or used whole as a master key for further derivation

---

## 6. Fingerprint

The fingerprint provides quick visual verification of a seed.

**Without passphrase** (instant):
```python
payload = positional_payload(indexes)  # same as step 5.1
key = HMAC-SHA512(key=b"universal-seed-v1", message=payload)
fingerprint = key[0:2].hex().upper()   # 4-char hex, e.g. "A3F1"
```

**With passphrase** (runs full KDF):
```python
key = get_private_key(indexes, passphrase)  # full 5-layer pipeline
fingerprint = key[0:2].hex().upper()
```

| Property | Value |
|:---|:---|
| Length | 4 hex characters (2 bytes = 16 bits) |
| Format | Uppercase hex, e.g. `"A3F1"` |
| Derived from | Seed only (no passphrase) or seed + passphrase |

---

## 7. Word Lookup

Words are resolved via a flat hash table (`words.json`) containing 38,730 keys across 42 languages plus emoji. Resolution uses NFKC normalization + lowercase:

```python
key = unicodedata.normalize("NFKC", word.strip()).lower()
index = lookup_table.get(key)
```

Fuzzy fallbacks (diacritic stripping, article stripping, suffix stripping) are available for UI/recovery but are **not used in key derivation** in v2+.

In v1, `_to_indexes()` uses fuzzy resolution (no strict mode).

---

## 8. Security Notes

### Protected against
- Brute-force (256-bit entropy + chained KDF)
- GPU/ASIC attacks (Argon2id memory-hardness)
- Reordering attacks (positional binding)
- Weak RNG (8 independent entropy sources, validated before use)

### NOT protected against
- Physical seed theft (paper backup compromise)
- Keylogger capturing passphrase
- Compromised implementation (supply chain)
- Social engineering

### Known limitations
- No checksum — transcription errors are not detected at the protocol level
- Fuzzy resolution in `_to_indexes()` means suffix-stripped words could theoretically misresolve (addressed in v2 with strict mode)
- 4-char fingerprint provides only 16-bit visual verification

---

## 9. Version History

| Version | Changes |
|:---|:---|
| 1.0 | Initial release |
| 1.1 | Debug output gated behind `DEBUG` flag |
| 1.2 | Article stripping, inner-word search |
| 1.3 | Multi-language seed generation, `get_languages()` API |
