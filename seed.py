# Copyright (c) 2026 Signer — MIT License

__version__ = "1.3"

"""Seed generation for the Universal Seed System.

Generates cryptographically secure seeds using 256 visual icons (8 bits each).
- 16 words = 128 bits of entropy
- 32 words = 256 bits of entropy

Every word is pure entropy — no words are wasted on checksums.

Entropy is gathered from multiple independent sources and mixed through
SHA-512 (a cryptographic randomness extractor). This ensures that even if
one source is weak or compromised, the output remains uniformly random
as long as *any* source provides real entropy.

Key derivation is hardened with multiple layers:
    1. Positional binding — each icon is hashed with its position
    2. Passphrase mixing — optional second factor mixed into input,
       influences every downstream step
    3. HKDF-Extract — collapses seed + passphrase into a PRK (RFC 5869)
    4. Chained KDF — PBKDF2-SHA512 (600,000 rounds) then Argon2id
       (64 MiB, 3 iterations) — defense in depth, resists GPU/ASIC/FPGA
    5. HKDF-Expand — derives final key with domain separation

Sources (8 independent classes):
    1. secrets.token_bytes  — OS CSPRNG (CryptGenRandom / /dev/urandom)
    2. os.urandom           — separate OS CSPRNG call
    3. time.perf_counter_ns — hardware timer LSB jitter (nanosecond noise)
    4. os.getpid            — process-level uniqueness
    5. CPU jitter            — instruction timing variance (cache/TLB/branch)
    6. Thread scheduling     — OS scheduler nondeterminism (context switches)
    7. Hardware RNG          — BCryptGenRandom / platform HWRNG (RDRAND/RDSEED)

Usage:
    from seed import generate_words, get_private_key, get_fingerprint, resolve, search
    seed = generate_words(32)                       # [(idx, "word"), ...]
    key  = get_private_key(seed)                    # 64 bytes — pass seed directly
    key  = get_private_key(seed, "passphrase")      # with passphrase (second factor)
    fp   = get_fingerprint(seed)                    # "A3F1" visual checksum
    idx   = resolve("dog")                          # 15
    idxs, errs = resolve(["dog", "sun", "key"])     # ([15, 63, 136], [])
    matches = search("do")                          # [("dog", 15), ...]
"""

import bisect
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import threading
import time
import unicodedata

from argon2.low_level import hash_secret_raw, Type as _Argon2Type

# 256 base English words — one per icon position (0–255)
_BASE_WORDS = (
    "eye", "ear", "nose", "mouth", "tongue", "bone", "tooth", "skull",
    "heart", "brain", "baby", "foot", "muscle", "hand", "leg", "dog",
    "cat", "horse", "cow", "pig", "goat", "rabbit", "mouse", "tiger",
    "wolf", "bear", "deer", "elephant", "bat", "camel", "zebra", "giraffe",
    "fox", "lion", "monkey", "panda", "llama", "squirrel", "chicken", "bird",
    "duck", "penguin", "peacock", "owl", "eagle", "snake", "frog", "turtle",
    "crocodile", "lizard", "fish", "octopus", "crab", "whale", "dolphin", "shark",
    "snail", "ant", "bee", "butterfly", "worm", "spider", "scorpion", "sun",
    "moon", "star", "earth", "fire", "water", "snow", "cloud", "rain",
    "rainbow", "wind", "thunder", "volcano", "tornado", "comet", "wave", "desert",
    "island", "mountain", "rock", "diamond", "feather", "tree", "cactus", "flower",
    "leaf", "mushroom", "wood", "mango", "apple", "banana", "grape", "orange",
    "melon", "peach", "strawberry", "pineapple", "cherry", "lemon", "coconut", "cucumber",
    "seed", "corn", "carrot", "onion", "potato", "pepper", "tomato", "garlic",
    "peanut", "bread", "cheese", "egg", "meat", "rice", "cake", "snack",
    "sweet", "honey", "milk", "coffee", "tea", "wine", "beer", "juice",
    "salt", "fork", "spoon", "bowl", "knife", "bottle", "soup", "pan",
    "key", "lock", "bell", "hammer", "axe", "gear", "magnet", "sword",
    "bow", "shield", "bomb", "compass", "hook", "thread", "needle", "scissors",
    "pencil", "house", "castle", "temple", "bridge", "factory", "door", "window",
    "tent", "beach", "bank", "tower", "statue", "wheel", "boat", "train",
    "car", "bike", "plane", "rocket", "helicopter", "ambulance", "fuel", "track",
    "map", "drum", "guitar", "violin", "piano", "paint", "book", "music",
    "mask", "camera", "microphone", "headset", "movie", "dress", "coat", "pants",
    "glove", "shirt", "shoes", "hat", "flag", "cross", "circle", "triangle",
    "square", "check", "alert", "sleep", "magic", "message", "blood", "repeat",
    "dna", "germ", "pill", "doctor", "microscope", "galaxy", "flask", "atom",
    "satellite", "battery", "telescope", "tv", "radio", "phone", "bulb", "keyboard",
    "chair", "bed", "candle", "mirror", "ladder", "basket", "vase", "shower",
    "razor", "soap", "computer", "trash", "umbrella", "money", "prayer", "toy",
    "crown", "ring", "dice", "piece", "coin", "calendar", "boxing", "swimming",
    "game", "soccer", "ghost", "alien", "robot", "angel", "dragon", "clock",
)
_BASE = {i: w for i, w in enumerate(_BASE_WORDS)}

# ── Language support (loaded from words.json at module level below) ──
_LANGUAGES = {}  # populated after words.json is loaded


def _load_language(code):
    """Return {index: first_word} for a language code."""
    lang = _LANGUAGES.get(code)
    if lang is None:
        raise ValueError(f"Unknown language: {code!r}")
    return {int(k): v for k, v in lang["words"].items()}


def get_languages():
    """Return available seed languages as a list of (code, label) tuples.

    Example::

        get_languages()
        # [("english", "English"), ("arabic", "العربية"), ("french", "Français"), ...]
    """
    results = [("english", "English")]
    for code in sorted(_LANGUAGES):
        if code == "english":
            continue
        results.append((code, _LANGUAGES[code]["label"]))
    return results


# Domain separator — ensures keys from this system can never collide
# with keys derived by other systems using the same hash functions.
_DOMAIN = b"universal-seed-v1"

# Argon2id parameters (OWASP recommended for high-value targets)
_ARGON2_TIME = 3         # iterations
_ARGON2_MEMORY = 65536   # 64 MiB
_ARGON2_PARALLEL = 4     # lanes
_ARGON2_HASHLEN = 64     # output bytes

# PBKDF2 parameters — first stage of chained KDF (OWASP 2023 minimum for SHA-512)
_PBKDF2_ITERATIONS = 600_000

# ── Word lookup data ──────────────────────────────────────────────
_SEED_DIR = os.path.dirname(os.path.abspath(__file__))
_LOOKUP_FILE = os.path.join(_SEED_DIR, "words.json")

with open(_LOOKUP_FILE, "r", encoding="utf-8") as _f:
    _WORDS_DATA = json.load(_f)

# Support both old flat format and new structured format
if "lookup" in _WORDS_DATA and "languages" in _WORDS_DATA:
    _LOOKUP = _WORDS_DATA["lookup"]
    _LANGUAGES = _WORDS_DATA["languages"]
else:
    _LOOKUP = _WORDS_DATA

_SORTED_KEYS = sorted(_LOOKUP.keys())
_INDEX_TO_BASE = _BASE  # index -> base English word

# Inner-word index for multi-word entries (e.g. "bàn tay" → searchable by "tay")
_INNER_WORDS = []  # sorted list of (inner_word, full_key)
for _k in _LOOKUP:
    _parts = _k.split()
    if len(_parts) > 1:
        for _p in _parts[1:]:
            _INNER_WORDS.append((_p, _k))
_INNER_WORDS.sort()
_INNER_WORD_KEYS = [_iw for _iw, _ in _INNER_WORDS]

DEBUG = False

# Zero-width and invisible characters to strip
_INVISIBLE_CHARS = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u00ad\u034f\u061c"
    "\ufeff\u2060\u2061\u2062\u2063\u2064\u180e]"
)

# Definite-article suffixes for Latin-script languages (longest first)
# Icelandic: -inn (masc), -in (fem), -ið (neut)
# Romanian:  -ul (masc), -le (masc after vowels)
# Norwegian/Danish: -en (common), -et (neuter), -a (fem, Norwegian)
_ARTICLE_SUFFIXES = ("inn", "ið", "ul", "in", "le", "en", "et", "a")

# Scripts where stripping combining marks is safe
_SAFE_STRIP_SCRIPTS = {"latin", "greek", "arabic", "hebrew", "cyrillic"}


def _normalize(word):
    """Normalize a word for lookup.

    Strips whitespace, removes invisible chars, NFKC normalizes
    (full-width -> regular, ligatures -> letters), lowercases.
    """
    w = word.strip()
    w = _INVISIBLE_CHARS.sub("", w)
    w = unicodedata.normalize("NFKC", w)
    return w.lower()


def _detect_script(word):
    """Detect the primary script of a word."""
    script_counts = {}
    for c in word:
        if not c.isalpha():
            continue
        name = unicodedata.name(c, "")
        if "LATIN" in name:
            script_counts["latin"] = script_counts.get("latin", 0) + 1
        elif "GREEK" in name:
            script_counts["greek"] = script_counts.get("greek", 0) + 1
        elif "CYRILLIC" in name:
            script_counts["cyrillic"] = script_counts.get("cyrillic", 0) + 1
        elif "ARABIC" in name:
            script_counts["arabic"] = script_counts.get("arabic", 0) + 1
        elif "HEBREW" in name:
            script_counts["hebrew"] = script_counts.get("hebrew", 0) + 1
    if not script_counts:
        return "other"
    return max(script_counts, key=script_counts.get)


def _strip_diacritics(word):
    """Remove optional diacritics based on script.

    Safe for: Latin (accents, ss, o, etc.), Greek (tonos),
    Arabic (tashkeel/harakat), Hebrew (niqqud), Cyrillic.
    NOT applied to Thai, Devanagari, Bengali, Tamil, Telugu, Gurmukhi.
    """
    script = _detect_script(word)
    if script not in _SAFE_STRIP_SCRIPTS:
        return word

    result = word

    if script == "latin":
        for old, new in {"\u00df": "ss", "\u00f8": "o", "\u00e6": "ae", "\u0153": "oe",
                         "\u00f0": "d", "\u00fe": "th", "\u0142": "l", "\u0111": "d"}.items():
            result = result.replace(old, new)

    if script == "cyrillic":
        result = result.replace("\u0451", "\u0435").replace("\u0401", "\u0415")

    nfkd = unicodedata.normalize("NFKD", result)
    stripped = "".join(c for c in nfkd if unicodedata.category(c) != "Mn")
    return unicodedata.normalize("NFC", stripped)


def _normalize_emoji(text):
    """Normalize an emoji by stripping variation selectors."""
    e = text.strip()
    e = e.replace("\ufe0e", "").replace("\ufe0f", "")
    e = _INVISIBLE_CHARS.sub("", e)
    return e


def _resolve_one(word):
    """Resolve a single word/emoji to its visual index (0-255), or None."""
    t0 = time.perf_counter()
    key = _normalize(word)

    # Numeric index (0-255)
    if key.isdigit():
        n = int(key)
        if 0 <= n <= 255:
            if DEBUG: print(f"  [resolve] numeric index {n}  ({(time.perf_counter()-t0)*1000:.2f}ms)")
            return n

    result = _LOOKUP.get(key)
    if result is not None:
        if DEBUG: print(f"  [resolve] exact match '{key}' ->{result}  ({(time.perf_counter()-t0)*1000:.2f}ms)")
        return result

    # Try emoji-normalized (strip variation selectors)
    e_key = _normalize_emoji(word)
    if e_key and e_key != key:
        result = _LOOKUP.get(e_key)
        if result is not None:
            if DEBUG: print(f"  [resolve] emoji match '{e_key}' ->{result}  ({(time.perf_counter()-t0)*1000:.2f}ms)")
            return result

    # Fallback: try diacritic-stripped version
    stripped = _strip_diacritics(key)
    if stripped != key:
        result = _LOOKUP.get(stripped)
        if result is not None:
            if DEBUG: print(f"  [resolve] diacritic-stripped '{stripped}' ->{result}  ({(time.perf_counter()-t0)*1000:.2f}ms)")
            return result

    # Fallback: strip Arabic definite article "ال" (al-) prefix
    candidate = stripped if stripped != key else key
    if candidate.startswith("\u0627\u0644"):
        bare = candidate[2:]
        result = _LOOKUP.get(bare)
        if result is not None:
            if DEBUG: print(f"  [resolve] Arabic al- stripped '{bare}' ->{result}  ({(time.perf_counter()-t0)*1000:.2f}ms)")
            return result

    # Fallback: strip Hebrew definite article "ה" (ha-) prefix
    if candidate.startswith("\u05d4"):
        bare = candidate[1:]
        result = _LOOKUP.get(bare)
        if result is not None:
            if DEBUG: print(f"  [resolve] Hebrew ha- stripped '{bare}' ->{result}  ({(time.perf_counter()-t0)*1000:.2f}ms)")
            return result

    # Fallback: strip French/Italian "l'" article contraction
    for apo in ("'", "\u2019", "\u02bc"):
        prefix = "l" + apo
        if candidate.startswith(prefix):
            bare = candidate[len(prefix):]
            result = _LOOKUP.get(bare)
            if result is not None:
                if DEBUG: print(f"  [resolve] l' stripped '{bare}' ->{result}  ({(time.perf_counter()-t0)*1000:.2f}ms)")
                return result
            break

    # Fallback: strip definite-article suffixes (Scandinavian, Romanian, Icelandic)
    if _detect_script(candidate) == "latin" and len(candidate) > 3:
        for suffix in _ARTICLE_SUFFIXES:
            if candidate.endswith(suffix) and len(candidate) - len(suffix) >= 2:
                bare = candidate[:-len(suffix)]
                result = _LOOKUP.get(bare)
                if result is not None:
                    if DEBUG: print(f"  [resolve] suffix-stripped '{bare}' (removed -{suffix}) ->{result}  ({(time.perf_counter()-t0)*1000:.2f}ms)")
                    return result

    if DEBUG: print(f"  [resolve] no match for '{key}'  ({(time.perf_counter()-t0)*1000:.2f}ms)")
    return None


def resolve(words):
    """Resolve one or more words (any language) or emoji to visual indexes.

    Accepts a single word (string) or a list of words.

    Single word:
        resolve("dog")      → 15
        resolve("unknown")  → None

    Multiple words:
        resolve(["dog", "sun", "key"])  → ([15, 63, 136], [])
        resolve(["dog", "???", "key"])  → ([15, 136], [(1, "???")])

    Returns:
        str input:  int (0-255) or None
        list input: (indexes, errors) where errors is [(position, word), ...]
    """
    if isinstance(words, str):
        return _resolve_one(words)

    indexes = []
    errors = []
    for i, word in enumerate(words):
        idx = _resolve_one(word)
        if idx is not None:
            indexes.append(idx)
        else:
            errors.append((i, word))
    return indexes, errors


def _strip_article_prefix(key):
    """Strip definite article prefixes for search. Returns stripped key or None."""
    # French/Italian l' contraction
    for apo in ("'", "\u2019", "\u02bc"):
        prefix = "l" + apo
        if key.startswith(prefix):
            return key[len(prefix):]
    # Arabic ال
    if key.startswith("\u0627\u0644"):
        return key[2:]
    # Hebrew ה
    if key.startswith("\u05d4") and len(key) > 1:
        return key[1:]
    return None


def _search_sorted(sorted_keys, lookup, key, limit, seen_indexes):
    """Binary-search sorted_keys for entries starting with key."""
    lo = bisect.bisect_left(sorted_keys, key)
    results = []
    for i in range(lo, len(sorted_keys)):
        if len(results) >= limit:
            break
        k = sorted_keys[i]
        if not k.startswith(key):
            break
        idx = lookup[k]
        if idx in seen_indexes:
            continue
        seen_indexes.add(idx)
        results.append((k, idx))
    return results


def search(prefix, limit=10):
    """Suggest words matching a prefix, for search/autocomplete.

    Returns a list of (word, index) tuples sorted alphabetically,
    up to `limit` unique indexes. Words mapping to the same index are
    deduplicated (first alphabetical match wins).
    """
    t0 = time.perf_counter()
    key = _normalize(prefix)
    if not key:
        return []

    # Numeric prefix: match indexes whose string starts with the typed digits
    if key.isdigit():
        results = []
        for idx in range(256):
            if str(idx).startswith(key):
                base = _INDEX_TO_BASE.get(idx, str(idx))
                results.append((base, idx))
                if len(results) >= limit:
                    break
        elapsed = (time.perf_counter() - t0) * 1000
        if DEBUG: print(f"  [search] numeric prefix='{key}' ->{len(results)} results  ({elapsed:.2f}ms)")
        return results

    # Collect English base words that match the prefix first
    english_first = []
    seen_indexes = set()
    for idx, base in _INDEX_TO_BASE.items():
        if base.lower().startswith(key):
            english_first.append((base.lower(), idx))
            seen_indexes.add(idx)
    english_first.sort()
    if len(english_first) > limit:
        english_first = english_first[:limit]

    results = list(english_first)
    remaining = limit - len(results)

    # Primary: binary search on full keys
    results += _search_sorted(_SORTED_KEYS, _LOOKUP, key, remaining, seen_indexes)
    remaining = limit - len(results)

    # Article prefix stripping (l'oeil → oeil, الأيدي → أيدي, etc.)
    if remaining > 0:
        alt_key = _strip_article_prefix(key)
        if alt_key:
            results += _search_sorted(_SORTED_KEYS, _LOOKUP, alt_key, remaining, seen_indexes)
            remaining = limit - len(results)

    # Inner-word matching for multi-word entries (e.g. "tay" finds "bàn tay")
    if remaining > 0:
        lo = bisect.bisect_left(_INNER_WORD_KEYS, key)
        for i in range(lo, len(_INNER_WORD_KEYS)):
            if remaining <= 0:
                break
            iw = _INNER_WORD_KEYS[i]
            if not iw.startswith(key):
                break
            full_key = _INNER_WORDS[i][1]
            idx = _LOOKUP[full_key]
            if idx in seen_indexes:
                continue
            seen_indexes.add(idx)
            results.append((full_key, idx))
            remaining -= 1

    elapsed = (time.perf_counter() - t0) * 1000
    if DEBUG: print(f"  [search] prefix='{key}' ->{len(results)} unique results  ({elapsed:.2f}ms)")
    return results




class mouse_entropy:
    """Collects entropy from mouse movement samples.

    Each sample is (x, y, timestamp_ns). Entropy comes from:
    - Sub-pixel timing jitter in nanosecond timestamps
    - Unpredictable micro-movements in cursor position

    Conservative estimate: ~2 bits per unique sample.
    Samples are continuously hashed into a SHA-512 pool.

    Usage:
        pool = mouse_entropy()
        pool.add_sample(x, y)   # call on each mouse move
        pool.bits_collected      # check progress
        extra = pool.digest()    # extract entropy bytes
        seed = generate_words(32, extra_entropy=extra)
    """

    def __init__(self):
        self._hasher = hashlib.sha512()
        self._hasher.update(_DOMAIN + b"-mouse-entropy")
        self._samples = 0
        self._last_x = None
        self._last_y = None
        self._last_t = None

    def add_sample(self, x, y):
        """Add a mouse position sample with high-resolution timing.

        Returns True if the sample was new (position changed), False if skipped.
        """
        t = time.perf_counter_ns()

        # Skip duplicate positions (no movement = no entropy)
        if x == self._last_x and y == self._last_y:
            return False

        # Pack absolute position + timing
        self._hasher.update(struct.pack("<iiQ", x, y, t))

        # Hash deltas too — micro-movements carry extra entropy
        if self._last_x is not None:
            dx = x - self._last_x
            dy = y - self._last_y
            dt = t - self._last_t
            self._hasher.update(struct.pack("<iiQ", dx, dy, dt))

        self._last_x = x
        self._last_y = y
        self._last_t = t
        self._samples += 1
        return True

    @property
    def bits_collected(self):
        """Conservative estimate of entropy bits collected.

        ~2 bits per unique sample (position delta + timing jitter).
        """
        return self._samples * 2

    @property
    def sample_count(self):
        return self._samples

    def digest(self):
        """Extract collected entropy as bytes (64 bytes / 512 bits).

        Returns a copy — the pool can continue collecting after this.
        """
        return self._hasher.copy().digest()

    def reset(self):
        """Clear the pool and start fresh."""
        self.__init__()


def _cpu_jitter_entropy():
    """Collect entropy from CPU execution timing jitter.

    Runs tight loops of mixed operations and measures nanosecond-level
    variations caused by cache misses, branch prediction, TLB eviction,
    pipeline stalls, and speculative execution. Similar to the jitterentropy
    library used by the Linux kernel's /dev/random.

    Conservative estimate: ~1 bit per sample (64 samples = ~64 bits).
    """
    h = hashlib.sha512()
    h.update(_DOMAIN + b"-cpu-jitter")
    for _ in range(64):
        t1 = time.perf_counter_ns()
        # Mixed operations to trigger cache/TLB/branch-predictor jitter
        x = 0
        for j in range(100):
            x ^= (x << 3) ^ (j * 7) ^ (x >> 5)
            x &= 0xFFFFFFFFFFFFFFFF
        t2 = time.perf_counter_ns()
        h.update(struct.pack("<QQ", t2 - t1, t2))
    return h.digest()



def _thread_jitter_entropy():
    """Collect entropy from OS thread scheduling jitter.

    Spawns short-lived threads and measures round-trip timing. Entropy
    comes from nondeterministic OS scheduler decisions: context switches,
    CPU core migration, priority inheritance, and interrupt coalescing.

    Conservative estimate: ~2 bits per thread (32 threads = ~64 bits).
    """
    h = hashlib.sha512()
    h.update(_DOMAIN + b"-thread-jitter")
    results = []

    def worker(idx):
        t = time.perf_counter_ns()
        x = 0
        for i in range(50):
            x = (x + time.perf_counter_ns()) & 0xFFFFFFFF
        t2 = time.perf_counter_ns()
        results.append(struct.pack("<BQQ", idx, t, t2))

    for _batch in range(4):
        results.clear()
        threads = []
        t0 = time.perf_counter_ns()
        for i in range(8):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        t1 = time.perf_counter_ns()
        h.update(struct.pack("<QQ", t0, t1))
        for r in results:
            h.update(r)
    return h.digest()


def _hardware_rng_entropy():
    """Collect entropy from platform hardware RNG (RDRAND/RDSEED).

    Windows: BCryptGenRandom — separate API from CryptGenRandom
             (used by os.urandom), provides defense-in-depth.
             Feeds from Intel RDRAND/RDSEED and/or TPM when available.
    Linux:   getrandom() via os.urandom (already covered above).

    Also mixes in heap ASLR addresses and thread IDs for uniqueness.
    """
    h = hashlib.sha512()
    h.update(_DOMAIN + b"-hardware-rng")

    if os.name == 'nt':
        try:
            import ctypes
            bcrypt = ctypes.windll.bcrypt
            buf = ctypes.create_string_buffer(64)
            # BCRYPT_USE_SYSTEM_PREFERRED_RNG = 2
            status = bcrypt.BCryptGenRandom(None, buf, 64, 2)
            if status == 0:
                h.update(buf.raw)
        except Exception:
            pass
    else:
        # On Linux/macOS, read from /dev/random (hardware-backed)
        try:
            with open('/dev/random', 'rb') as f:
                h.update(f.read(32))
        except Exception:
            pass

    # Mix in ASLR heap addresses + thread ID for uniqueness
    h.update(struct.pack("<QQ",
        id(object()),
        threading.current_thread().ident or 0,
    ))
    return h.digest()


def _collect_entropy(n_bytes, extra_entropy=None):
    """Collect entropy from multiple sources and mix via SHA-512.

    SHA-512 acts as a randomness extractor — it uniformly distributes
    entropy across its output regardless of how the input is structured.
    The result has at least as much entropy as the strongest single source.

    Args:
        n_bytes: Number of random bytes to return.
        extra_entropy: Optional bytes to mix in (e.g. from mouse_entropy).

    Returns exactly n_bytes of cryptographic-quality random data.
    """
    pool = bytearray()

    # Source 1: OS CSPRNG via secrets (primary source)
    pool.extend(secrets.token_bytes(64))

    # Source 2: OS CSPRNG via os.urandom (separate syscall)
    pool.extend(os.urandom(64))

    # Source 3: High-resolution timing jitter
    # The LSBs of perf_counter_ns contain hardware clock noise that is
    # unpredictable even to an attacker who controls the OS CSPRNG
    for _ in range(32):
        pool.extend(struct.pack("<Q", time.perf_counter_ns()))

    # Source 4: Process-level uniqueness
    pool.extend(struct.pack("<I", os.getpid()))

    # Source 5: CPU execution timing jitter (cache/TLB/branch predictor)
    pool.extend(_cpu_jitter_entropy())

    # Source 6: Thread scheduling jitter (OS scheduler nondeterminism)
    pool.extend(_thread_jitter_entropy())

    # Source 7: Hardware RNG (RDRAND/RDSEED via BCrypt or /dev/random)
    pool.extend(_hardware_rng_entropy())

    # Source 8: User-supplied entropy (mouse movements, etc.)
    if extra_entropy:
        pool.extend(extra_entropy)

    # Mix everything through SHA-512
    h = hashlib.sha512(pool)

    # Fold in one final secrets call keyed on the digest
    # This ensures the output is at minimum as strong as secrets alone
    h.update(secrets.token_bytes(32))

    digest = h.digest()  # 64 bytes = 512 bits

    if n_bytes <= 64:
        return digest[:n_bytes]

    # For sizes > 64 bytes (unlikely), use HKDF-style expand
    out = bytearray()
    counter = 1
    prev = b""
    while len(out) < n_bytes:
        prev = hashlib.sha512(prev + digest + struct.pack("B", counter)).digest()
        out.extend(prev)
        counter += 1
    return bytes(out[:n_bytes])


_MAX_ENTROPY_RETRIES = 10
_VALIDATION_SAMPLE_SIZE = 1024  # bytes — large enough for statistical tests


def generate_words(word_count=32, extra_entropy=None, language=None):
    """Generate a cryptographically secure seed.

    All words are pure entropy — nothing is wasted on checksums.

    The entropy pipeline is validated before use: a 1024-byte sample is
    drawn from the same sources and tested with four statistical tests
    (monobit, chi-squared, runs, autocorrelation). If any test fails,
    the sample is discarded and the pipeline is retried — up to 10
    attempts. Only after validation passes is the actual seed generated.

    Args:
        word_count: 16 (128-bit) or 32 (256-bit)
        extra_entropy: Optional bytes to mix in (e.g. from mouse_entropy.digest()).
        language: Optional language code (e.g. "french", "arabic").
                  None or "english" returns English words.

    Returns:
        List of (index, word) tuples.

    Raises:
        ValueError: If word_count is not 16 or 32, or language is unknown.
        RuntimeError: If all 10 entropy attempts fail validation
                      (indicates a compromised or broken RNG).
    """
    if word_count not in (16, 32):
        raise ValueError("word_count must be 16 or 32")

    # Resolve word map for requested language
    if language and language != "english":
        word_map = _load_language(language)
    else:
        word_map = _BASE

    for _ in range(_MAX_ENTROPY_RETRIES):
        # Validate the entropy pipeline with a large sample (1024 bytes)
        # so the statistical tests have enough data to detect real bias.
        # 32 bytes is too few — chi-squared needs hundreds of observations.
        test_sample = _collect_entropy(_VALIDATION_SAMPLE_SIZE, extra_entropy)
        tests = _test_entropy(test_sample)
        if all(t["pass"] for t in tests.values()):
            # Pipeline is healthy — now generate the actual seed
            entropy = _collect_entropy(word_count, extra_entropy)
            indexes = list(entropy)
            return [(idx, word_map[idx]) for idx in indexes]

    raise RuntimeError(
        f"Entropy failed validation {_MAX_ENTROPY_RETRIES} times — "
        "RNG source may be compromised. Do NOT generate seeds on this system."
    )


def _hkdf_expand(prk, info, length):
    """HKDF-Expand (RFC 5869) using HMAC-SHA512."""
    n = (length + 63) // 64  # SHA-512 = 64-byte blocks
    okm = b""
    prev = b""
    for i in range(1, n + 1):
        prev = hmac.new(prk, prev + info + bytes([i]), hashlib.sha512).digest()
        okm += prev
    return okm[:length]


def _stretch(prk):
    """Chained key stretching: PBKDF2-SHA512 → Argon2id (defense in depth).

    Two independent KDFs run in series — the output of PBKDF2 feeds into
    Argon2id. An attacker must break both to recover the key:
    - PBKDF2:   600,000 rounds of SHA-512 ≈ 1 sec per guess
    - Argon2id: 64 MiB memory × 3 iterations × 4 lanes ≈ 1 sec per guess
    """
    salt = _DOMAIN + b"-stretch"

    # Stage 1: PBKDF2-SHA512
    stage1 = hashlib.pbkdf2_hmac(
        "sha512",
        prk,
        salt + b"-pbkdf2",
        iterations=_PBKDF2_ITERATIONS,
        dklen=64,
    )

    # Stage 2: Argon2id on top of PBKDF2 output
    return hash_secret_raw(
        secret=stage1,
        salt=salt + b"-argon2id",
        time_cost=_ARGON2_TIME,
        memory_cost=_ARGON2_MEMORY,
        parallelism=_ARGON2_PARALLEL,
        hash_len=_ARGON2_HASHLEN,
        type=_Argon2Type.ID,
    )


def _to_indexes(seed):
    """Convert a seed to a list of integer indexes.

    Accepts:
        - List of (int, str) tuples: output of generate_words() — indexes extracted
        - List of ints (0-255): returned as-is
        - List of strings: each word is resolved via resolve()

    Raises ValueError if any word fails to resolve.
    """
    if not seed:
        raise ValueError("seed must not be empty")
    first = seed[0]
    if isinstance(first, tuple):
        return [idx for idx, _ in seed]
    if isinstance(first, int):
        return seed
    # Resolve words → indexes
    indexes, errors = resolve(list(seed))
    if errors:
        bad = ", ".join(f"'{w}' (pos {i})" for i, w in errors)
        raise ValueError(f"could not resolve: {bad}")
    return indexes


def get_private_key(seed, passphrase=""):
    """Derive 512 bits of hardened key material from a seed + optional passphrase.

    Security layers:
        1. Positional binding — each icon is tagged with its slot index
        2. Passphrase mixing — optional second factor mixed into input
        3. HKDF-Extract — collapses payload into a pseudorandom key (RFC 5869)
        4. Chained KDF — PBKDF2-SHA512 (600k rounds) then Argon2id (64 MiB)
        5. HKDF-Expand — derives final 64-byte key with domain separation

    The output is 64 bytes (512 bits) which can be split into:
        - First 32 bytes: 256-bit encryption key
        - Last 32 bytes:  256-bit authentication key
    Or used whole as a master key for further derivation.

    The optional passphrase acts as a second factor. Same seed with
    different passphrases → completely unrelated keys. An empty
    passphrase is valid and produces a deterministic key.

    Args:
        seed: List of icon indexes (ints 0-255) or words (strings in any language).
        passphrase: Optional passphrase string (second factor).

    Returns:
        64 bytes of derived key material.
    """
    indexes = _to_indexes(seed)

    # Step 1: Position-tagged payload — each icon is bound to its slot
    payload = b""
    for pos, idx in enumerate(indexes):
        payload += struct.pack("<BB", pos, idx)

    # Step 2: Mix passphrase into payload (influences every downstream step)
    if passphrase:
        payload += passphrase.encode("utf-8")

    # Step 3: HKDF-Extract — collapse payload + passphrase into fixed PRK
    prk = hmac.new(_DOMAIN, payload, hashlib.sha512).digest()

    # Step 4: Chained KDF stretching (PBKDF2 → Argon2id)
    stretched = _stretch(prk)

    # Step 5: HKDF-Expand — derive output key with domain separation
    return _hkdf_expand(stretched, _DOMAIN + b"-master", 64)


def get_fingerprint(seed, passphrase=""):
    """Compute a short visual fingerprint for verification.

    Without a passphrase this is instant (HMAC only).
    With a passphrase it runs the full PBKDF2 + Argon2id pipeline
    so the fingerprint reflects both the seed AND the passphrase.

    Args:
        seed: List of icon indexes (ints 0-255) or words (strings in any language).
        passphrase: Optional passphrase (if set, fingerprint changes).

    Returns:
        4-char uppercase hex string, e.g. "A3F1".
    """
    indexes = _to_indexes(seed)
    if passphrase:
        key = get_private_key(indexes, passphrase)
    else:
        payload = b""
        for pos, idx in enumerate(indexes):
            payload += struct.pack("<BB", pos, idx)
        key = hmac.new(_DOMAIN, payload, hashlib.sha512).digest()
    return key[:2].hex().upper()

def get_entropy_bits(word_count, passphrase=""):
    """Calculate total entropy in bits from seed words + passphrase.

    Seed entropy: word_count × 8 bits (each word = 1 of 256 icons).

    Passphrase entropy is estimated from its character set:
        - Digits only (0-9):            ~3.32 bits/char
        - Lowercase only (a-z):         ~4.70 bits/char
        - Mixed case (a-z, A-Z):        ~5.70 bits/char
        - Mixed + digits:               ~5.95 bits/char
        - Full printable (symbols too):  ~6.55 bits/char
        - Unicode (non-ASCII):           ~7.00 bits/char (conservative)

    This measures the keyspace an attacker must search if they know
    the character classes used but not the actual characters.

    Args:
        word_count: Number of seed words (16 or 32).
        passphrase: Passphrase string.

    Returns:
        Estimated total entropy as a float (e.g. 256.0, 289.3).
    """
    seed_bits = word_count * 8

    if not passphrase:
        return float(seed_bits)

    import math

    has_lower = any(c.islower() for c in passphrase)
    has_upper = any(c.isupper() for c in passphrase)
    has_digit = any(c.isdigit() for c in passphrase)
    has_symbol = any(not c.isalnum() and c.isascii() for c in passphrase)
    has_unicode = any(ord(c) > 127 for c in passphrase)

    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_symbol:
        pool += 33  # printable ASCII symbols
    if has_unicode:
        pool += 100  # conservative estimate

    if pool == 0:
        return float(seed_bits)

    bits_per_char = math.log2(pool)
    pp_bits = bits_per_char * len(passphrase)

    return seed_bits + pp_bits


def kdf_info():
    """Return a string describing the chained KDF pipeline."""
    return (f"PBKDF2-SHA512 ({_PBKDF2_ITERATIONS:,} rounds) "
            f"+ Argon2id (mem={_ARGON2_MEMORY}KB, t={_ARGON2_TIME}, p={_ARGON2_PARALLEL})")


def _test_entropy(data):
    """Run statistical tests on raw bytes and return per-test results.

    This is the core testing engine used by both generate_words (to validate
    entropy before use) and verify_randomness (diagnostic UI).

    Returns a dict of {test_name: {pass, detail, ...}} for the four tests.
    """
    import math

    n_bits = len(data) * 8
    bits = []
    for byte in data:
        for bit_pos in range(7, -1, -1):
            bits.append((byte >> bit_pos) & 1)

    results = {}

    # ── Test 1: Monobit (frequency) test ─────────────────────
    ones = sum(bits)
    s = abs(2 * ones - n_bits) / math.sqrt(n_bits)
    monobit_pass = s < 2.576
    results["monobit"] = {
        "pass": monobit_pass,
        "ones_ratio": ones / n_bits,
        "z_score": round(s, 4),
        "threshold": 2.576,
        "detail": f"{ones}/{n_bits} ones ({ones/n_bits:.4f}), z={s:.4f}",
    }

    # ── Test 2: Chi-squared byte frequency ───────────────────
    observed = [0] * 256
    for byte in data:
        observed[byte] += 1
    expected = len(data) / 256.0
    chi2 = sum((o - expected) ** 2 / expected for o in observed)
    chi2_pass = chi2 < 310.5
    results["chi_squared"] = {
        "pass": chi2_pass,
        "chi2": round(chi2, 2),
        "threshold": 310.5,
        "expected_per_bin": round(expected, 2),
        "detail": f"chi2={chi2:.2f} (threshold 310.5), expected/bin={expected:.2f}",
    }

    # ── Test 3: Runs test ────────────────────────────────────
    pi = ones / n_bits
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n_bits):
        runs_pass = False
        runs_z = float("inf")
    else:
        runs = 1
        for i in range(1, n_bits):
            if bits[i] != bits[i - 1]:
                runs += 1
        expected_runs = 2.0 * n_bits * pi * (1 - pi) + 1
        std_runs = 2.0 * math.sqrt(2.0 * n_bits) * pi * (1 - pi)
        if std_runs == 0:
            runs_z = float("inf")
        else:
            runs_z = abs(runs - expected_runs) / std_runs
        runs_pass = runs_z < 2.576
    results["runs"] = {
        "pass": runs_pass,
        "z_score": round(runs_z, 4) if runs_z != float("inf") else "inf",
        "threshold": 2.576,
        "detail": f"z={runs_z:.4f}" if runs_z != float("inf") else "z=inf (degenerate)",
    }

    # ── Test 4: Autocorrelation ──────────────────────────────
    # Bonferroni correction: 16 offsets at family-wise alpha=0.01
    _AUTOCORR_Z = 3.42
    autocorr_pass = True
    worst_z = 0.0
    worst_offset = 0
    for d in range(1, 17):
        matches = sum(1 for i in range(n_bits - d) if bits[i] == bits[i + d])
        total = n_bits - d
        z = abs(2 * matches - total) / math.sqrt(total)
        if z > worst_z:
            worst_z = z
            worst_offset = d
        if z >= _AUTOCORR_Z:
            autocorr_pass = False
    results["autocorrelation"] = {
        "pass": autocorr_pass,
        "worst_z": round(worst_z, 4),
        "worst_offset": worst_offset,
        "threshold": _AUTOCORR_Z,
        "detail": f"worst z={worst_z:.4f} at offset {worst_offset}",
    }

    return results


def verify_randomness(sample_bytes=None, sample_size=2048, num_samples=5):
    """Test randomness quality of the entropy source to detect weak RNG.

    Runs four statistical tests based on NIST SP 800-22 methodology:
        1. Monobit — proportion of 1-bits should be ~50%
        2. Chi-squared byte frequency — all 256 values roughly uniform
        3. Runs — transitions between 0/1 bits (detects stuck patterns)
        4. Autocorrelation — checks for bit-level correlations at offsets 1-16

    Each test returns pass/fail and a score. A healthy RNG should pass all four.
    If any test fails, the entropy source may be weak or compromised.

    Aggregation uses majority voting: a test is only marked as failed if
    more than half the samples fail it. This eliminates false positives
    from statistical noise while still catching genuinely weak entropy.

    Args:
        sample_bytes: Optional raw bytes to test. If None, samples are
                      generated from _collect_entropy.
        sample_size:  Bytes per sample when auto-generating (default 2048).
        num_samples:  Number of independent samples to generate and test
                      (default 5). Ignored if sample_bytes is provided.

    Returns:
        dict with:
            "pass": bool — True if all tests passed across all samples
            "tests": list of per-test results
            "summary": human-readable summary string

    Usage:
        result = verify_randomness()
        print(result["summary"])
        if not result["pass"]:
            raise RuntimeError("Weak randomness detected!")
    """
    samples = []
    if sample_bytes is not None:
        samples = [sample_bytes]
    else:
        for _ in range(num_samples):
            samples.append(_collect_entropy(sample_size))

    all_results = []
    for si, data in enumerate(samples):
        sample_tests = _test_entropy(data)
        all_results.append({"sample": si, "tests": sample_tests})

    # ── Aggregate with majority voting ───────────────────────────
    # A test fails only if more than half the samples fail it.
    # With 5 samples at ~4% per-sample false-positive rate,
    # P(3+ fail by chance) ≈ 0.003% — virtually eliminates noise.
    test_names = ["monobit", "chi_squared", "runs", "autocorrelation"]
    overall_pass = True
    test_summary = []
    for name in test_names:
        failed_count = sum(1 for r in all_results if not r["tests"][name]["pass"])
        majority_failed = failed_count > len(all_results) / 2
        if majority_failed:
            overall_pass = False
        status = "PASS" if not majority_failed else f"FAIL ({failed_count}/{len(all_results)} samples)"
        test_summary.append({"test": name, "pass": not majority_failed, "status": status})

    lines = []
    lines.append(f"Randomness verification: {'PASS' if overall_pass else 'FAIL'}")
    lines.append(f"Samples: {len(samples)}, Size: {len(samples[0])} bytes each")
    lines.append("")
    for ts in test_summary:
        mark = "+" if ts["pass"] else "!"
        lines.append(f"  [{mark}] {ts['test']:<20s} {ts['status']}")
    if not overall_pass:
        lines.append("")
        lines.append("WARNING: Weak randomness detected. Do NOT use for seed generation.")
    summary = "\n".join(lines)

    return {
        "pass": overall_pass,
        "tests": test_summary,
        "samples": all_results,
        "summary": summary,
    }
