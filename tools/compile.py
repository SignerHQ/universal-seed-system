# Copyright (c) 2026 Signer — MIT License

"""
Compile all language files into a single flat lookup dictionary.

Reads every languages/*.py file, merges all accepted words into one dict,
detects collisions (same word → different indexes), and saves words.json.

Handles:
  - NFKC normalization (full-width → regular, ligatures → letters, etc.)
  - Zero-width character removal (ZWJ, ZWNJ, soft hyphens, BOM, etc.)
  - Accent/diacritic stripping for safe scripts:
      Latin:    "corazón" → "corazon", ß → ss, ø → o, æ → ae, etc.
      Greek:    "σκύλος" → "σκυλος" (tonos removed)
      Arabic:   tashkeel/harakat removed (vowel marks)
      Hebrew:   niqqud removed (vowel points)
      Cyrillic: ё → е (Russian common substitution)
  - NOT stripped: Thai, Devanagari, Bengali, Tamil, Telugu, Gurmukhi
    (combining marks change meaning in these scripts)
  - Case insensitive: all words stored lowercase

Usage: python tools/compile.py
"""

import importlib
import json
import os
import re
import sys
import unicodedata

# Zero-width and invisible characters to strip from all input
_INVISIBLE_CHARS = re.compile(
    "["
    "\u200b"   # zero-width space
    "\u200c"   # zero-width non-joiner
    "\u200d"   # zero-width joiner
    "\u200e"   # left-to-right mark
    "\u200f"   # right-to-left mark
    "\u00ad"   # soft hyphen
    "\u034f"   # combining grapheme joiner
    "\u061c"   # arabic letter mark
    "\ufeff"   # BOM / zero-width no-break space
    "\u2060"   # word joiner
    "\u2061"   # function application
    "\u2062"   # invisible times
    "\u2063"   # invisible separator
    "\u2064"   # invisible plus
    "\u180e"   # mongolian vowel separator
    "]"
)

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
LANGUAGES_DIR = os.path.join(PROJECT_DIR, "languages")
OUTPUT_FILE = os.path.join(PROJECT_DIR, "words.json")

sys.path.insert(0, PROJECT_DIR)


def normalize(word):
    """Normalize a word for lookup.

    1. Strip whitespace
    2. Remove zero-width / invisible characters
    3. NFKC normalize (full-width → regular, ligatures → letters, etc.)
    4. Lowercase
    """
    w = word.strip()
    w = _INVISIBLE_CHARS.sub("", w)
    w = unicodedata.normalize("NFKC", w)
    return w.lower()


def detect_script(word):
    """Detect the primary script of a word.

    Returns one of: 'latin', 'greek', 'cyrillic', 'arabic', 'hebrew',
    'thai', 'devanagari', 'bengali', 'tamil', 'telugu', 'gurmukhi',
    'cjk', 'hangul', 'kana', or 'other'.
    """
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
        elif "THAI" in name:
            script_counts["thai"] = script_counts.get("thai", 0) + 1
        elif "DEVANAGARI" in name:
            script_counts["devanagari"] = script_counts.get("devanagari", 0) + 1
        elif "BENGALI" in name:
            script_counts["bengali"] = script_counts.get("bengali", 0) + 1
        elif "TAMIL" in name:
            script_counts["tamil"] = script_counts.get("tamil", 0) + 1
        elif "TELUGU" in name:
            script_counts["telugu"] = script_counts.get("telugu", 0) + 1
        elif "GURMUKHI" in name:
            script_counts["gurmukhi"] = script_counts.get("gurmukhi", 0) + 1
        elif "CJK" in name or "KANGXI" in name:
            script_counts["cjk"] = script_counts.get("cjk", 0) + 1
        elif "HANGUL" in name:
            script_counts["hangul"] = script_counts.get("hangul", 0) + 1
        elif "HIRAGANA" in name or "KATAKANA" in name:
            script_counts["kana"] = script_counts.get("kana", 0) + 1

    if not script_counts:
        return "other"
    return max(script_counts, key=script_counts.get)


# Scripts where NFD + strip combining marks is SAFE
# (diacritics are optional / decorative, not meaning-changing)
_SAFE_STRIP_SCRIPTS = {"latin", "greek", "arabic", "hebrew", "cyrillic"}

# Scripts where stripping combining marks would DESTROY meaning
# (tone marks, nukta, anusvara, etc. change the word)
# Thai, Devanagari, Bengali, Tamil, Telugu, Gurmukhi, CJK, Hangul, Kana


def strip_diacritics(word, script=None):
    """Remove optional diacritics/accents based on the word's script.

    Safe for: Latin, Greek, Arabic (tashkeel), Hebrew (niqqud), Cyrillic (ё→е)
    NOT applied to: Thai, Devanagari, Bengali, Tamil, Telugu, Gurmukhi
    (where combining marks change meaning)
    """
    if script is None:
        script = detect_script(word)

    if script not in _SAFE_STRIP_SCRIPTS:
        return word

    result = word

    # Latin-specific character mappings
    if script == "latin":
        latin_replacements = {
            "ß": "ss", "ø": "o", "æ": "ae", "œ": "oe",
            "ð": "d", "þ": "th", "ł": "l", "đ": "d",
        }
        for old, new in latin_replacements.items():
            result = result.replace(old, new)

    # Cyrillic-specific: ё → е (extremely common in Russian)
    if script == "cyrillic":
        result = result.replace("ё", "е").replace("Ё", "Е")

    # NFD decompose then strip combining marks (accents/tashkeel/niqqud/tonos)
    nfkd = unicodedata.normalize("NFKD", result)
    stripped = "".join(c for c in nfkd if unicodedata.category(c) != "Mn")
    return unicodedata.normalize("NFC", stripped)


def get_variants(word):
    """Get all lookup variants for a word.

    Returns a set of normalized strings that should all map to the same index.
    For scripts with optional diacritics, includes the stripped version.
    """
    nw = normalize(word)
    variants = {nw}

    script = detect_script(nw)
    if script in _SAFE_STRIP_SCRIPTS:
        stripped = strip_diacritics(nw, script)
        if stripped != nw:
            variants.add(stripped)

    return variants


def normalize_emoji(emoji):
    """Normalize an emoji for lookup.

    Strips variation selectors (VS15/VS16) and zero-width joiners so that
    different renderings of the same emoji resolve identically.
    """
    # Remove variation selectors (U+FE0E text, U+FE0F emoji)
    e = emoji.strip()
    e = e.replace("\ufe0e", "").replace("\ufe0f", "")
    e = _INVISIBLE_CHARS.sub("", e)
    return e


def compile_lookup():
    # Discover all language modules
    lang_files = sorted([
        f[:-3] for f in os.listdir(LANGUAGES_DIR)
        if f.endswith(".py") and f != "__init__.py"
    ])

    if not lang_files:
        print("ERROR: No language files found in languages/")
        return False

    print(f"Found {len(lang_files)} language files\n")

    # Track all word → [(index, language)] mappings for collision detection
    word_sources = {}  # normalized_word -> [(index, lang_name)]
    lang_stats = {}    # lang_name -> word count
    accent_variants = 0  # count of auto-generated accent-stripped entries

    for lang_file in lang_files:
        try:
            mod = importlib.import_module(f"languages.{lang_file}")
        except Exception as e:
            print(f"  ERROR importing languages/{lang_file}.py: {e}")
            continue

        label = getattr(mod, "LABEL", lang_file)
        seed_words = getattr(mod, "SEED_WORDS", None)

        if seed_words is None:
            print(f"  WARNING: {lang_file}.py has no SEED_WORDS dict, skipping")
            continue

        word_count = 0
        for idx, words in seed_words.items():
            idx = int(idx)
            for word in words:
                for variant in get_variants(word):
                    if not variant:
                        continue
                    if variant not in word_sources:
                        word_sources[variant] = []
                    word_sources[variant].append((idx, label))
                    word_count += 1

                # Count accent variants
                vs = get_variants(word)
                if len(vs) > 1:
                    accent_variants += len(vs) - 1

        lang_stats[label] = word_count
        print(f"  {label} ({lang_file}): {word_count} words")

    # Add emoji from base.py
    from languages.base import signer_universal_seed_base
    emoji_count = 0
    for idx, emoji, _word in signer_universal_seed_base:
        e_norm = normalize_emoji(emoji)
        if not e_norm:
            continue
        if e_norm not in word_sources:
            word_sources[e_norm] = []
        word_sources[e_norm].append((idx, "emoji"))
        emoji_count += 1
        # Also store with variation selectors intact
        e_raw = emoji.strip()
        if e_raw != e_norm:
            if e_raw not in word_sources:
                word_sources[e_raw] = []
            word_sources[e_raw].append((idx, "emoji"))
            emoji_count += 1
    print(f"\n  Emoji entries added: {emoji_count}")

    # Detect collisions: same word → different indexes
    collisions = []
    for word, sources in word_sources.items():
        indexes = set(idx for idx, _ in sources)
        if len(indexes) > 1:
            collisions.append((word, sources))

    print(f"\n{'='*60}")
    print(f"Total languages: {len(lang_stats)}")
    print(f"Total unique lookup keys: {len(word_sources)}")
    print(f"Auto-generated accent-stripped variants: {accent_variants}")

    if collisions:
        print(f"\nCOLLISIONS FOUND: {len(collisions)}")
        print("The following words map to DIFFERENT indexes across languages:")
        print("-" * 60)
        for word, sources in sorted(collisions):
            by_index = {}
            for idx, lang in sources:
                if idx not in by_index:
                    by_index[idx] = []
                by_index[idx].append(lang)
            parts = []
            for idx, langs in sorted(by_index.items()):
                lang_list = sorted(set(langs))
                parts.append(f"  index {idx}: {', '.join(lang_list)}")
            print(f'\n  "{word}":')
            for part in parts:
                print(f"    {part}")
        print(f"\nFix all {len(collisions)} collisions before deploying.")
        print("Remove the ambiguous word from one language's word list.")
        print(f"{'='*60}")
        print("\nWARNING: Saving lookup WITH collisions for debugging.")
    else:
        print("Collisions: NONE (clean!)")
        print(f"{'='*60}")

    # Build flat lookup (for collisions, first index wins - but we warn above)
    lookup = {}
    for word, sources in word_sources.items():
        lookup[word] = sources[0][0]

    # Build languages section: {code: {label, words: {idx: first_word}}}
    languages = {}
    for lang_file in lang_files:
        if lang_file == "base" or lang_file.startswith("_"):
            continue
        try:
            mod = importlib.import_module(f"languages.{lang_file}")
        except Exception:
            continue
        seed_words = getattr(mod, "SEED_WORDS", None)
        if seed_words is None:
            continue
        label = getattr(mod, "LABEL", lang_file.replace("_", " ").title())
        words_map = {}
        for idx, word_list in seed_words.items():
            if word_list:
                words_map[str(int(idx))] = word_list[0]
        languages[lang_file] = {"label": label, "words": words_map}

    print(f"\nLanguages embedded: {len(languages)}")
    for code in sorted(languages):
        print(f"  {code}: {languages[code]['label']} ({len(languages[code]['words'])} words)")

    # Save words.json with lookup + languages
    output = {"lookup": lookup, "languages": languages}
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=None, separators=(",", ":"))

    size_kb = os.path.getsize(OUTPUT_FILE) / 1024
    print(f"\nSaved {OUTPUT_FILE}")
    print(f"  {len(lookup)} lookup entries + {len(languages)} languages, {size_kb:.1f} KB")

    # Generate SHA-256
    import hashlib
    sha_path = OUTPUT_FILE + ".sha256"
    with open(OUTPUT_FILE, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    with open(sha_path, "w", encoding="utf-8") as f:
        f.write(f"{digest}  words.json\n")
    print(f"  SHA-256: {digest}")
    print(f"  Saved {sha_path}")

    return len(collisions) == 0


if __name__ == "__main__":
    ok = compile_lookup()
    sys.exit(0 if ok else 1)
