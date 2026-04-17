# Copyright (c) 2026 Lock — MIT License

"""
Automated collision fixer for the Universal Quantum Seed.

For each collision (same word → different indexes), decides which index
the word most naturally belongs to and removes it from the other(s).

Resolution strategy (in priority order):
1. If the word is the English base word for one of the indexes → that index wins
2. If the word is the primary word (first in list) for one index but not another → primary wins
3. If the word is primary in multiple places within the SAME language → keep for the index
   where the base concept is closer to the word's meaning (lower index as tiebreaker)
4. Otherwise → keep for the index where it appears in more languages

After resolution, rewrites each modified language file.
"""

import importlib
import os
import re
import sys
import unicodedata

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
LANGUAGES_DIR = os.path.join(PROJECT_DIR, "languages")

sys.path.insert(0, PROJECT_DIR)

# Import base words for priority resolution
from languages.base import lock_universal_seed_base
BASE_WORDS = {entry[2].lower(): entry[0] for entry in lock_universal_seed_base}

# Zero-width chars
_INVISIBLE_CHARS = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u00ad\u034f\u061c"
    "\ufeff\u2060\u2061\u2062\u2063\u2064\u180e]"
)

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


def normalize(word):
    w = word.strip()
    w = _INVISIBLE_CHARS.sub("", w)
    w = unicodedata.normalize("NFKC", w)
    return w.lower()


def detect_script(word):
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


_SAFE_STRIP_SCRIPTS = {"latin", "greek", "arabic", "hebrew", "cyrillic"}


def strip_diacritics(word, script=None):
    if script is None:
        script = detect_script(word)
    if script not in _SAFE_STRIP_SCRIPTS:
        return word
    result = word
    if script == "latin":
        for old, new in {"ß": "ss", "ø": "o", "æ": "ae", "œ": "oe",
                         "ð": "d", "þ": "th", "ł": "l", "đ": "d"}.items():
            result = result.replace(old, new)
    if script == "cyrillic":
        result = result.replace("ё", "е").replace("Ё", "Е")
    nfkd = unicodedata.normalize("NFKD", result)
    stripped = "".join(c for c in nfkd if unicodedata.category(c) != "Mn")
    return unicodedata.normalize("NFC", stripped)


def get_variants(word):
    nw = normalize(word)
    variants = {nw}
    script = detect_script(nw)
    if script in _SAFE_STRIP_SCRIPTS:
        stripped = strip_diacritics(nw, script)
        if stripped != nw:
            variants.add(stripped)
    return variants


def load_all_languages():
    """Load all language modules and return their data."""
    lang_files = sorted([
        f[:-3] for f in os.listdir(LANGUAGES_DIR)
        if f.endswith(".py") and f != "__init__.py"
    ])

    languages = {}  # lang_file -> {label, seed_words}
    for lang_file in lang_files:
        try:
            mod = importlib.import_module(f"languages.{lang_file}")
        except Exception as e:
            print(f"ERROR importing {lang_file}: {e}")
            continue

        label = getattr(mod, "LABEL", lang_file)
        seed_words = getattr(mod, "SEED_WORDS", None)
        if seed_words is None:
            continue

        languages[lang_file] = {
            "label": label,
            "seed_words": {int(k): list(v) for k, v in seed_words.items()}
        }

    return languages


def find_collisions(languages):
    """Find all collisions across all languages.

    Returns dict: normalized_word -> {index -> [(lang_file, original_word, position_in_list)]}
    """
    # Track: normalized_word -> {index -> [(lang_file, original_word, pos)]}
    word_map = {}

    for lang_file, lang_data in languages.items():
        for idx, words in lang_data["seed_words"].items():
            for pos, word in enumerate(words):
                for variant in get_variants(word):
                    if not variant:
                        continue
                    if variant not in word_map:
                        word_map[variant] = {}
                    if idx not in word_map[variant]:
                        word_map[variant][idx] = []
                    word_map[variant][idx].append((lang_file, word, pos))

    # Filter to only collisions (same word → multiple indexes)
    collisions = {}
    for word, index_map in word_map.items():
        if len(index_map) > 1:
            collisions[word] = index_map

    return collisions


def resolve_collision(norm_word, index_map):
    """Decide which index should keep the word.

    Returns the winning index.
    """
    indexes = sorted(index_map.keys())

    # Strategy 1: If it's a base English word, that index wins
    if norm_word in BASE_WORDS:
        base_idx = BASE_WORDS[norm_word]
        if base_idx in index_map:
            return base_idx

    # Strategy 2: Check if the word is primary (position 0) in one index but not another
    primary_indexes = []
    secondary_indexes = []
    for idx in indexes:
        sources = index_map[idx]
        has_primary = any(pos == 0 for _, _, pos in sources)
        if has_primary:
            primary_indexes.append(idx)
        else:
            secondary_indexes.append(idx)

    if len(primary_indexes) == 1:
        return primary_indexes[0]

    # Strategy 3: Count how many languages use this word for each index
    lang_counts = {}
    for idx in indexes:
        sources = index_map[idx]
        unique_langs = set(lf for lf, _, _ in sources)
        lang_counts[idx] = len(unique_langs)

    max_count = max(lang_counts.values())
    best_by_count = [idx for idx, c in lang_counts.items() if c == max_count]

    if len(best_by_count) == 1:
        return best_by_count[0]

    # Strategy 4: If tied, prefer the index where it's a primary word across more languages
    primary_lang_counts = {}
    for idx in best_by_count:
        sources = index_map[idx]
        primary_count = sum(1 for _, _, pos in sources if pos == 0)
        primary_lang_counts[idx] = primary_count

    max_primary = max(primary_lang_counts.values())
    best_by_primary = [idx for idx, c in primary_lang_counts.items() if c == max_primary]

    if len(best_by_primary) == 1:
        return best_by_primary[0]

    # Final tiebreaker: lower index wins
    return min(best_by_primary)


def compute_removals(collisions):
    """For each collision, compute which (lang_file, index, word) entries to remove.

    Returns: list of (lang_file, index, original_word) to remove
    """
    removals = []

    for norm_word, index_map in collisions.items():
        winner_idx = resolve_collision(norm_word, index_map)

        # Remove the word from all other indexes
        for idx, sources in index_map.items():
            if idx == winner_idx:
                continue
            for lang_file, original_word, pos in sources:
                # Check if this original word's variant caused the collision
                # We need to verify the original word actually produces this norm_word
                variants = get_variants(original_word)
                if norm_word in variants:
                    removals.append((lang_file, idx, original_word))

    return removals


def apply_removals(languages, removals):
    """Remove words from language data structures.

    Returns set of modified lang_files.
    """
    # Group removals by (lang_file, idx) for efficiency
    removal_map = {}  # (lang_file, idx) -> set of words to remove
    for lang_file, idx, word in removals:
        key = (lang_file, idx)
        if key not in removal_map:
            removal_map[key] = set()
        removal_map[key].add(word)

    modified_files = set()
    total_removed = 0

    for (lang_file, idx), words_to_remove in removal_map.items():
        if lang_file not in languages:
            continue
        seed_words = languages[lang_file]["seed_words"]
        if idx not in seed_words:
            continue

        original_list = seed_words[idx]
        new_list = [w for w in original_list if w not in words_to_remove]

        if len(new_list) < len(original_list):
            removed_count = len(original_list) - len(new_list)
            total_removed += removed_count

            if len(new_list) == 0:
                # Don't leave an empty list - this shouldn't happen since
                # we should keep at least the primary word for the winning index
                print(f"  WARNING: Would empty index {idx} in {lang_file}, "
                      f"removing: {words_to_remove}")
                # Keep the first word at minimum
                new_list = [original_list[0]]
                total_removed -= 1

            seed_words[idx] = new_list
            modified_files.add(lang_file)

    print(f"\nTotal words removed: {total_removed}")
    print(f"Files modified: {len(modified_files)}")

    return modified_files


def write_language_file(lang_file, lang_data):
    """Rewrite a language file with updated SEED_WORDS."""
    filepath = os.path.join(LANGUAGES_DIR, f"{lang_file}.py")

    # Read original file to preserve LABEL and any comments at top
    with open(filepath, "r", encoding="utf-8") as f:
        original = f.read()

    # Extract LABEL
    label = lang_data["label"]

    # Build new SEED_WORDS dict
    lines = []
    lines.append(f'LABEL = "{label}"')
    lines.append("")
    lines.append("SEED_WORDS = {")

    for idx in range(256):
        words = lang_data["seed_words"].get(idx, [])
        if not words:
            words = ["???"]  # placeholder - shouldn't happen

        # Format the word list
        word_strs = [repr(w) for w in words]
        entry = f"    {idx}: [{', '.join(word_strs)}],"
        lines.append(entry)

    lines.append("}")
    lines.append("")

    content = "\n".join(lines)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    print("Loading all language files...")
    languages = load_all_languages()
    print(f"Loaded {len(languages)} languages\n")

    print("Finding collisions...")
    collisions = find_collisions(languages)
    print(f"Found {len(collisions)} colliding words\n")

    if not collisions:
        print("No collisions to fix!")
        return

    print("Resolving collisions...")
    removals = compute_removals(collisions)
    print(f"Computed {len(removals)} word removals\n")

    print("Applying removals...")
    modified_files = apply_removals(languages, removals)

    print(f"\nWriting {len(modified_files)} modified language files...")
    for lang_file in sorted(modified_files):
        write_language_file(lang_file, languages[lang_file])
        print(f"  Wrote {lang_file}.py")

    print("\nDone! Run compile.py to verify zero collisions.")


if __name__ == "__main__":
    main()
