# Copyright (c) 2026 Lock — MIT License

"""Audit word lengths across all languages. Find indexes where shortest word is too long."""
import sys, io, importlib, os

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
LANGUAGES_DIR = os.path.join(PROJECT_DIR, "languages")

sys.path.insert(0, PROJECT_DIR)
lang_files = sorted([
    f[:-3] for f in os.listdir(LANGUAGES_DIR)
    if f.endswith(".py") and f not in ("__init__.py", "base.py")
])

print("=" * 70)
print("WORD LENGTH AUDIT")
print("=" * 70)

# Per-language stats
for lang_file in lang_files:
    mod = importlib.import_module(f"languages.{lang_file}")
    label = getattr(mod, "LABEL", lang_file)
    sw = getattr(mod, "SEED_WORDS", {})

    # For each index, find shortest word length
    shortest_per_idx = {}
    for idx in range(256):
        words = sw.get(idx, [])
        if words:
            shortest_per_idx[idx] = min(len(w) for w in words)
        else:
            shortest_per_idx[idx] = 999

    long_indexes = [(idx, shortest_per_idx[idx]) for idx in range(256) if shortest_per_idx[idx] >= 8]
    very_long = [(idx, shortest_per_idx[idx]) for idx in range(256) if shortest_per_idx[idx] >= 12]

    avg_shortest = sum(shortest_per_idx.values()) / 256
    max_shortest = max(shortest_per_idx.values())

    word_counts = [len(sw.get(idx, [])) for idx in range(256)]
    single_word = sum(1 for c in word_counts if c <= 1)

    if long_indexes or single_word > 50:
        print(f"\n{label} ({lang_file}):")
        print(f"  Avg shortest word: {avg_shortest:.1f} chars")
        print(f"  Indexes with shortest >= 8 chars: {len(long_indexes)}")
        print(f"  Indexes with shortest >= 12 chars: {len(very_long)}")
        print(f"  Indexes with only 1 word: {single_word}")

        if very_long:
            print(f"  Worst offenders (shortest >= 12):")
            for idx, length in sorted(very_long, key=lambda x: -x[1])[:10]:
                words = sw.get(idx, [])
                display = [f"{w}({len(w)})" for w in words[:4]]
                print(f"    [{idx:3d}] min={length:2d}  {' | '.join(display)}")

# Summary: which languages have the most single-word indexes
print("\n" + "=" * 70)
print("VARIANT COUNT SUMMARY (indexes with only 1 word)")
print("=" * 70)

for lang_file in lang_files:
    mod = importlib.import_module(f"languages.{lang_file}")
    label = getattr(mod, "LABEL", lang_file)
    sw = getattr(mod, "SEED_WORDS", {})
    word_counts = [len(sw.get(idx, [])) for idx in range(256)]
    single = sum(1 for c in word_counts if c <= 1)
    two = sum(1 for c in word_counts if c == 2)
    three_plus = sum(1 for c in word_counts if c >= 3)
    avg = sum(word_counts) / 256
    print(f"  {label:25s} 1-word: {single:3d}  2-word: {two:3d}  3+: {three_plus:3d}  avg: {avg:.1f}")
