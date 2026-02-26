# Copyright (c) 2026 Signer — MIT License

"""Universal Quantum Seed — 256 visual icons, 42 languages, 272-bit entropy.

Drop-in package: copy or symlink this folder as `modules/seed/` in signer
and all existing imports work unchanged.
"""

try:
    from .seed import (
        generate_words,
        get_seed,
        get_profile,
        get_quantum_seed,
        generate_quantum_keypair,
        get_fingerprint,
        get_entropy_bits,
        verify_checksum,
        _compute_checksum,
        resolve,
        search,
        verify_randomness,
        mouse_entropy,
        kdf_info,
        get_languages,
        DARK_VISUALS,
    )
except ImportError:
    from seed import (
        generate_words,
        get_seed,
        get_profile,
        get_quantum_seed,
        generate_quantum_keypair,
        get_fingerprint,
        get_entropy_bits,
        verify_checksum,
        _compute_checksum,
        resolve,
        search,
        verify_randomness,
        mouse_entropy,
        kdf_info,
        get_languages,
        DARK_VISUALS,
    )

__all__ = [
    "generate_words",
    "get_seed",
    "get_profile",
    "get_quantum_seed",
    "generate_quantum_keypair",
    "get_fingerprint",
    "get_entropy_bits",
    "verify_checksum",
    "_compute_checksum",
    "resolve",
    "search",
    "verify_randomness",
    "mouse_entropy",
    "kdf_info",
    "get_languages",
    "DARK_VISUALS",
]
