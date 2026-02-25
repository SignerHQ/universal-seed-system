"""Tests for Ed25519, X25519, Hybrid-DSA-65, and Hybrid-KEM-768.

Includes RFC 8032 / RFC 7748 test vectors and round-trip verification.
"""

import os
import sys
import hashlib

# ── RFC 8032 Ed25519 Test Vectors (Section 7.1) ────────────────

def test_ed25519_vectors():
    from crypto.ed25519 import ed25519_keygen, ed25519_sign, ed25519_verify

    vectors = [
        # Vector 1: empty message (RFC 8032 Section 7.1)
        {
            "seed": bytes.fromhex(
                "9d61b19deffd5a60ba844af492ec2cc4"
                "4449c5697b326919703bac031cae7f60"
            ),
            "pk": bytes.fromhex(
                "d75a980182b10ab7d54bfed3c964073a"
                "0ee172f3daa62325af021a68f707511a"
            ),
            "msg": b"",
            "sig": bytes.fromhex(
                "e5564300c360ac729086e2cc806e828a"
                "84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46b"
                "d25bf5f0595bbe24655141438e7a100b"
            ),
        },
        # Vector 2: 1-byte message
        {
            "seed": bytes.fromhex(
                "4ccd089b28ff96da9db6c346ec114e0f"
                "5b8a319f35aba624da8cf6ed4fb8a6fb"
            ),
            "pk": bytes.fromhex(
                "3d4017c3e843895a92b70aa74d1b7ebc"
                "9c982ccf2ec4968cc0cd55f12af4660c"
            ),
            "msg": bytes.fromhex("72"),
            "sig": bytes.fromhex(
                "92a009a9f0d4cab8720e820b5f642540"
                "a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c"
                "387b2eaeb4302aeeb00d291612bb0c00"
            ),
        },
        # Vector 3: 2-byte message
        {
            "seed": bytes.fromhex(
                "c5aa8df43f9f837bedb7442f31dcb7b1"
                "66d38535076f094b85ce3a2e0b4458f7"
            ),
            "pk": bytes.fromhex(
                "fc51cd8e6218a1a38da47ed00230f058"
                "0816ed13ba3303ac5deb911548908025"
            ),
            "msg": bytes.fromhex("af82"),
            "sig": bytes.fromhex(
                "6291d657deec24024827e69c3abe01a3"
                "0ce548a284743a445e3680d7db5ac3ac"
                "18ff9b538d16f290ae67f760984dc659"
                "4a7c15e9716ed28dc027beceea1ec40a"
            ),
        },
    ]

    passed = 0
    for i, v in enumerate(vectors):
        sk, pk = ed25519_keygen(v["seed"])
        assert pk == v["pk"], f"Vector {i+1}: pk mismatch"
        sig = ed25519_sign(v["msg"], sk)
        assert sig == v["sig"], f"Vector {i+1}: sig mismatch"
        assert ed25519_verify(v["msg"], sig, pk), f"Vector {i+1}: verify failed"
        # Wrong message must fail
        assert not ed25519_verify(b"wrong", sig, pk), f"Vector {i+1}: wrong msg accepted"
        passed += 1

    print(f"  Ed25519 RFC 8032 vectors: {passed}/{len(vectors)} passed")
    return passed == len(vectors)


# ── RFC 7748 X25519 Test Vectors (Section 6.1) ─────────────────

def test_x25519_vectors():
    from crypto.x25519 import x25519_keygen, x25519

    # Alice's keypair
    alice_sk = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645"
        "df4c2f87ebc0992ab177fba51db92c2a"
    )
    alice_pk_expected = bytes.fromhex(
        "8520f0098930a754748b7ddcb43ef75a"
        "0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )

    # Bob's keypair
    bob_sk = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee6"
        "6f3bb1292618b6fd1c2f8b27ff88e0eb"
    )
    bob_pk_expected = bytes.fromhex(
        "de9edb7d7b7dc1b4d35b61c2ece43537"
        "3f8343c85b78674dadfc7e146f882b4f"
    )

    # Shared secret
    shared_expected = bytes.fromhex(
        "4a5d9d5ba4ce2de1728e3bf480350f25"
        "e07e21c947d19e3376f09b3c1e161742"
    )

    passed = 0

    # Test keygen (note: x25519_keygen clamps, so we need to check via DH)
    # The RFC vectors give raw scalars; x25519_keygen clamps them.
    # We test DH directly using the raw x25519 function.
    from crypto.x25519 import _clamp, _x25519_raw, _encode_u

    # Verify Alice's public key from clamped scalar * basepoint
    alice_clamped = _clamp(alice_sk)
    basepoint = (9).to_bytes(32, 'little')
    alice_pk_computed = _encode_u(_x25519_raw(alice_clamped, basepoint))
    assert alice_pk_computed == alice_pk_expected, "Alice pk mismatch"
    passed += 1

    # Verify Bob's public key
    bob_clamped = _clamp(bob_sk)
    bob_pk_computed = _encode_u(_x25519_raw(bob_clamped, basepoint))
    assert bob_pk_computed == bob_pk_expected, "Bob pk mismatch"
    passed += 1

    # Verify shared secret: Alice's sk * Bob's pk
    shared_alice = x25519(alice_clamped, bob_pk_expected)
    assert shared_alice == shared_expected, "Shared secret (Alice) mismatch"
    passed += 1

    # Verify shared secret: Bob's sk * Alice's pk
    shared_bob = x25519(bob_clamped, alice_pk_expected)
    assert shared_bob == shared_expected, "Shared secret (Bob) mismatch"
    passed += 1

    # Round-trip with keygen
    sk_a, pk_a = x25519_keygen(os.urandom(32))
    sk_b, pk_b = x25519_keygen(os.urandom(32))
    ss_a = x25519(sk_a, pk_b)
    ss_b = x25519(sk_b, pk_a)
    assert ss_a == ss_b, "Round-trip DH mismatch"
    assert len(ss_a) == 32
    passed += 1

    print(f"  X25519 RFC 7748 vectors: {passed}/5 passed")
    return passed == 5


# ── RFC 7748 Section 5.2: Iterated X25519 (1000 iterations) ────

def test_x25519_iterated():
    from crypto.x25519 import _x25519_raw, _encode_u

    k = (9).to_bytes(32, 'little')
    u = (9).to_bytes(32, 'little')

    for _ in range(1000):
        result = _x25519_raw(k, u)
        u = k
        k = _encode_u(result)

    expected = bytes.fromhex(
        "684cf59ba83309552800ef566f2f4d3c"
        "1c3887c49360e3875f2eb94d99532c51"
    )
    ok = k == expected
    print(f"  X25519 1000-iteration: {'passed' if ok else 'FAILED'}")
    return ok


# ── Ed25519 Round-trip Tests ───────────────────────────────────

def test_ed25519_roundtrip():
    from crypto.ed25519 import ed25519_keygen, ed25519_sign, ed25519_verify

    passed = 0

    # Random keypair sign/verify
    for i in range(5):
        seed = os.urandom(32)
        sk, pk = ed25519_keygen(seed)
        assert len(sk) == 64
        assert len(pk) == 32
        msg = os.urandom(100 + i * 50)
        sig = ed25519_sign(msg, sk)
        assert len(sig) == 64
        assert ed25519_verify(msg, sig, pk), f"Round-trip {i} failed"
        # Tamper message
        assert not ed25519_verify(msg + b"\x00", sig, pk)
        # Tamper signature
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0x01
        assert not ed25519_verify(msg, bytes(bad_sig), pk)
        passed += 1

    # Wrong key
    sk1, pk1 = ed25519_keygen(os.urandom(32))
    sk2, pk2 = ed25519_keygen(os.urandom(32))
    sig = ed25519_sign(b"test", sk1)
    assert not ed25519_verify(b"test", sig, pk2)
    passed += 1

    print(f"  Ed25519 round-trip: {passed}/6 passed")
    return passed == 6


# ── Hybrid DSA Tests ───────────────────────────────────────────

def test_hybrid_dsa():
    from crypto.hybrid_dsa import (
        hybrid_dsa_keygen, hybrid_dsa_sign, hybrid_dsa_verify,
        HYBRID_DSA_SK_SIZE, HYBRID_DSA_PK_SIZE, HYBRID_DSA_SIG_SIZE,
    )

    passed = 0

    # Keygen from deterministic seed
    seed = hashlib.sha512(b"test-hybrid-dsa").digest()
    sk, pk = hybrid_dsa_keygen(seed)
    assert len(sk) == HYBRID_DSA_SK_SIZE, f"sk size: {len(sk)} != {HYBRID_DSA_SK_SIZE}"
    assert len(pk) == HYBRID_DSA_PK_SIZE, f"pk size: {len(pk)} != {HYBRID_DSA_PK_SIZE}"
    passed += 1

    # Sign and verify
    msg = b"Hello, hybrid world!"
    sig = hybrid_dsa_sign(msg, sk)
    assert len(sig) == HYBRID_DSA_SIG_SIZE, f"sig size: {len(sig)} != {HYBRID_DSA_SIG_SIZE}"
    assert hybrid_dsa_verify(msg, sig, pk), "Verify failed"
    passed += 1

    # With context
    sig_ctx = hybrid_dsa_sign(msg, sk, ctx=b"backup-update")
    assert hybrid_dsa_verify(msg, sig_ctx, pk, ctx=b"backup-update")
    # Wrong context fails
    assert not hybrid_dsa_verify(msg, sig_ctx, pk, ctx=b"wrong-context")
    passed += 1

    # Tamper Ed25519 portion -> fails
    bad_sig = bytearray(sig)
    bad_sig[0] ^= 0x01  # Corrupt Ed25519 signature byte
    assert not hybrid_dsa_verify(msg, bytes(bad_sig), pk), "Ed25519 tamper not detected"
    passed += 1

    # Tamper ML-DSA portion -> fails
    bad_sig2 = bytearray(sig)
    bad_sig2[64] ^= 0x01  # Corrupt ML-DSA signature byte
    assert not hybrid_dsa_verify(msg, bytes(bad_sig2), pk), "ML-DSA tamper not detected"
    passed += 1

    # Wrong key -> fails
    seed2 = hashlib.sha512(b"different-seed").digest()
    sk2, pk2 = hybrid_dsa_keygen(seed2)
    assert not hybrid_dsa_verify(msg, sig, pk2), "Wrong key accepted"
    passed += 1

    # Wrong message -> fails
    assert not hybrid_dsa_verify(b"wrong message", sig, pk), "Wrong msg accepted"
    passed += 1

    # Bad sizes -> fails
    assert not hybrid_dsa_verify(msg, sig[:10], pk)
    assert not hybrid_dsa_verify(msg, sig, pk[:10])
    passed += 1

    # Deterministic: same seed -> same keypair
    sk_copy, pk_copy = hybrid_dsa_keygen(seed)
    assert sk == sk_copy and pk == pk_copy
    passed += 1

    print(f"  Hybrid DSA: {passed}/9 passed")
    return passed == 9


# ── Hybrid KEM Tests ───────────────────────────────────────────

def test_hybrid_kem():
    from crypto.hybrid_kem import (
        hybrid_kem_keygen, hybrid_kem_encaps, hybrid_kem_decaps,
        HYBRID_KEM_EK_SIZE, HYBRID_KEM_DK_SIZE, HYBRID_KEM_CT_SIZE,
    )

    passed = 0

    # Keygen
    seed = os.urandom(96)
    ek, dk = hybrid_kem_keygen(seed)
    assert len(ek) == HYBRID_KEM_EK_SIZE, f"ek size: {len(ek)} != {HYBRID_KEM_EK_SIZE}"
    assert len(dk) == HYBRID_KEM_DK_SIZE, f"dk size: {len(dk)} != {HYBRID_KEM_DK_SIZE}"
    passed += 1

    # Encaps/decaps round-trip
    ct, ss_enc = hybrid_kem_encaps(ek)
    assert len(ct) == HYBRID_KEM_CT_SIZE, f"ct size: {len(ct)} != {HYBRID_KEM_CT_SIZE}"
    assert len(ss_enc) == 32
    ss_dec = hybrid_kem_decaps(dk, ct)
    assert len(ss_dec) == 32
    assert ss_enc == ss_dec, "Shared secrets don't match"
    passed += 1

    # Deterministic with explicit randomness
    randomness = os.urandom(64)
    ct1, ss1 = hybrid_kem_encaps(ek, randomness=randomness)
    ct2, ss2 = hybrid_kem_encaps(ek, randomness=randomness)
    assert ct1 == ct2 and ss1 == ss2, "Deterministic encaps failed"
    passed += 1

    # Different randomness -> different ciphertext and shared secret
    ct3, ss3 = hybrid_kem_encaps(ek, randomness=os.urandom(64))
    assert ct3 != ct1 or ss3 != ss1, "Different randomness produced same result"
    passed += 1

    # Wrong dk -> different shared secret (ML-KEM implicit rejection)
    seed2 = os.urandom(96)
    ek2, dk2 = hybrid_kem_keygen(seed2)
    ss_wrong = hybrid_kem_decaps(dk2, ct)
    assert ss_wrong != ss_enc, "Wrong dk produced same shared secret"
    passed += 1

    # Deterministic keygen
    seed_fixed = hashlib.sha512(b"test-kem" * 3).digest() + os.urandom(32)
    # Make it 96 bytes
    seed_fixed = seed_fixed[:96]
    ek_a, dk_a = hybrid_kem_keygen(seed_fixed)
    ek_b, dk_b = hybrid_kem_keygen(seed_fixed)
    assert ek_a == ek_b and dk_a == dk_b, "Deterministic keygen failed"
    passed += 1

    print(f"  Hybrid KEM: {passed}/6 passed")
    return passed == 6


# ── Seed.py Integration Tests ──────────────────────────────────

def test_seed_integration():
    from seed import get_quantum_seed, generate_quantum_keypair
    from crypto.hybrid_dsa import HYBRID_DSA_SK_SIZE, HYBRID_DSA_PK_SIZE
    from crypto.hybrid_kem import HYBRID_KEM_DK_SIZE, HYBRID_KEM_EK_SIZE

    passed = 0
    master_key = os.urandom(64)

    # hybrid-dsa-65 seed size
    qs = get_quantum_seed(master_key, "hybrid-dsa-65")
    assert len(qs) == 64, f"hybrid-dsa-65 seed: {len(qs)} != 64"
    passed += 1

    # hybrid-kem-768 seed size
    qs2 = get_quantum_seed(master_key, "hybrid-kem-768")
    assert len(qs2) == 96, f"hybrid-kem-768 seed: {len(qs2)} != 96"
    passed += 1

    # Domain independence: hybrid vs pure PQ produce different seeds
    qs_ml = get_quantum_seed(master_key, "ml-dsa-65")
    qs_hybrid = get_quantum_seed(master_key, "hybrid-dsa-65")
    assert qs_ml != qs_hybrid[:32], "hybrid-dsa seed collides with ml-dsa seed"
    passed += 1

    qs_kem = get_quantum_seed(master_key, "ml-kem-768")
    qs_hkem = get_quantum_seed(master_key, "hybrid-kem-768")
    assert qs_kem != qs_hkem[:64], "hybrid-kem seed collides with ml-kem seed"
    passed += 1

    # Key index independence
    qs_0 = get_quantum_seed(master_key, "hybrid-dsa-65", key_index=0)
    qs_1 = get_quantum_seed(master_key, "hybrid-dsa-65", key_index=1)
    assert qs_0 != qs_1, "Different key indices produced same seed"
    passed += 1

    # Full keypair generation
    sk, pk = generate_quantum_keypair(master_key, "hybrid-dsa-65")
    assert len(sk) == HYBRID_DSA_SK_SIZE
    assert len(pk) == HYBRID_DSA_PK_SIZE
    passed += 1

    sk_kem, pk_kem = generate_quantum_keypair(master_key, "hybrid-kem-768")
    assert len(sk_kem) == HYBRID_KEM_DK_SIZE
    assert len(pk_kem) == HYBRID_KEM_EK_SIZE
    passed += 1

    # Existing algorithms still work
    sk_ml, pk_ml = generate_quantum_keypair(master_key, "ml-dsa-65")
    assert len(sk_ml) == 4032 and len(pk_ml) == 1952
    passed += 1

    print(f"  Seed integration: {passed}/8 passed")
    return passed == 8


# ── Main ───────────────────────────────────────────────────────

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    print("Testing Ed25519 (RFC 8032)...")
    ok1 = test_ed25519_vectors()
    ok2 = test_ed25519_roundtrip()

    print("\nTesting X25519 (RFC 7748)...")
    ok3 = test_x25519_vectors()
    ok4 = test_x25519_iterated()

    print("\nTesting Hybrid DSA (Ed25519 + ML-DSA-65)...")
    ok5 = test_hybrid_dsa()

    print("\nTesting Hybrid KEM (X25519 + ML-KEM-768)...")
    ok6 = test_hybrid_kem()

    print("\nTesting seed.py integration...")
    ok7 = test_seed_integration()

    print()
    all_ok = all([ok1, ok2, ok3, ok4, ok5, ok6, ok7])
    if all_ok:
        print("ALL TESTS PASSED")
    else:
        print("SOME TESTS FAILED")
        sys.exit(1)
