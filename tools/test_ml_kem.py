# Copyright (c) 2026 Signer — MIT License

"""Test suite for ML-KEM-768 (FIPS 203) key encapsulation mechanism.

Tests the pure-Python ML-KEM-768 implementation with:
    - Deterministic known-answer tests (KATs) for regression
    - NTT/inverse-NTT algebraic property tests
    - ByteEncode/ByteDecode roundtrip tests
    - Compress/Decompress bounded-error tests
    - Full keygen → encaps → decaps roundtrip
    - Implicit rejection (tampered ciphertext)
    - FIPS 203 §7.1 modulus check negative tests
    - Input validation and edge cases

Run from the universal-quantum-seed root:
    python -m tools.test_ml_kem
"""

import hashlib
import os
import random
import sys
import time
import unittest

# Ensure project root is on the import path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto.ml_kem import (
    _Q, _N,
    _ntt, _ntt_inv, _multiply_ntts,
    _byte_encode, _byte_decode,
    _compress, _decompress, _compress_poly, _decompress_poly,
    _sample_ntt, _sample_cbd,
    _ek_modulus_check,
    ml_kem_keygen, ml_kem_encaps, ml_kem_decaps,
)


# ── Deterministic KAT Vectors ──────────────────────────────────
#
# Generated from our implementation with known seeds.  These pin the
# exact output bytes so any refactor or optimisation that changes
# behaviour will be caught immediately.

_KAT_KEYGEN_SEED = bytes(range(64))  # 0x00..0x3f

# SHA-256 of the full EK (1 184 bytes) and DK (2 400 bytes)
_KAT_EK_SHA256 = "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9"
_KAT_DK_SHA256 = "dac268bde6a8dd238e9887117d6b664e7a7a9350ad6b7c08a948e504809572a5"

# First / last 32 bytes of EK
_KAT_EK_HEAD = "298aa10d423c8dda069d02bc59e6cdf03a096b8b3da4cab9b80ca4a14907672c"
_KAT_EK_TAIL = "5e43481c3eeb397eb192505229b67a201ea893c3e2cb32da8bc342fa4dea0578"

_KAT_ENCAPS_RANDOMNESS = bytes(range(32, 64))  # 0x20..0x3f
_KAT_SS = "dfa3d17135b0c7cad38cd14d75cf05753c4060f4fff1b4df961f2774c7aa051b"
_KAT_CT_SHA256 = "1d3fc60ee5c1d56e6d65a6e453e4d17072d97b3f4c88c4939fe44573e29b1c98"


class TestMLKEMKAT(unittest.TestCase):
    """Known-answer / regression tests."""

    @classmethod
    def setUpClass(cls):
        """Generate the keypair once (expensive in pure Python)."""
        cls.ek, cls.dk = ml_kem_keygen(_KAT_KEYGEN_SEED)

    def test_keygen_ek_size(self):
        self.assertEqual(len(self.ek), 1184)

    def test_keygen_dk_size(self):
        self.assertEqual(len(self.dk), 2400)

    def test_keygen_ek_sha256(self):
        self.assertEqual(hashlib.sha256(self.ek).hexdigest(), _KAT_EK_SHA256)

    def test_keygen_dk_sha256(self):
        self.assertEqual(hashlib.sha256(self.dk).hexdigest(), _KAT_DK_SHA256)

    def test_keygen_ek_head(self):
        self.assertEqual(self.ek[:32].hex(), _KAT_EK_HEAD)

    def test_keygen_ek_tail(self):
        self.assertEqual(self.ek[-32:].hex(), _KAT_EK_TAIL)

    def test_encaps_deterministic(self):
        ct, ss = ml_kem_encaps(self.ek, randomness=_KAT_ENCAPS_RANDOMNESS)
        self.assertEqual(len(ct), 1088)
        self.assertEqual(len(ss), 32)
        self.assertEqual(ss.hex(), _KAT_SS)
        self.assertEqual(hashlib.sha256(ct).hexdigest(), _KAT_CT_SHA256)

    def test_decaps_roundtrip(self):
        ct, ss = ml_kem_encaps(self.ek, randomness=_KAT_ENCAPS_RANDOMNESS)
        ss2 = ml_kem_decaps(self.dk, ct)
        self.assertEqual(ss, ss2)


class TestNTTProperties(unittest.TestCase):
    """Algebraic property tests for the NTT."""

    def _rand_poly(self, seed_val=None):
        rng = random.Random(seed_val)
        return [rng.randint(0, _Q - 1) for _ in range(_N)]

    def test_ntt_roundtrip(self):
        """ntt_inv(ntt(f)) == f for random polynomials."""
        for seed_val in range(5):
            f = self._rand_poly(seed_val)
            self.assertEqual(_ntt_inv(_ntt(f)), f,
                             f"NTT roundtrip failed for seed {seed_val}")

    def test_ntt_zero(self):
        """NTT of the zero polynomial is the zero polynomial."""
        zero = [0] * _N
        self.assertEqual(_ntt(zero), zero)
        self.assertEqual(_ntt_inv(zero), zero)

    def test_ntt_one(self):
        """ntt_inv(ntt([1, 0, ..., 0])) == [1, 0, ..., 0]."""
        one = [1] + [0] * (_N - 1)
        self.assertEqual(_ntt_inv(_ntt(one)), one)

    def test_multiply_ntts_commutative(self):
        """NTT multiplication is commutative: f*g == g*f."""
        f = _ntt(self._rand_poly(10))
        g = _ntt(self._rand_poly(11))
        fg = _multiply_ntts(f, g)
        gf = _multiply_ntts(g, f)
        self.assertEqual(fg, gf)

    def test_multiply_ntts_identity(self):
        """Multiplying by NTT(1) gives the original polynomial back."""
        one = [1] + [0] * (_N - 1)
        one_ntt = _ntt(one)
        f = self._rand_poly(20)
        f_ntt = _ntt(f)
        product = _multiply_ntts(f_ntt, one_ntt)
        result = _ntt_inv(product)
        self.assertEqual(result, f)


class TestByteEncodeDecode(unittest.TestCase):
    """ByteEncode / ByteDecode roundtrip and validation tests."""

    def test_roundtrip_all_d(self):
        """ByteDecode(ByteEncode(f, d), d) == f for all relevant d values."""
        rng = random.Random(42)
        for d in [1, 4, 10, 12]:
            m = (1 << d) if d < 12 else _Q
            f = [rng.randint(0, m - 1) for _ in range(_N)]
            encoded = _byte_encode(f, d)
            decoded = _byte_decode(encoded, d)
            self.assertEqual(f, decoded, f"Roundtrip failed for d={d}")

    def test_encode_output_size(self):
        """ByteEncode produces the correct number of bytes."""
        for d in [1, 4, 10, 12]:
            m = (1 << d) if d < 12 else _Q
            f = [0] * _N
            encoded = _byte_encode(f, d)
            expected_len = (256 * d + 7) // 8
            self.assertEqual(len(encoded), expected_len,
                             f"Wrong output size for d={d}")

    def test_decode_wrong_length(self):
        """ByteDecode raises ValueError on wrong input length."""
        with self.assertRaises(ValueError):
            _byte_decode(b"\x00" * 10, 12)  # expects 384 bytes
        with self.assertRaises(ValueError):
            _byte_decode(b"\x00" * 100, 1)  # expects 32 bytes
        with self.assertRaises(ValueError):
            _byte_decode(b"", 4)  # expects 128 bytes

    def test_decode_d12_reduces_mod_q(self):
        """ByteDecode_12 reduces values mod q = 3329."""
        # Craft a byte string where a 12-bit field is >= q
        # 3329 = 0xD01.  Place 0xFFF (4095) in the first 12 bits.
        data = bytearray(384)
        data[0] = 0xFF
        data[1] = 0x0F  # first 12 bits = 0xFFF = 4095
        decoded = _byte_decode(bytes(data), 12)
        # 4095 % 3329 = 766
        self.assertEqual(decoded[0], 4095 % _Q)

    def test_encode_zero_poly(self):
        """Encoding all zeros produces all-zero bytes."""
        for d in [1, 4, 10, 12]:
            f = [0] * _N
            encoded = _byte_encode(f, d)
            self.assertEqual(encoded, b"\x00" * len(encoded))


class TestCompressDecompress(unittest.TestCase):
    """Compression / decompression bounded-error tests."""

    def test_compress_range(self):
        """Compressed values are in [0, 2^d)."""
        for d in [1, 4, 10]:
            m = 1 << d
            for x in range(0, _Q, 100):
                c = _compress(x, d)
                self.assertGreaterEqual(c, 0)
                self.assertLess(c, m)

    def test_decompress_range(self):
        """Decompressed values are in [0, q)."""
        for d in [1, 4, 10]:
            m = 1 << d
            for y in range(m):
                dc = _decompress(y, d)
                self.assertGreaterEqual(dc, 0)
                self.assertLess(dc, _Q)

    def test_roundtrip_bounded_error(self):
        """Decompress(Compress(x)) is within q / 2^(d+1) of x."""
        for d in [1, 4, 10]:
            max_err = (_Q + (1 << d)) // (1 << (d + 1))
            for x in range(_Q):
                c = _compress(x, d)
                dc = _decompress(c, d)
                # Error wraps around mod q
                err = min((x - dc) % _Q, (dc - x) % _Q)
                self.assertLessEqual(err, max_err,
                    f"d={d}, x={x}, compressed={c}, decompressed={dc}, err={err}")


class TestSampling(unittest.TestCase):
    """Tests for SampleNTT and SamplePolyCBD."""

    def test_sample_ntt_range(self):
        """SampleNTT produces coefficients in [0, q)."""
        seed = b"\x00" * 32
        coeffs = _sample_ntt(seed, 0, 0)
        self.assertEqual(len(coeffs), 256)
        for c in coeffs:
            self.assertGreaterEqual(c, 0)
            self.assertLess(c, _Q)

    def test_sample_ntt_deterministic(self):
        """SampleNTT is deterministic for same inputs."""
        seed = b"\xab" * 32
        a = _sample_ntt(seed, 1, 2)
        b = _sample_ntt(seed, 1, 2)
        self.assertEqual(a, b)

    def test_sample_ntt_different_indices(self):
        """Different (i, j) indices produce different polynomials."""
        seed = b"\x00" * 32
        a = _sample_ntt(seed, 0, 0)
        b = _sample_ntt(seed, 0, 1)
        self.assertNotEqual(a, b)

    def test_sample_cbd_range(self):
        """SamplePolyCBD_2 produces coefficients in {-2, -1, 0, 1, 2} mod q."""
        data = os.urandom(128)  # 64 * eta = 64 * 2 = 128 bytes
        f = _sample_cbd(data, 2)
        self.assertEqual(len(f), 256)
        valid = {0, 1, 2, _Q - 1, _Q - 2}  # {0, 1, 2, -1, -2} mod q
        for c in f:
            self.assertIn(c, valid, f"CBD coefficient {c} out of range")

    def test_sample_cbd_deterministic(self):
        """SamplePolyCBD is deterministic."""
        data = b"\x55" * 128
        a = _sample_cbd(data, 2)
        b = _sample_cbd(data, 2)
        self.assertEqual(a, b)


class TestFullProtocol(unittest.TestCase):
    """End-to-end keygen → encaps → decaps tests."""

    def test_roundtrip_random(self):
        """Random keygen + encaps + decaps produces matching shared secrets."""
        ek, dk = ml_kem_keygen()
        ct, ss_enc = ml_kem_encaps(ek)
        ss_dec = ml_kem_decaps(dk, ct)
        self.assertEqual(ss_enc, ss_dec)

    def test_roundtrip_multiple_encaps(self):
        """Multiple encapsulations to the same key all decapsulate correctly."""
        seed = bytes(range(64))
        ek, dk = ml_kem_keygen(seed)
        for i in range(3):
            randomness = hashlib.sha256(bytes([i]) * 32).digest()
            ct, ss_enc = ml_kem_encaps(ek, randomness=randomness)
            ss_dec = ml_kem_decaps(dk, ct)
            self.assertEqual(ss_enc, ss_dec, f"Roundtrip failed for encaps #{i}")

    def test_different_randomness_different_ct(self):
        """Different randomness produces different ciphertexts and shared secrets."""
        seed = bytes(range(64))
        ek, dk = ml_kem_keygen(seed)
        ct1, ss1 = ml_kem_encaps(ek, randomness=b"\x00" * 32)
        ct2, ss2 = ml_kem_encaps(ek, randomness=b"\x01" * 32)
        self.assertNotEqual(ct1, ct2)
        self.assertNotEqual(ss1, ss2)

    def test_different_keys_different_ss(self):
        """Different keypairs produce different shared secrets for same randomness."""
        ek1, dk1 = ml_kem_keygen(b"\x00" * 64)
        ek2, dk2 = ml_kem_keygen(b"\x01" * 64)
        r = b"\xaa" * 32
        _, ss1 = ml_kem_encaps(ek1, randomness=r)
        _, ss2 = ml_kem_encaps(ek2, randomness=r)
        self.assertNotEqual(ss1, ss2)


class TestImplicitRejection(unittest.TestCase):
    """Implicit rejection (IND-CCA2) tests."""

    @classmethod
    def setUpClass(cls):
        cls.ek, cls.dk = ml_kem_keygen(_KAT_KEYGEN_SEED)
        cls.ct, cls.ss = ml_kem_encaps(cls.ek, randomness=_KAT_ENCAPS_RANDOMNESS)

    def test_tampered_ciphertext_rejected(self):
        """Flipping a byte in CT produces a different shared secret."""
        ct_bad = bytearray(self.ct)
        ct_bad[0] ^= 0xFF
        ss_bad = ml_kem_decaps(self.dk, bytes(ct_bad))
        self.assertNotEqual(self.ss, ss_bad)
        self.assertEqual(len(ss_bad), 32)

    def test_tampered_ct_deterministic_rejection(self):
        """Same tampered CT always produces the same rejection key (K_bar)."""
        ct_bad = bytearray(self.ct)
        ct_bad[500] ^= 0x01
        ct_bad = bytes(ct_bad)
        ss1 = ml_kem_decaps(self.dk, ct_bad)
        ss2 = ml_kem_decaps(self.dk, ct_bad)
        self.assertEqual(ss1, ss2)

    def test_every_byte_position_tamper(self):
        """Tampering any single byte in CT triggers implicit rejection."""
        # Test a sample of positions across the ciphertext
        for pos in [0, 1, 100, 500, 960, 1087]:
            ct_bad = bytearray(self.ct)
            ct_bad[pos] ^= 0x01
            ss_bad = ml_kem_decaps(self.dk, bytes(ct_bad))
            self.assertNotEqual(self.ss, ss_bad,
                                f"Tamper at position {pos} was not rejected")

    def test_wrong_dk_for_ct(self):
        """CT encrypted to one key decapsulated with another yields rejection."""
        _, dk2 = ml_kem_keygen(b"\xff" * 64)
        ss_wrong = ml_kem_decaps(dk2, self.ct)
        self.assertNotEqual(self.ss, ss_wrong)
        self.assertEqual(len(ss_wrong), 32)


class TestInputValidation(unittest.TestCase):
    """FIPS 203 input validation and error handling."""

    def test_keygen_wrong_seed_length(self):
        """keygen rejects seeds that are not 64 bytes."""
        with self.assertRaises(ValueError):
            ml_kem_keygen(b"\x00" * 32)
        with self.assertRaises(ValueError):
            ml_kem_keygen(b"\x00" * 128)
        with self.assertRaises(ValueError):
            ml_kem_keygen(b"")

    def test_encaps_wrong_randomness_length(self):
        """encaps rejects randomness that is not 32 bytes."""
        ek, _ = ml_kem_keygen(_KAT_KEYGEN_SEED)
        with self.assertRaises(ValueError):
            ml_kem_encaps(ek, randomness=b"\x00" * 16)
        with self.assertRaises(ValueError):
            ml_kem_encaps(ek, randomness=b"\x00" * 64)

    def test_decaps_wrong_ct_length(self):
        """decaps rejects ciphertexts that are not 1088 bytes."""
        _, dk = ml_kem_keygen(_KAT_KEYGEN_SEED)
        with self.assertRaises(ValueError):
            ml_kem_decaps(dk, b"\x00" * 100)
        with self.assertRaises(ValueError):
            ml_kem_decaps(dk, b"\x00" * 2000)

    def test_encaps_modulus_check_rejects_invalid_ek(self):
        """encaps rejects an EK with out-of-range coefficients (§7.1)."""
        # Create an invalid EK: set all bytes to 0xFF so that 12-bit
        # fields decode to 4095 > q, making re-encoding differ.
        bad_ek = b"\xff" * 1184
        with self.assertRaises(ValueError):
            ml_kem_encaps(bad_ek)

    def test_encaps_modulus_check_accepts_valid_ek(self):
        """encaps accepts a legitimately generated EK."""
        ek, _ = ml_kem_keygen(_KAT_KEYGEN_SEED)
        self.assertTrue(_ek_modulus_check(ek))

    def test_modulus_check_wrong_length(self):
        """Modulus check fails for wrong-length inputs."""
        self.assertFalse(_ek_modulus_check(b"\x00" * 100))
        self.assertFalse(_ek_modulus_check(b"\x00" * 2000))
        self.assertFalse(_ek_modulus_check(b""))

    def test_decaps_dk_hash_check_rejects_tampered_dk(self):
        """decaps rejects a DK whose embedded H(ek) has been tampered."""
        _, dk = ml_kem_keygen(_KAT_KEYGEN_SEED)
        ek, _ = ml_kem_keygen(_KAT_KEYGEN_SEED)
        ct, _ = ml_kem_encaps(ek, randomness=_KAT_ENCAPS_RANDOMNESS)

        # Tamper the H(ek) portion of DK (bytes 1152+1184 .. 1152+1184+32)
        dk_bad = bytearray(dk)
        h_offset = 384 * 3 + 1184  # 1152 + 1184 = 2336
        dk_bad[h_offset] ^= 0x01
        with self.assertRaises(ValueError):
            ml_kem_decaps(bytes(dk_bad), ct)


class TestByteDecodeEdgeCases(unittest.TestCase):
    """Edge cases for _byte_decode length validation."""

    def test_d1_correct_length(self):
        """ByteDecode_1 accepts exactly 32 bytes."""
        data = b"\x00" * 32
        result = _byte_decode(data, 1)
        self.assertEqual(len(result), 256)

    def test_d4_correct_length(self):
        """ByteDecode_4 accepts exactly 128 bytes."""
        data = b"\x00" * 128
        result = _byte_decode(data, 4)
        self.assertEqual(len(result), 256)

    def test_d10_correct_length(self):
        """ByteDecode_10 accepts exactly 320 bytes."""
        data = b"\x00" * 320
        result = _byte_decode(data, 10)
        self.assertEqual(len(result), 256)

    def test_d12_correct_length(self):
        """ByteDecode_12 accepts exactly 384 bytes."""
        data = b"\x00" * 384
        result = _byte_decode(data, 12)
        self.assertEqual(len(result), 256)

    def test_off_by_one_rejected(self):
        """ByteDecode rejects input that is one byte too short or too long."""
        for d in [1, 4, 10, 12]:
            correct_len = (256 * d + 7) // 8
            with self.assertRaises(ValueError, msg=f"d={d} too short"):
                _byte_decode(b"\x00" * (correct_len - 1), d)
            with self.assertRaises(ValueError, msg=f"d={d} too long"):
                _byte_decode(b"\x00" * (correct_len + 1), d)


# ── Runner ──────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 68)
    print("ML-KEM-768 (FIPS 203) Test Suite")
    print("=" * 68)
    t0 = time.time()

    # Run with moderate verbosity
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    elapsed = time.time() - t0
    print(f"\nCompleted in {elapsed:.1f}s")
    sys.exit(0 if result.wasSuccessful() else 1)
