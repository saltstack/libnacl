"""
Basic tests for verify functions
"""

import libnacl
import unittest


# These are copied from libsodium test suite
class TestVerify(unittest.TestCase):
    def test_verify16(self):
        v16 = libnacl.randombytes_buf(16)
        v16x = v16[:]
        self.assertTrue(libnacl.crypto_verify_16(v16, v16x))
        v16x = bytearray(v16x)
        v16x[libnacl.randombytes_random() & 15] += 1
        self.assertFalse(libnacl.crypto_verify_16(v16, bytes(v16x)))

        self.assertEqual(libnacl.crypto_verify_16_BYTES, 16)

    def test_verify32(self):
        v32 = libnacl.randombytes_buf(32)
        v32x = v32[:]
        self.assertTrue(libnacl.crypto_verify_32(v32, v32x))
        v32x = bytearray(v32x)
        v32x[libnacl.randombytes_random() & 31] += 1
        self.assertFalse(libnacl.crypto_verify_32(v32, bytes(v32x)))

        self.assertEqual(libnacl.crypto_verify_32_BYTES, 32)

    def test_verify64(self):
        v64 = libnacl.randombytes_buf(64)
        v64x = v64[:]
        self.assertTrue(libnacl.crypto_verify_64(v64, v64x))
        v64x = bytearray(v64x)
        v64x[libnacl.randombytes_random() & 63] += 1
        self.assertFalse(libnacl.crypto_verify_64(v64, bytes(v64x)))

        self.assertEqual(libnacl.crypto_verify_64_BYTES, 64)
