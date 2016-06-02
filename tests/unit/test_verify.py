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
        self.assertTrue(libnacl.bytes_eq(v16, v16x))
        v16x = bytearray(v16x)
        v16x[libnacl.randombytes_random() & 15] += 1
        v16x = bytes(v16x)
        self.assertFalse(libnacl.crypto_verify_16(v16, v16x))
        self.assertFalse(libnacl.bytes_eq(v16, v16x))

        self.assertEqual(libnacl.crypto_verify_16_BYTES, 16)

    def test_verify32(self):
        v32 = libnacl.randombytes_buf(32)
        v32x = v32[:]
        self.assertTrue(libnacl.crypto_verify_32(v32, v32x))
        self.assertTrue(libnacl.bytes_eq(v32, v32x))
        v32x = bytearray(v32x)
        v32x[libnacl.randombytes_random() & 31] += 1
        v32x = bytes(v32x)
        self.assertFalse(libnacl.crypto_verify_32(v32, v32x))
        self.assertFalse(libnacl.bytes_eq(v32, v32x))

        self.assertEqual(libnacl.crypto_verify_32_BYTES, 32)

    def test_verify64(self):
        v64 = libnacl.randombytes_buf(64)
        v64x = v64[:]
        self.assertTrue(libnacl.crypto_verify_64(v64, v64x))
        self.assertTrue(libnacl.bytes_eq(v64, v64x))
        v64x = bytearray(v64x)
        v64x[libnacl.randombytes_random() & 63] += 1
        v64x = bytes(v64x)
        self.assertFalse(libnacl.crypto_verify_64(v64, v64x))
        self.assertFalse(libnacl.bytes_eq(v64, v64x))

        self.assertEqual(libnacl.crypto_verify_64_BYTES, 64)


class TestVerifyBytesEq(unittest.TestCase):
    def test_equal(self):
        a = libnacl.randombytes_buf(122)
        b = a[:]
        self.assertTrue(libnacl.bytes_eq(a, b))

    def test_different(self):
        a = libnacl.randombytes_buf(122)
        b = bytearray(a)
        b[87] += 1
        b = bytes(b)
        self.assertFalse(libnacl.bytes_eq(a, b))

    def test_invalid_type(self):
        a = libnacl.randombytes_buf(122)
        b = bytearray(a)
        with self.assertRaises(TypeError):
            libnacl.bytes_eq(a, b)

    def test_different_length(self):
        a = libnacl.randombytes_buf(122)
        b = a[:-1]
        self.assertFalse(libnacl.bytes_eq(a, b))
