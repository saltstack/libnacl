"""
Basic tests for randombytes_* functions
"""

import libnacl
import unittest


class TestRandomBytes(unittest.TestCase):
    def test_randombytes_random(self):
        self.assertIsInstance(libnacl.randombytes_random(), int)

    def test_randombytes_uniform(self):
        self.assertIsInstance(libnacl.randombytes_uniform(200), int)

        freq = {libnacl.randombytes_uniform(256): 1 for _ in range(65536)}

        self.assertEqual(256, len(freq))
        self.assertTrue(all(freq.values()))

    def test_randombytes(self):
        'copied from libsodium default/randombytes.c'

        data = libnacl.randombytes(65536)

        freq = {x: 1 for x in data}

        self.assertEqual(256, len(freq))
        self.assertTrue(all(freq.values()))

    def test_randombytes_buf_deterministic(self):

        seed = libnacl.randombytes_buf(32)
        seed2 = libnacl.randombytes_buf(32)
        data = libnacl.randombytes_buf_deterministic(32, seed)
        data2 = libnacl.randombytes_buf_deterministic(32, seed)
        data3 = libnacl.randombytes_buf_deterministic(32, seed2)

        self.assertEqual(32, len(data))
        self.assertEqual(32, len(data))
        self.assertEqual(32, len(data))
        self.assertEqual(data, data2)
        self.assertNotEqual(data, data3)

    def test_crypto_kdf_keygen(self):

        master_key = libnacl.crypto_kdf_keygen()

        freq = {x: 1 for x in master_key}

        self.assertEqual(32, len(master_key))
        self.assertTrue(all(freq.values()))


    def test_crypto_kdf_derive_from_key(self):

      master_key = libnacl.crypto_kdf_keygen()
      subkey = libnacl.crypto_kdf_derive_from_key(16, 1, "Examples", master_key)
      subkey2 = libnacl.crypto_kdf_derive_from_key(16, 1, "Examples", master_key)
      subkey3 = libnacl.crypto_kdf_derive_from_key(16, 2, "Examples", master_key)

      self.assertEqual(16, len(subkey))
      self.assertEqual(16, len(subkey2))
      self.assertEqual(16, len(subkey3))
      self.assertEqual(subkey, subkey2)
      self.assertNotEqual(subkey, subkey3)
      

