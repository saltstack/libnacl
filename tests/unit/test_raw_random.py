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
