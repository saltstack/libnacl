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
