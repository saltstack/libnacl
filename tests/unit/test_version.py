"""
Basic tests for version functions
"""

import libnacl
import unittest


# These are copied from libsodium test suite
class TestSodiumVersion(unittest.TestCase):
    def test_version_string(self):
        self.assertIsNotNone(libnacl.sodium_version_string())

    def test_library_version_major(self):
        # Using assertTrue to keep tests "uniform" and keep compatibility with
        # Python 2.6
        self.assertTrue(libnacl.sodium_library_version_major() > 0)

    def test_library_version_minor(self):
        # Using assertTrue to keep tests "uniform" and keep compatibility with
        # Python 2.6 (assertGreaterEqual appeared in Python 2.7 only)
        self.assertTrue(libnacl.sodium_library_version_minor() >= 0)
