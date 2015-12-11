# Import nacl libs
import libnacl
from hashlib import sha256, sha512

# Import python libs
import unittest


class TestHash(unittest.TestCase):
    """
    Test sign functions
    """
    def test_hash(self):
        msg1 = b'Are you suggesting coconuts migrate?'
        msg2 = b'Not at all, they could be carried.'
        chash1 = libnacl.crypto_hash(msg1)
        chash2 = libnacl.crypto_hash(msg2)
        self.assertNotEqual(msg1, chash1)
        self.assertNotEqual(msg2, chash2)
        self.assertNotEqual(chash2, chash1)

        ref256 = sha256(msg1)
        self.assertEqual(ref256.digest_size, libnacl.crypto_hash_sha256_BYTES)
        self.assertEqual(ref256.digest(), libnacl.crypto_hash_sha256(msg1))

        ref512 = sha512(msg1)
        self.assertEqual(ref512.digest_size, libnacl.crypto_hash_sha512_BYTES)
        self.assertEqual(ref512.digest(), libnacl.crypto_hash_sha512(msg1))

