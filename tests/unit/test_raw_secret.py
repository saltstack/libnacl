# Import libnacl libs
import libnacl
import libnacl.utils

# Import python libs
import unittest


class TestSecret(unittest.TestCase):
    """
    Test secret functions
    """
    def test_secretbox(self):
        msg = b'Are you suggesting coconuts migrate?'

        nonce = libnacl.utils.rand_nonce()
        key = libnacl.utils.salsa_key()

        c = libnacl.crypto_secretbox(msg, nonce, key)
        m = libnacl.crypto_secretbox_open(c, nonce, key)
        self.assertEqual(msg, m)

        with self.assertRaises(ValueError):
            libnacl.crypto_secretbox(msg, b'too_short', key)

        with self.assertRaises(ValueError):
            libnacl.crypto_secretbox(msg, nonce, b'too_short')

        with self.assertRaises(ValueError):
            libnacl.crypto_secretbox_open(c, b'too_short', key)

        with self.assertRaises(ValueError):
            libnacl.crypto_secretbox_open(c, nonce, b'too_short')
