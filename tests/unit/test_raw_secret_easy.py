# Import libnacl libs
import libnacl
import libnacl.utils

# Import python libs
import unittest


class TestSecret(unittest.TestCase):
    """
    Test secret functions
    """
    def test_secretbox_easy(self):
        msg = b'Are you suggesting coconuts migrate?'

        nonce = libnacl.utils.rand_nonce()
        key = libnacl.utils.salsa_key()

        c = libnacl.crypto_secretbox_easy(msg, nonce, key)
        m = libnacl.crypto_secretbox_open_easy(c, nonce, key)
        self.assertEqual(msg, m)

        with self.assertRaises(ValueError):
            libnacl.crypto_secretbox_easy(msg, b'too_short', key)

        with self.assertRaises(ValueError):
            libnacl.crypto_secretbox_easy(msg, nonce, b'too_short')

        with self.assertRaises(ValueError):
            libnacl.crypto_secretbox_open_easy(c, b'too_short', key)

        with self.assertRaises(ValueError):
            libnacl.crypto_secretbox_open_easy(c, nonce, b'too_short')
